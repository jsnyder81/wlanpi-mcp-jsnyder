"""
Elicitation confirms for destructive tools.

A client that supports form elicitation gets a protocol-level confirm before
anything destructive runs, so the model does not have to ask "are you sure"
itself. The Pi owns these tool-specific confirms: the browser extension must
not double-confirm on top of them.

The daemon is stateless. Capabilities arrive per request in
``params._meta["io.modelcontextprotocol/clientCapabilities"]`` and surface
as ``ctx.client_capabilities``; the retry's answers arrive on
``ctx.input_responses`` alongside the echoed ``requestState``. The SDK's
RequestStateBoundary middleware seals and verifies that echo, binding it to
the method, tool name, arguments digest, audience, principal and TTL, so it
cannot be forged or replayed against a different call.

A second pair, confirm_with_state and resume_with_state, serves the
mid-flow confirm: the tool calls core first, and only when core refuses
with a 409 that an override flag would force does the server ask. The
sealed state carries the operation, its arguments and the refusal
detail, so a declined retry resumes without re-consulting core; an
accepted one calls core again, with the override.

Known limitation: the boundary mints no single-use nonce, so a captured
*accepted* requestState still replays against the same zero-argument call
within the TTL (600s default). That window is inherent to stateless
multi-round-trip requests. Upgrade path: carry a random nonce in the sealed
state and reject a retry that repeats one (needs per-principal replay
storage).

The boundary's key is ephemeral (per-process, MCPServer's default policy);
keys are never persisted. A retry after a daemon restart therefore fails
cleanly at the boundary with -32602 "Invalid or expired requestState" and
the client must start the call over.
"""

import json
from typing import Any

from mcp.server.elicitation import render_elicitation_schema
from mcp.server.mcpserver import Context
from mcp.types import (
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
)
from mcp_types.version import is_version_at_least
from pydantic import BaseModel

#: input_required interim results exist only from this revision up; the
#: SDK's own resolver path gates identically (mcp.server.mcpserver.resolve).
_INPUT_REQUIRED_VERSION = "2026-07-28"

#: Wire key for the single confirm question. Stable across rounds and
#: workers, like the SDK's own resolver keys.
CONFIRM_KEY = "wlanpi-mcp/confirm"

#: Sealed into requestState on every ask. Never read back: its job is to
#: make RequestStateBoundary bind the retry to this exact request.
_REQUEST_STATE = "wlanpi-mcp/confirm-asked"


class _ConfirmForm(BaseModel):
    """The one question rendered to the user: a yes/no checkbox."""

    confirm: bool


#: Spec-valid form schema, rendered once: every confirm asks the same thing.
_CONFIRM_SCHEMA = render_elicitation_schema(_ConfirmForm)


def _ask(message: str, state: str) -> InputRequiredResult:
    """Build the one-question ask carrying the given (pre-seal) state."""
    return InputRequiredResult(
        input_requests={
            CONFIRM_KEY: ElicitRequest(
                params=ElicitRequestFormParams(
                    message=message, requested_schema=_CONFIRM_SCHEMA
                )
            )
        },
        request_state=state,
    )


def _accepted(answer: ElicitResult) -> bool:
    """Whether this answer is a confirmation.

    An unchecked box still arrives as action "accept", so the content
    decides; accept with no content at all is not a confirmation.
    """
    return answer.action == "accept" and (answer.content or {}).get("confirm") is True


def form_elicitations_supported(ctx: Context[Any, Any]) -> bool:
    """Report whether this request's client can answer a form elicitation.

    Answers ride the input_required result, so a client on a protocol older
    than 2026-07-28 reports False even when it declares the capability. A
    bare ``elicitation`` capability counts as form support; a url-only
    declaration does not, the same rule the SDK applies to form elicitations
    themselves. Outside an active request (unit tests, direct calls) there
    is no negotiated version and no client to ask, so this reports False.
    """
    if ctx.protocol_version is None or not is_version_at_least(
        ctx.protocol_version, _INPUT_REQUIRED_VERSION
    ):
        return False
    capabilities = ctx.client_capabilities
    elicitation = capabilities.elicitation if capabilities is not None else None
    return elicitation is not None and (
        elicitation.form is not None or elicitation.url is None
    )


def confirm_gate(
    ctx: Context[Any, Any], message: str
) -> InputRequiredResult | dict[str, Any] | None:
    """Return the value the tool should hand back, or None to proceed.

    None means go ahead: the client cannot answer forms (behavior is then
    exactly what it was before confirms existed), or this is the retry the
    user accepted. Otherwise return the result from the tool unchanged: the
    ask on the first round, or a plain declined report.

    Args:
        ctx: The calling request's context.
        message: What will happen, stated concretely, shown to the user.
    """
    if not form_elicitations_supported(ctx):
        return None
    # A retry counts only when it echoes the requestState the server minted
    # when it asked; answers without it cannot skip the confirm.
    responses = ctx.input_responses if ctx.request_state is not None else None
    answer = responses.get(CONFIRM_KEY) if responses else None
    if not isinstance(answer, ElicitResult):
        return _ask(message, _REQUEST_STATE)
    if _accepted(answer):
        return None
    return {"performed": False, "reason": "user declined or dismissed"}


#: Marker inside the sealed state of a mid-flow confirm, so
#: resume_with_state can tell our state from another mechanism's or junk.
_STATE_MARK = "wlanpi-mcp/override-confirm"


def confirm_with_state(
    ctx: Context[Any, Any], message: str, state: dict[str, Any]
) -> InputRequiredResult | None:
    """Build a mid-flow confirm ask, or None if this client cannot answer.

    Call this when core has refused an action that an override flag would
    force. None means the tool must behave exactly as it did before
    confirms existed (surface the refusal unchanged). The retry re-enters
    the tool and reads the answer with resume_with_state.

    Args:
        ctx: The calling request's context.
        message: The question shown to the user.
        state: JSON-serializable values the retry needs to resume: which
            operation, its arguments, and what to return on a decline.
    """
    if not form_elicitations_supported(ctx):
        return None
    return _ask(message, json.dumps({_STATE_MARK: True, **state}))


def resume_with_state(ctx: Context[Any, Any]) -> tuple[bool, dict[str, Any]] | None:
    """Read a retry's answer to a mid-flow confirm, or None if this is no retry.

    None means the tool should run its normal first round: no state, state
    from another mechanism or a malformed one, or an echoed state whose
    answer has not arrived (that ends in a fresh ask). Otherwise return
    (accepted, state), the state confirm_with_state sealed.

    Args:
        ctx: The retry request's context.
    """
    if ctx.request_state is None:
        return None
    try:
        state = json.loads(ctx.request_state)
    except ValueError:
        return None
    if not isinstance(state, dict) or state.get(_STATE_MARK) is not True:
        return None
    responses = ctx.input_responses
    answer = responses.get(CONFIRM_KEY) if responses else None
    if not isinstance(answer, ElicitResult):
        return None
    return _accepted(answer), state
