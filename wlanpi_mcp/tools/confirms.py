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

Known limitation: the boundary mints no single-use nonce, so a captured
*accepted* requestState still replays against the same zero-argument call
within the TTL (600s default). That window is inherent to stateless
multi-round-trip requests. Upgrade path: carry a random nonce in the sealed
state and reject a retry that repeats one (needs per-principal replay
storage).
"""

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
        return InputRequiredResult(
            input_requests={
                CONFIRM_KEY: ElicitRequest(
                    params=ElicitRequestFormParams(
                        message=message, requested_schema=_CONFIRM_SCHEMA
                    )
                )
            },
            request_state=_REQUEST_STATE,
        )
    # An unchecked box still arrives as action "accept", so the content
    # decides; accept with no content at all is not a confirmation.
    if answer.action == "accept" and (answer.content or {}).get("confirm") is True:
        return None
    return {"performed": False, "reason": "user declined or dismissed"}
