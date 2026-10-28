"""
Elicitation confirms and picks for tools that must ask the user.

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

A third pair, choose_from and resume_choice, serves the mid-flow pick:
the tool calls core first, and only when core answers that several
candidates need the user's choice (scan_wlan's needsSelection) does the
server ask, as a single-select enum form rather than a checkbox. The
sealed state carries a candidates map (each option's value to the data
the retry needs from it) plus everything else the retry needs, so an
accepted retry runs straight on the chosen entry and a declined one
returns the original result unchanged. An answer naming a value outside
the sealed candidates, or with no value at all, fails closed.

Known limitation: the boundary mints no single-use nonce, so a captured
*accepted* requestState still replays against the same call with the
same arguments within the TTL (600s default). That window is inherent to
stateless multi-round-trip requests. Upgrade path: carry a random nonce
in the sealed state and reject a retry that repeats one (needs
per-principal replay storage).

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

#: Wire key for the single enum pick question. Same role as CONFIRM_KEY.
CHOICE_KEY = "wlanpi-mcp/choice"

#: Sealed into requestState on every ask. Never read back: its job is to
#: make RequestStateBoundary bind the retry to this exact request.
_REQUEST_STATE = "wlanpi-mcp/confirm-asked"


class _ConfirmForm(BaseModel):
    """The one question rendered to the user: a yes/no checkbox."""

    confirm: bool


#: Spec-valid form schema, rendered once: every confirm asks the same thing.
_CONFIRM_SCHEMA = render_elicitation_schema(_ConfirmForm)


def _ask(
    message: str,
    state: str,
    key: str = CONFIRM_KEY,
    schema: dict[str, Any] | None = None,
) -> InputRequiredResult:
    """Build the one-question ask carrying the given (pre-seal) state."""
    return InputRequiredResult(
        input_requests={
            key: ElicitRequest(
                params=ElicitRequestFormParams(
                    message=message,
                    requested_schema=_CONFIRM_SCHEMA if schema is None else schema,
                )
            )
        },
        request_state=state,
    )


def _answer_value(answer: ElicitResult, field: str) -> Any:
    """Return the value this answer carries for field, or None if no accept.

    The accept rule shared by every ask: action "accept" with the value
    present. An unchecked box still arrives as action "accept", so the
    content decides; accept with no content at all is not an answer.
    """
    if answer.action != "accept":
        return None
    return (answer.content or {}).get(field)


def _accepted(answer: ElicitResult) -> bool:
    """Whether this answer is a confirmation."""
    return _answer_value(answer, "confirm") is True


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


#: Marker inside the sealed state of a pick, so resume_choice can tell our
#: state from another mechanism's or junk. Mirrors _STATE_MARK.
_CHOICE_MARK = "wlanpi-mcp/choice-ask"

#: Schema property the enum answer rides under (and the content key the
#: client echoes it back as). Stable across rounds, like the confirm field.
_CHOICE_FIELD = "choice"


def _choice_schema(options: list[tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
    """Render a single-select enum form schema from (value, label, resume) triples.

    Uses the spec's oneOf form so each candidate can carry a display label;
    the answer is the chosen value (a string), not a boolean.
    """
    return {
        "type": "object",
        "properties": {
            _CHOICE_FIELD: {
                "type": "string",
                "oneOf": [
                    {"const": value, "title": label} for value, label, _ in options
                ],
            }
        },
        "required": [_CHOICE_FIELD],
    }


def choose_from(
    ctx: Context[Any, Any],
    message: str,
    options: list[tuple[str, str, dict[str, Any]]],
    state: dict[str, Any],
) -> InputRequiredResult | None:
    """Build a mid-flow pick ask, or None if this client cannot answer.

    Call this when core has answered that several candidates need the
    user's choice. None means the tool must behave exactly as it did
    before picks existed (surface the needs-selection result unchanged).
    The retry re-enters the tool and reads the answer with resume_choice.

    Args:
        ctx: The calling request's context.
        message: The question shown to the user.
        options: (value, label, resume) triples, one per candidate; the
            value keys the enum and the sealed candidates map, the label
            is what the user reads, and resume is what the retry finds
            under state["candidates"][choice]. Values must be unique.
        state: JSON-serializable values the retry needs beyond the chosen
            option, such as what to return on a decline. The candidates
            map is sealed alongside them.
    """
    if not form_elicitations_supported(ctx) or not options:
        return None
    sealed = {
        _CHOICE_MARK: True,
        **state,
        "candidates": {value: resume for value, _, resume in options},
    }
    return _ask(
        message, json.dumps(sealed), key=CHOICE_KEY, schema=_choice_schema(options)
    )


def resume_choice(ctx: Context[Any, Any]) -> tuple[str | None, dict[str, Any]] | None:
    """Read a retry's answer to a mid-flow pick, or None if this is no retry.

    None means the tool should run its normal first round: no state, state
    from another mechanism or a malformed one, or an echoed state whose
    answer has not arrived (that ends in a fresh ask). Otherwise return
    (choice, state): the accepted value, or None on a decline, a
    dismissal, an accept with no value at all, or a value outside the
    sealed candidates (fail closed). state is what choose_from sealed.

    Args:
        ctx: The retry request's context.
    """
    if ctx.request_state is None:
        return None
    try:
        state = json.loads(ctx.request_state)
    except ValueError:
        return None
    if not isinstance(state, dict) or state.get(_CHOICE_MARK) is not True:
        return None
    responses = ctx.input_responses
    answer = responses.get(CHOICE_KEY) if responses else None
    if not isinstance(answer, ElicitResult):
        return None
    value = _answer_value(answer, _CHOICE_FIELD)
    candidates = state.get("candidates")
    if isinstance(value, str) and isinstance(candidates, dict) and value in candidates:
        return value, state
    return None, state
