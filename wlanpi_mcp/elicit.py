"""
Ask the user directly with MCP elicitation, the multi-round-trip way.

The daemon is stateless streamable HTTP, so a tool cannot send the client a
standalone elicitation/create request mid-call (ctx.elicit() has no back
channel). Protocol revision 2026-07-28 replaces that with multi-round-trip
requests (MRTR): the tool answers with an InputRequiredResult carrying the
question, the client asks the user and retries the same tools/call with
inputResponses and the requestState we handed out. These helpers build those
rounds and read the answers back.

Elicitation is used only when the request itself is 2026-07-28 and its
_meta clientCapabilities declare the mode we need. Anything else (a legacy
request, Claude Desktop, claude -p) gets the tool's behaviour from before,
so every caller must keep a working path for "cannot ask".

requestState is sealed by the SDK's RequestStateBoundary (AES-GCM, bound to
the tool name, its arguments and the caller's JWT; see
request_state_security()). It records which questions this server asked, and
an answer counts only for a question the state says we asked, so a client
cannot pre-fill a confirm on the first round. The key is per process: a round
pending across a daemon restart fails with -32602 "Invalid or expired
requestState" and the client starts over.

Form mode must not collect secrets (MCP spec); create_network_config uses URL
mode for those.
"""

import hashlib
import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context
from mcp.server.request_state import RequestStateSecurity
from mcp_types import InputRequiredResult
from mcp_types.version import is_version_at_least

from wlanpi_mcp.auth.token_context import get_token

if TYPE_CHECKING:
    from wlanpi_mcp.client.core_client import CoreClient

#: The first protocol revision with MRTR and per-request client capabilities.
MODERN_PROTOCOL = "2026-07-28"

#: How long a pending question stays answerable, in seconds.
STATE_TTL_S = 600.0


def _token_principal(ctx: ServerRequestContext[Any, Any]) -> str | None:
    """Bind sealed state to the caller's JWT, as the middleware's principal does."""
    token = get_token()
    return hashlib.sha256(token.encode()).hexdigest() if token else None


def request_state_security() -> RequestStateSecurity:
    """
    Return the requestState policy for this server: a per-process key, JWT-bound.

    The SDK's default binds state to its own OAuth identity, which this
    server does not use (wlanpi-core validates the passed-through JWT), so
    without this a round could be finished under a different token.
    """
    return RequestStateSecurity(
        keys=[os.urandom(32)], ttl=STATE_TTL_S, bind_principal=_token_principal
    )


def is_modern(protocol_version: str | None) -> bool:
    """Return True for a 2026-07-28 (or later) request."""
    return protocol_version is not None and is_version_at_least(
        protocol_version, MODERN_PROTOCOL
    )


def _modern(ctx: Context) -> bool:
    return is_modern(ctx.protocol_version)


def can_form(ctx: Context) -> bool:
    """Return True when this request lets us ask the user with a form."""
    if not _modern(ctx):
        return False
    caps = ctx.client_capabilities
    elicitation = caps.elicitation if caps is not None else None
    # A bare `elicitation: {}` predates modes and means form.
    return elicitation is not None and (
        elicitation.form is not None or elicitation.url is None
    )


def can_url(ctx: Context) -> bool:
    """Return True when this request lets us send the user to a URL."""
    if not _modern(ctx):
        return False
    caps = ctx.client_capabilities
    elicitation = caps.elicitation if caps is not None else None
    return elicitation is not None and elicitation.url is not None


def state(ctx: Context) -> dict[str, Any]:
    """Return the plaintext state from our previous round, or {} on the first."""
    raw = ctx.request_state
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except ValueError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


@dataclass(frozen=True)
class Answer:
    """The user's response to one of our questions."""

    action: str  # accept | decline | cancel
    content: dict[str, Any]

    @property
    def accepted(self) -> bool:
        """True when the user accepted (submitted the form, or opened the URL)."""
        return self.action == "accept"


def answer(ctx: Context, key: str) -> Answer | None:
    """
    Return the user's answer to question ``key``, or None if there is none yet.

    Only a question our sealed state says we asked counts.
    """
    if key not in state(ctx).get("asked", []):
        return None
    response = (ctx.input_responses or {}).get(key)
    if response is None:
        return None
    action = getattr(response, "action", None)
    if action is None:
        return None
    content = getattr(response, "content", None) or {}
    return Answer(action=str(action), content=dict(content))


def ask(
    ctx: Context, key: str, request: dict[str, Any], **extra: Any
) -> InputRequiredResult:
    """
    Answer this round with one question; the client retries with the answer.

    ``extra`` is merged into the state carried to the next round (e.g. a
    ticket); keys from earlier rounds are kept.
    """
    carried = state(ctx)
    asked = sorted({*carried.get("asked", []), key})
    return InputRequiredResult(
        input_requests={key: request},  # type: ignore[dict-item]
        request_state=json.dumps({**carried, **extra, "asked": asked}),
    )


def form_request(
    message: str,
    properties: dict[str, Any] | None = None,
    required: list[str] | None = None,
) -> dict[str, Any]:
    """Build an elicitation/create form request. No properties = a plain confirm."""
    schema: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        schema["required"] = required
    return {
        "method": "elicitation/create",
        "params": {"mode": "form", "message": message, "requestedSchema": schema},
    }


def url_request(message: str, url: str) -> dict[str, Any]:
    """Build an elicitation/create URL request (2026-07-28 has no elicitationId)."""
    return {
        "method": "elicitation/create",
        "params": {"mode": "url", "message": message, "url": url},
    }


async def confirm(
    ctx: Context,
    key: str,
    message: str | Callable[[], Awaitable[str]],
    what: str,
) -> dict[str, Any] | InputRequiredResult | None:
    """
    Ask the user to confirm an action before the tool performs it.

    Returns None to go ahead: the user accepted, or this client cannot be
    asked (the docstring's ask-the-user rule then stands). Otherwise returns
    what the tool must return as is: the question (an InputRequiredResult),
    or not_performed(what) when the user declined or dismissed it.
    ``message`` may be a coroutine factory, so its lookups run only when we
    actually ask.
    """
    if not can_form(ctx):
        return None
    reply = answer(ctx, key)
    if reply is None:
        text = message if isinstance(message, str) else await message()
        return ask(ctx, key, form_request(text))
    return None if reply.accepted else not_performed(what)


def choose(
    ctx: Context,
    key: str,
    message: str,
    options: list[tuple[str, str]],
    field: str = "choice",
) -> str | InputRequiredResult | None:
    """
    Ask the user to pick one of ``options`` ((value, label) pairs).

    Returns the chosen value, None when the user declined or the client
    cannot be asked, or an InputRequiredResult to return as is. A value not
    among the options counts as no choice.
    """
    if not can_form(ctx):
        return None
    reply = answer(ctx, key)
    if reply is None:
        prop = {
            "type": "string",
            "title": "Choose one",
            "oneOf": [{"const": value, "title": label} for value, label in options],
        }
        return ask(ctx, key, form_request(message, {field: prop}, [field]))
    if not reply.accepted:
        return None
    picked = reply.content.get(field)
    return picked if picked in {value for value, _ in options} else None


async def device_name(client: "CoreClient") -> str:
    """Return the hostname for a confirm message; generic if core can't say."""
    try:
        info = await client.get("/api/v1/system/device/info")
    except Exception:  # noqa: BLE001 - a confirm must not fail on its wording
        return "the WLAN Pi"
    name = info.get("hostname") if isinstance(info, dict) else None
    return str(name) if name else "the WLAN Pi"


def not_performed(what: str) -> dict[str, Any]:
    """Return the result for an action the user did not approve. Not an error."""
    return {
        "status": "not_performed",
        "message": (
            f"Not performed: the user declined to {what}. Nothing was changed; "
            "do not retry unless the user asks again."
        ),
    }
