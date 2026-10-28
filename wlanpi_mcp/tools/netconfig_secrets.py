"""
Browser entry of Wi-Fi passphrases for create_network_config (URL elicitation).

A PSK given as a tool argument passes through the model and the transcript,
and the MCP spec forbids collecting secrets with form-mode elicitation. URL
mode sends the user to a page outside the client instead: create_network_config
mints a ticket here, asks the client to open GET /netconfig-secret/<ticket>,
the user types each passphrase into that page, and the tool's next round takes
the stored passphrases by ticket and sends them to wlanpi-core itself. The
model only ever sees that a passphrase was entered.

The ticket follows the download-link rules (wlanpi_mcp/download_links.py):
random, short-lived, in memory only, and minted only after wlanpi-core has
accepted the caller's JWT. Unlike a download ticket it is not spent by the
browser: the page may be reloaded until the form is submitted, the
submission is accepted once, and the stored passphrases are handed over once,
to a round carrying the same JWT that minted the ticket. Whatever is left
expires after SECRET_TTL_S. The route is the only one under SECRET_PREFIX,
and BearerTokenMiddleware lets it through without a JWT because the browser
has none; the ticket is the credential.
"""

import hashlib
import html
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from wlanpi_mcp.auth.token_context import get_token

#: Route prefix of the passphrase page; also in TICKET_PATH_PREFIXES.
SECRET_PREFIX = "/netconfig-secret/"

#: How long a passphrase ticket lives, in seconds: long enough to find the
#: passphrase and type it, short enough not to linger.
SECRET_TTL_S = 600

#: Largest form body the page accepts, in bytes.
MAX_FORM_BYTES = 16 * 1024

#: Security types core takes a psk for (core has no EAP security type).
PSK_TYPES = ("WPA2-PSK", "WPA3-PSK")

_HEX64 = re.compile(r"^[0-9A-Fa-f]{64}$")
_PRINTABLE = re.compile(r"^[\x20-\x7e]{8,63}$")

#: Security headers on every page response. The page needs no script, posts
#: only to itself, and must never be framed, cached or leak its URL.
_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
}


@dataclass
class SecretSlot:
    """One entry of the profile that needs a passphrase."""

    section: str  # 'namespaces' or 'roots'
    index: int
    ssid: str
    security: str
    interface: str


@dataclass
class SecretTicket:
    """A pending passphrase request."""

    profile: str
    owner: str | None
    slots: list[SecretSlot]
    expires: float
    values: dict[int, str] | None = None  # slot position -> passphrase
    errors: dict[int, str] = field(default_factory=dict)


#: Pending passphrase requests, ticket -> state. Memory only.
_TICKETS: dict[str, SecretTicket] = {}


def _owner() -> str | None:
    token = get_token()
    return hashlib.sha256(token.encode()).hexdigest() if token else None


def _prune(now: float) -> None:
    for ticket in [t for t, s in _TICKETS.items() if s.expires <= now]:
        _TICKETS.pop(ticket, None)


def slots_needing_secret(config: dict[str, Any]) -> list[SecretSlot]:
    """List the PSK entries of a create_network_config profile that have no psk."""
    slots = []
    for section in ("namespaces", "roots"):
        for index, entry in enumerate(config.get(section) or []):
            sec = entry.get("security") if isinstance(entry, dict) else None
            if not isinstance(sec, dict) or sec.get("security") not in PSK_TYPES:
                continue
            if sec.get("psk"):
                continue
            slots.append(
                SecretSlot(
                    section=section,
                    index=index,
                    ssid=str(sec.get("ssid") or ""),
                    security=str(sec["security"]),
                    interface=str(entry.get("interface") or ""),
                )
            )
    return slots


def mint(profile: str, slots: list[SecretSlot]) -> str:
    """Open a passphrase request for the caller's JWT; return its route."""
    now = time.time()
    _prune(now)
    ticket = secrets.token_urlsafe(32)
    _TICKETS[ticket] = SecretTicket(
        profile=profile, owner=_owner(), slots=slots, expires=now + SECRET_TTL_S
    )
    return SECRET_PREFIX + ticket


class TicketGone(Exception):
    """The ticket expired, was used, or belongs to another token."""


def take(route_or_ticket: str) -> list[tuple[SecretSlot, str]] | None:
    """
    Hand over the submitted passphrases once; None while not yet submitted.

    Raises:
        TicketGone: unknown, expired, already taken, or minted for another JWT.
    """
    _prune(time.time())
    ticket = route_or_ticket.removeprefix(SECRET_PREFIX)
    state = _TICKETS.get(ticket)
    if state is None or state.owner != _owner():
        raise TicketGone(ticket)
    if state.values is None:
        return None
    _TICKETS.pop(ticket, None)
    return [(slot, state.values[i]) for i, slot in enumerate(state.slots)]


def discard(route_or_ticket: str) -> None:
    """Drop a request the user declined, with anything already entered."""
    _TICKETS.pop(route_or_ticket.removeprefix(SECRET_PREFIX), None)


def apply(
    config: dict[str, Any], filled: list[tuple[SecretSlot, str]]
) -> dict[str, Any]:
    """Return a copy of ``config`` with each slot's psk set."""
    out = {**config}
    for section in ("namespaces", "roots"):
        if out.get(section):
            out[section] = [
                {**e, "security": {**e["security"]}}
                if isinstance(e, dict) and isinstance(e.get("security"), dict)
                else e
                for e in out[section]
            ]
    for slot, value in filled:
        out[slot.section][slot.index]["security"]["psk"] = value
    return out


def redact(text: str, filled: list[tuple[SecretSlot, str]]) -> str:
    """Remove the entered passphrases from ``text``, raw or JSON-escaped."""
    for _slot, value in filled:
        for form in {value, json.dumps(value)[1:-1]}:
            text = text.replace(form, "***")
    return text


def _check(security: str, value: str) -> str | None:
    """Core's psk rules (422 otherwise), checked here so the user can fix it."""
    if security == "WPA2-PSK":
        if _PRINTABLE.match(value) or _HEX64.match(value):
            return None
        return "8 to 63 printable ASCII characters, or 64 hex digits"
    if _PRINTABLE.match(value) and not _HEX64.match(value):
        return None
    return "8 to 63 printable ASCII characters (WPA3 takes no 64-hex key)"


def _page(state: SecretTicket, done: bool = False) -> str:
    e = html.escape
    title = f"Wi-Fi passphrase for network profile '{e(state.profile)}'"
    if done:
        body = (
            "<p class=ok>Saved. Go back to your MCP client and accept or "
            "continue there to create the profile.</p>"
            "<p>You can close this page.</p>"
        )
    else:
        fields = []
        for i, slot in enumerate(state.slots):
            where = f" on {e(slot.interface)}" if slot.interface else ""
            error = state.errors.get(i)
            fields.append(
                f"<label for=p{i}><b>{e(slot.ssid) or '(no SSID)'}</b> "
                f"<span>{e(slot.security)}{where}</span></label>"
                f"<input id=p{i} name=p{i} type=password required "
                f"autocomplete=new-password minlength=8 maxlength=64>"
                + (f"<p class=err>{e(error)}</p>" if error else "")
            )
        body = (
            "<p>Enter the passphrase for each network below. It goes straight "
            "to the WLAN Pi, never through the AI conversation.</p>"
            f"<form method=post>{''.join(fields)}<button>Save</button></form>"
        )
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>WLAN Pi passphrase</title><style>"
        "body{font:16px system-ui,sans-serif;max-width:32rem;margin:2rem auto;"
        "padding:0 1rem;color:#1d1d1f;background:#fff}"
        "label{display:block;margin-top:1rem}label span{color:#666;font-size:.9em}"
        "input{display:block;width:100%;box-sizing:border-box;padding:.5rem;"
        "margin-top:.25rem;font:inherit}"
        "button{margin-top:1.25rem;padding:.5rem 1.25rem;font:inherit}"
        ".err{color:#b00020;margin:.25rem 0 0}.ok{color:#0a6b2d}"
        "@media(prefers-color-scheme:dark){body{background:#111;color:#eee}"
        "label span{color:#aaa}.err{color:#ff6b7a}.ok{color:#5fd38a}}"
        f"</style></head><body><h1>{title}</h1>{body}</body></html>"
    )


def register_routes(mcp: MCPServer) -> None:
    """Serve the passphrase page under SECRET_PREFIX."""

    @mcp.custom_route(SECRET_PREFIX + "{ticket}", methods=["GET", "POST"])
    async def netconfig_secret_page(request: Request) -> Response:
        """Show the passphrase form, or store a submission, for a live ticket."""
        _prune(time.time())
        state = _TICKETS.get(request.path_params.get("ticket", ""))
        if state is None:
            return HTMLResponse(
                "<!doctype html><title>Link expired</title><p>This passphrase "
                "link is unknown, used or expired. Ask for the network profile "
                "to be created again.</p>",
                status_code=404,
                headers=_HEADERS,
            )
        if request.method == "GET":
            return HTMLResponse(
                _page(state, done=state.values is not None), headers=_HEADERS
            )
        if state.values is not None:
            return HTMLResponse(_page(state, done=True), headers=_HEADERS)
        raw = await request.body()
        if len(raw) > MAX_FORM_BYTES:
            return Response("form too large", status_code=413, headers=_HEADERS)
        form = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        values: dict[int, str] = {}
        state.errors = {}
        for i, slot in enumerate(state.slots):
            value = (form.get(f"p{i}") or [""])[0]
            problem = _check(slot.security, value)
            if problem:
                state.errors[i] = f"Needs {problem}."
            values[i] = value
        if state.errors:
            return HTMLResponse(_page(state), status_code=422, headers=_HEADERS)
        state.values = values
        return HTMLResponse(_page(state, done=True), headers=_HEADERS)
