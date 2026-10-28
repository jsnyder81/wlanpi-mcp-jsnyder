"""Starlette middleware requiring a wlanpi-core JWT on every HTTP request."""

import hashlib

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.authentication import AuthCredentials
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from wlanpi_mcp.auth.token_context import current_request, current_token

#: Path prefixes served without a Bearer token because the route itself checks
#: a one-time ticket (tools/capture_file.py DOWNLOAD_PREFIX,
#: tools/profiler_reports.py REPORT_PREFIX, tools/netconfig_secrets.py
#: SECRET_PREFIX, whose page a browser opens with no JWT). Keep in sync.
TICKET_PATH_PREFIXES = ("/pcap/", "/profiler-report/", "/netconfig-secret/")


def _principal_for(token: str) -> AuthenticatedUser:
    """
    Represent the connecting token as an ASGI principal.

    The principal is keyed by a fingerprint of the token itself. The MCP
    streamable HTTP session manager binds a session to the principal on
    scope["user"] when the session is created and rejects any later request
    on that session whose principal differs (mcp/server/streamable_http_manager.py).
    The daemon runs the transport stateless, so there are no sessions to bind
    and every request stands alone with its own token; the principal is still
    published so that property holds unchanged if stateful mode is ever turned
    on.

    We hash rather than parse the JWT: this middleware never validates tokens
    (that is wlanpi-core's job), and the fingerprint only needs to be stable
    and unique per token. The raw token stays out of the principal object; it
    already lives in the contextvar for the actual API call.
    """
    fingerprint = hashlib.sha256(token.encode()).hexdigest()
    return AuthenticatedUser(
        AccessToken(token=fingerprint, client_id=fingerprint, scopes=[])
    )


class BearerTokenMiddleware:
    """
    Require a wlanpi-core JWT on every HTTP request and stash it in a contextvar.

    The JWT must arrive as 'Authorization: Bearer <token>' so CoreClient can
    pass it through to wlanpi-core. The token is not validated here —
    wlanpi-core rejects bad tokens with a 401, which propagates back to the MCP
    client as a tool error.

    Pure ASGI middleware (not BaseHTTPMiddleware) so the downstream app runs
    in the same task. The streamable HTTP transport starts the per-request
    MCP server task from inside this request, so the contextvars set here
    (the token and the Starlette request) are what a tool sees, per request.

    It also publishes a per-token principal on scope["user"] so a stateful
    session manager would bind each session to its opening token (see
    _principal_for).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Require a Bearer token on every HTTP request and stash it in the contextvar."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # One-time download links carry no JWT: the route admits only a
        # ticket minted by an authenticated tool call.
        if scope.get("path", "").startswith(TICKET_PATH_PREFIXES):
            await self.app(scope, receive, send)
            return

        auth = Headers(scope=scope).get("authorization", "")
        token = (
            auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        )

        if not token:
            response = JSONResponse(
                {
                    "detail": (
                        "Missing Bearer token. Obtain a JWT from wlanpi-core "
                        "(POST /api/v1/auth/token) and send it as "
                        "'Authorization: Bearer <token>'."
                    )
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        scope["user"] = _principal_for(token)
        scope["auth"] = AuthCredentials()

        ctx_token = current_token.set(token)
        req_token = current_request.set(Request(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            current_request.reset(req_token)
            current_token.reset(ctx_token)
