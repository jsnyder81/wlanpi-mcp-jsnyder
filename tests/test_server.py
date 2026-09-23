"""Regression guards for the assembled streamable HTTP app as nginx presents it."""

from contextlib import asynccontextmanager

import httpx
import pytest
import respx

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import CLASSROOM_TOOLS
from wlanpi_mcp.middleware.bearer_token import BearerTokenMiddleware
from wlanpi_mcp.server import create_server

# What the daemon sees through the nginx front: the client's real Host and
# Origin are forwarded verbatim (proxy_set_header Host $http_host), so the
# loopback-only daemon must accept LAN addresses, hostnames and both ports.
FORWARDED_HEADERS = [
    {"Host": "10.254.102.51:8767", "Origin": "https://10.254.102.51:8767"},
    {"Host": "10.254.102.51:8766", "Origin": "http://10.254.102.51:8766"},
    {"Host": "wlanpi-9be.local:8767"},
]

# The streamable HTTP transport refuses a POST without both media types in
# Accept (406), whatever the response mode.
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}

DEVICE_INFO_URL = "https://localhost:31415/api/v1/system/device/info"


def _initialize(request_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        },
    }


def _call_tool(name: str, request_id: int = 2) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": {}},
    }


@pytest.fixture
def core(settings):
    # Deliberately not the conftest `client` fixture: that one pre-sets the
    # token contextvar, which would mask whether the token really travels
    # from the HTTP header into the tool call.
    return CoreClient(settings)


@pytest.fixture
def mcp(core):
    return create_server(core, host="127.0.0.1", port=8768)


@asynccontextmanager
async def _serve(mcp, *, with_middleware: bool = True):
    """Yield an httpx client bound to the assembled app, with its lifespan running.

    httpx's ASGITransport does not run the app lifespan, which is where the
    session manager starts the task group every request is served from. This
    is a context manager rather than an async fixture because the manager's
    task group must be entered and exited in the same task, and pytest-asyncio
    tears async-generator fixtures down elsewhere.

    Pass with_middleware=False to omit BearerTokenMiddleware, so the contextvar
    it would set stays untouched and get_token() has only the transport-bound
    request to read from.
    """
    app = mcp.streamable_http_app()
    if with_middleware:
        app.add_middleware(BearerTokenMiddleware)
    transport = httpx.ASGITransport(app=app)
    async with mcp.session_manager.run():
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8768"
        ) as http:
            yield http


def test_dns_rebinding_protection_is_off_for_loopback_bind(mcp):
    # FastMCP flips this on automatically for host=127.0.0.1; the nginx front
    # forwards LAN Host headers, so it must stay off (the Bearer gate is the
    # protection).
    security = mcp.settings.transport_security
    assert security is not None
    assert security.enable_dns_rebinding_protection is False


def test_transport_is_stateless_json_on_mcp_path(mcp):
    # Stateless is the point of the move: no server-side session for a
    # reconnecting client to strand on. JSON responses keep nginx/curl simple.
    assert mcp.settings.streamable_http_path == "/mcp"
    assert mcp.settings.stateless_http is True
    assert mcp.settings.json_response is True


@pytest.mark.parametrize("headers", FORWARDED_HEADERS)
async def test_mcp_accepts_forwarded_lan_host(mcp, headers):
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=_initialize(),
            headers={
                "Authorization": "Bearer core.jwt.abc123",
                **MCP_HEADERS,
                **headers,
            },
        )
    # 421/403 mean the Host/Origin check fired.
    assert response.status_code == 200, response.text
    assert response.json()["result"]["serverInfo"]["name"] == "WLAN Pi"


async def test_mcp_rejects_missing_bearer(mcp):
    async with _serve(mcp) as http:
        response = await http.post("/mcp", json=_initialize(), headers=MCP_HEADERS)
    assert response.status_code == 401


@respx.mock
async def test_tool_call_without_initialize_forwards_bearer(mcp):
    # The failure that forced the move off SSE: a client that reconnected
    # without re-sending initialize had every tools/call answered -32602.
    # Stateless mode has no handshake to miss, and the call's own Bearer is
    # what reaches wlanpi-core.
    route = respx.get(DEVICE_INFO_URL).mock(
        return_value=httpx.Response(200, json={"hostname": "wlanpi-9be"})
    )
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=_call_tool("get_device_info"),
            headers={"Authorization": "Bearer core.jwt.abc123", **MCP_HEADERS},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "error" not in body, body
    assert body["result"]["isError"] is False
    assert body["result"]["structuredContent"] == {"hostname": "wlanpi-9be"}
    assert route.call_count == 1
    assert route.calls[0].request.headers["Authorization"] == "Bearer core.jwt.abc123"


@respx.mock
async def test_each_request_carries_its_own_token(mcp):
    # Stateless replacement for the SSE session binding: with no session to
    # share, a request can only ever run with the token it carried itself.
    route = respx.get(DEVICE_INFO_URL).mock(
        return_value=httpx.Response(200, json={"hostname": "wlanpi-9be"})
    )
    async with _serve(mcp) as http:
        for token in ("token-A", "token-B", "token-A"):
            response = await http.post(
                "/mcp",
                json=_call_tool("get_device_info"),
                headers={"Authorization": f"Bearer {token}", **MCP_HEADERS},
            )
            assert response.status_code == 200, response.text
            assert response.json()["result"]["isError"] is False
    seen = [call.request.headers["Authorization"] for call in route.calls]
    assert seen == ["Bearer token-A", "Bearer token-B", "Bearer token-A"]


@respx.mock
async def test_transport_populates_request_header_token(mcp):
    # get_token() reads the Authorization header off the Starlette request the
    # streamable HTTP transport binds to each MCP call (the SDK's request_ctx).
    # The middleware path would set the same token on the contextvar, so it
    # cannot distinguish the two. Run the app WITHOUT the middleware and poison
    # the contextvar with a decoy: only a transport-bound request can supply the
    # real token, so this fails if the SDK ever stops populating request_ctx.
    from wlanpi_mcp.auth.token_context import current_token

    route = respx.get(DEVICE_INFO_URL).mock(
        return_value=httpx.Response(200, json={"hostname": "wlanpi-9be"})
    )
    reset = current_token.set("decoy.contextvar.token")
    try:
        async with _serve(mcp, with_middleware=False) as http:
            response = await http.post(
                "/mcp",
                json=_call_tool("get_device_info"),
                headers={"Authorization": "Bearer header.token", **MCP_HEADERS},
            )
        assert response.status_code == 200, response.text
        assert response.json()["result"]["isError"] is False
        # The decoy contextvar is still set, so only a transport-bound request
        # could have produced the real token; core saw the header, not the decoy.
        assert route.call_count == 1
        assert route.calls[0].request.headers["Authorization"] == "Bearer header.token"
    finally:
        current_token.reset(reset)


def _tool_names(server) -> set[str]:
    return {tool.name for tool in server._tool_manager.list_tools()}


def test_every_classroom_tool_is_registered(core):
    # Guards the allowlist against tool renames: a stale name would fail
    # classroom startup, so catch it here instead.
    assert CLASSROOM_TOOLS <= _tool_names(create_server(core))


def test_classroom_profile_hides_control_tools(core):
    names = _tool_names(create_server(core, tools=CLASSROOM_TOOLS))
    assert names == CLASSROOM_TOOLS
    for control in ("restart_service", "reboot_device", "set_regulatory_domain"):
        assert control not in names


def test_unknown_allowlisted_tool_fails_startup(core):
    with pytest.raises(ValueError, match="no_such_tool"):
        create_server(core, tools={"get_device_info", "no_such_tool"})
