"""Regression guards for the assembled streamable HTTP app as nginx presents it."""

import asyncio
import shlex
from contextlib import asynccontextmanager

import httpx
import pytest
import respx

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.middleware.bearer_token import BearerTokenMiddleware
from wlanpi_mcp.resources import device as device_resources
from wlanpi_mcp.server import create_http_app, create_server

# What the daemon sees through the nginx front: the client's real Host and
# Origin are forwarded verbatim (proxy_set_header Host $http_host), so the
# loopback-only daemon must accept LAN addresses and hostnames, with or without a port.
FORWARDED_HEADERS = [
    {"Host": "10.254.102.51:8767", "Origin": "https://10.254.102.51:8767"},
    {"Host": "10.254.102.51"},
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
    return create_server(core)


@asynccontextmanager
async def _serve(mcp):
    """Yield an httpx client bound to the assembled app, with its lifespan running.

    httpx's ASGITransport does not run the app lifespan, which is where the
    session manager starts the task group every request is served from. This
    is a context manager rather than an async fixture because the manager's
    task group must be entered and exited in the same task, and pytest-asyncio
    tears async-generator fixtures down elsewhere.
    """
    app = create_http_app(mcp)
    app.add_middleware(BearerTokenMiddleware)
    transport = httpx.ASGITransport(app=app)
    async with mcp.session_manager.run():
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8768"
        ) as http:
            yield http


def test_dns_rebinding_protection_is_off_for_loopback_bind(mcp):
    # The nginx front forwards LAN Host headers, so the check must stay off
    # (the Bearer gate is the protection).
    create_http_app(mcp)
    security = mcp.session_manager.security_settings
    assert security is not None
    assert security.enable_dns_rebinding_protection is False


def test_transport_is_stateless_json_on_mcp_path(mcp):
    # Stateless is the point of the move: no server-side session for a
    # reconnecting client to strand on. JSON responses keep nginx/curl simple.
    app = create_http_app(mcp)
    assert any(r.path == "/mcp" for r in app.routes)
    assert mcp.session_manager.stateless is True
    assert mcp.session_manager.json_response is True


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
async def test_concurrent_requests_keep_their_own_token(mcp):
    # Tool handlers run in the contextvars of the request that carried the call
    # (there is no request_ctx in mcp 2.x), so two in-flight requests with
    # different tokens must each reach core with their own Bearer.
    arrivals = 0
    both_arrived = asyncio.Event()

    async def device_info(request: httpx.Request) -> httpx.Response:
        # Barrier: neither call answers until both are in flight at once.
        nonlocal arrivals
        arrivals += 1
        if arrivals == 2:
            both_arrived.set()
        await asyncio.wait_for(both_arrived.wait(), 2)
        return httpx.Response(200, json={"hostname": request.headers["Authorization"]})

    respx.get(DEVICE_INFO_URL).mock(side_effect=device_info)
    async with _serve(mcp) as http:
        responses = await asyncio.gather(
            *(
                http.post(
                    "/mcp",
                    json=_call_tool("get_device_info"),
                    headers={"Authorization": f"Bearer {token}", **MCP_HEADERS},
                )
                for token in ("token-A", "token-B")
            )
        )
    for token, response in zip(("token-A", "token-B"), responses, strict=True):
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result["isError"] is False
        assert result["structuredContent"] == {"hostname": f"Bearer {token}"}


@respx.mock
async def test_modern_protocol_request_forwards_its_own_bearer(mcp):
    # 2026-07-28 requests carry no handshake and are routed by headers; they
    # take a different SDK path than the stateless 2025-era POSTs above.
    route = respx.get(DEVICE_INFO_URL).mock(
        return_value=httpx.Response(200, json={"hostname": "wlanpi-9be"})
    )
    version = "2026-07-28"
    call = _call_tool("get_device_info")
    call["params"]["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=call,
            headers={
                "Authorization": "Bearer modern.token",
                "MCP-Protocol-Version": version,
                "Mcp-Method": "tools/call",
                "Mcp-Name": "get_device_info",
                **MCP_HEADERS,
            },
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["result"]["isError"] is False, body
    assert route.calls[0].request.headers["Authorization"] == "Bearer modern.token"


@respx.mock
async def test_unreachable_core_reaches_the_client(mcp):
    # A transport failure must not collapse into a generic tool error.
    respx.get(DEVICE_INFO_URL).mock(
        side_effect=httpx.ConnectError("[Errno 111] Connection refused")
    )
    async with _serve(mcp) as http:
        reply = await http.post(
            "/mcp",
            json=_call_tool("get_device_info"),
            headers={"Authorization": "Bearer t", **MCP_HEADERS},
        )
    result = reply.json()["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "wlanpi-core unreachable" in text and "Connection refused" in text, text


def _read_resource(uri: str, request_id: int = 2) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "resources/read",
        "params": {"uri": uri},
    }


@pytest.mark.parametrize(
    ("core_response", "expected"),
    [
        (
            httpx.Response(401, json={"detail": "Invalid token"}),
            ["401", "Invalid token"],
        ),
        (
            httpx.ConnectError("[Errno 111] Connection refused"),
            ["wlanpi-core unreachable", "Connection refused"],
        ),
    ],
)
@respx.mock
async def test_core_error_reaches_a_resource_read(
    mcp, monkeypatch, core_response, expected
):
    # mcp 2.x withholds the message of anything but a ResourceError from a
    # resources/read, so the core error classes are ResourceErrors too.
    monkeypatch.setattr(device_resources, "_cache", {})
    route = respx.get(DEVICE_INFO_URL)
    if isinstance(core_response, Exception):
        route.mock(side_effect=core_response)
    else:
        route.mock(return_value=core_response)
    async with _serve(mcp) as http:
        reply = await http.post(
            "/mcp",
            json=_read_resource("device://info"),
            headers={"Authorization": "Bearer t", **MCP_HEADERS},
        )
    message = reply.json()["error"]["message"]
    for part in expected:
        assert part in message, message


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (409, {"detail": "interface busy"}, ["409", "interface busy"]),
        (
            422,
            {"detail": {"message": "nope", "outcomes": ["a", "b"]}},
            ["422", "nope", "outcomes"],
        ),
        (502, "upstream exploded", ["502", "upstream exploded"]),
    ],
)
@respx.mock
async def test_core_error_detail_reaches_the_client(mcp, status, body, expected):
    # mcp 2.1+ reduces an arbitrary exception to "Error executing tool X";
    # CoreAPIError is a ToolError so core's status and detail still get through.
    if isinstance(body, str):
        response = httpx.Response(status, text=body)
    else:
        response = httpx.Response(status, json=body)
    respx.get(DEVICE_INFO_URL).mock(return_value=response)
    async with _serve(mcp) as http:
        reply = await http.post(
            "/mcp",
            json=_call_tool("get_device_info"),
            headers={"Authorization": "Bearer t", **MCP_HEADERS},
        )
    result = reply.json()["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    for part in expected:
        assert part in text, text


@respx.mock
async def test_pcap_download_link_serves_the_file_once_without_a_jwt(
    mcp, monkeypatch, tmp_path
):
    # The point of the link: an agent saves a pcap with plain curl, the bytes
    # never pass through the MCP result, and curl needs no JWT. The ticket is
    # minted by an authenticated tool call, works once, then 404s.
    from wlanpi_mcp.capture import storage
    from wlanpi_mcp.config import Settings
    from wlanpi_mcp.tools import capture_file

    settings = Settings(PCAP_CAPTURE_DIR=str(tmp_path), _env_file=None)
    monkeypatch.setattr(storage, "get_settings", lambda: settings)
    monkeypatch.setattr(capture_file, "get_settings", lambda: settings)
    capture_file._TICKETS.clear()
    data = b"\x0a\x0d\x0d\x0a" + bytes(range(256)) * 4
    pcap = tmp_path / "capture-20261003T120000-cap_e2e.pcapng"
    pcap.write_bytes(data)
    respx.get(DEVICE_INFO_URL).mock(
        return_value=httpx.Response(200, json={"hostname": "wlanpi-9be"})
    )

    call = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "get_pcap_download_url",
            "arguments": {"capture_id": "cap_e2e"},
        },
    }
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=call,
            headers={
                "Authorization": "Bearer core.jwt.abc123",
                "Host": "wlanpi-9be.local:8767",
                "X-Forwarded-Proto": "https",
                **MCP_HEADERS,
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]["structuredContent"]
        url = result["download_url"]
        assert url.startswith("https://wlanpi-9be.local:8767/pcap/")
        assert result["size_bytes"] == len(data)
        assert url in result["curl"] and result["curl"].startswith("curl -gsSfk -o ")
        route = url.removeprefix("https://wlanpi-9be.local:8767")

        first = await http.get(route)  # no Authorization header
        assert first.status_code == 200
        assert first.content == data
        assert first.headers["content-type"] == capture_file.PCAP_MIME

        again = await http.get(route)
        assert again.status_code == 404

        bogus = await http.get("/pcap/not-a-ticket")
        assert bogus.status_code == 404

        # Everything else still needs the Bearer token.
        still_gated = await http.post("/mcp", json=_initialize(), headers=MCP_HEADERS)
        assert still_gated.status_code == 401


async def test_expired_pcap_download_link_is_refused(mcp, monkeypatch, tmp_path):
    from wlanpi_mcp.capture import storage
    from wlanpi_mcp.config import Settings
    from wlanpi_mcp.tools import capture_file

    settings = Settings(PCAP_CAPTURE_DIR=str(tmp_path), _env_file=None)
    monkeypatch.setattr(storage, "get_settings", lambda: settings)
    pcap = tmp_path / "capture-20261003T120000-cap_old.pcapng"
    pcap.write_bytes(b"\x0a\x0d\x0d\x0a")
    capture_file._TICKETS.clear()
    capture_file._TICKETS["stale"] = (str(pcap.resolve()), 1.0)  # long expired
    async with _serve(mcp) as http:
        response = await http.get("/pcap/stale")
    assert response.status_code == 404
    assert capture_file._TICKETS == {}


@respx.mock
async def test_profiler_report_links_serve_each_file_once_without_a_jwt(
    mcp, monkeypatch, tmp_path
):
    # get_profiler_reports(output="links") mints a ticket per file through an
    # authenticated /mcp call; plain curl then fetches each one once.
    from wlanpi_mcp.tools import profiler_reports

    profiler_reports._TICKETS.clear()
    files_url = "https://localhost:31415/api/v1/profiler/files"
    stem = "clients/aa-bb-cc-dd-ee-ff/aa-bb-cc-dd-ee-ff_5GHz"
    modified = "2026-10-04T12:00:00Z"
    respx.get(files_url).mock(
        return_value=httpx.Response(
            200,
            json={
                "clients": [
                    {
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "files": [
                            {"path": f"{stem}.json", "size": 12, "modified": modified},
                            {"path": f"{stem}.pcap", "size": 4, "modified": modified},
                        ],
                    }
                ],
                "reports": [],
            },
        )
    )
    respx.get(f"{files_url}/{stem}.json").mock(
        return_value=httpx.Response(200, json={"mac": "x"})
    )
    respx.get(f"{files_url}/{stem}.pcap").mock(
        return_value=httpx.Response(
            200,
            content=b"\xd4\xc3\xb2\xa1",
            headers={"content-type": "application/vnd.tcpdump.pcap"},
        )
    )
    call = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "get_profiler_reports", "arguments": {"output": "links"}},
    }
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=call,
            headers={
                "Authorization": "Bearer core.jwt.abc123",
                "Host": "wlanpi-9be.local:8767",
                "X-Forwarded-Proto": "https",
                **MCP_HEADERS,
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]["structuredContent"]
        files = {f["path"]: f["download_url"] for f in result["files"]}
        pcap_url = files["clients/aa-bb-cc-dd-ee-ff/aa-bb-cc-dd-ee-ff_5GHz.pcap"]
        assert pcap_url.startswith("https://wlanpi-9be.local:8767/profiler-report/")
        route = pcap_url.removeprefix("https://wlanpi-9be.local:8767")

        first = await http.get(route)  # no Authorization header
        assert first.status_code == 200
        assert first.content == b"\xd4\xc3\xb2\xa1"
        assert first.headers["content-type"] == "application/vnd.tcpdump.pcap"
        assert "aa-bb-cc-dd-ee-ff_5GHz.pcap" in first.headers["content-disposition"]

        assert (await http.get(route)).status_code == 404
        assert (await http.get("/profiler-report/nope")).status_code == 404
    # Every core call, the listing and each file, carried the caller's own JWT.
    assert len(respx.calls) == 3
    assert {c.request.headers["Authorization"] for c in respx.calls} == {
        "Bearer core.jwt.abc123"
    }


def test_ticket_download_routes_are_the_only_routes_without_a_jwt(mcp):
    # BearerTokenMiddleware exempts everything under TICKET_PATH_PREFIXES, so
    # any other route added there would be served without authentication.
    from wlanpi_mcp.middleware.bearer_token import TICKET_PATH_PREFIXES
    from wlanpi_mcp.tools import capture_file, netconfig_secrets, profiler_reports

    exempt = sorted(
        route.path
        for route in create_http_app(mcp).routes
        if route.path.startswith(TICKET_PATH_PREFIXES)
    )
    assert exempt == sorted(
        [
            capture_file.DOWNLOAD_PREFIX + "{ticket}",
            profiler_reports.REPORT_PREFIX + "{ticket}",
            netconfig_secrets.SECRET_PREFIX + "{ticket}",
        ]
    )
    assert sorted(TICKET_PATH_PREFIXES) == sorted(
        [
            capture_file.DOWNLOAD_PREFIX,
            profiler_reports.REPORT_PREFIX,
            netconfig_secrets.SECRET_PREFIX,
        ]
    )


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        # A list from a proxy chain: the first hop is the client's scheme.
        (
            {"Host": "wlanpi-9be.local:8767", "X-Forwarded-Proto": "https, http"},
            "https://wlanpi-9be.local:8767/pcap/",
        ),
        (
            {"Host": "[fe80::1]:8767", "X-Forwarded-Proto": "https"},
            "https://[fe80::1]:8767/pcap/",
        ),
        # Not a scheme: fall back to the one the request arrived on.
        (
            {"Host": "127.0.0.1:8768", "X-Forwarded-Proto": "javascript"},
            "http://127.0.0.1:8768/pcap/",
        ),
        # A Host that is not a plain host[:port] gets no link or curl command.
        ({"Host": "evil'; rm -rf ~; echo '"}, None),
    ],
)
@respx.mock
async def test_pcap_download_link_sanitises_forwarded_headers(
    mcp, monkeypatch, tmp_path, headers, expected
):
    from wlanpi_mcp.capture import storage
    from wlanpi_mcp.config import Settings
    from wlanpi_mcp.tools import capture_file

    settings = Settings(PCAP_CAPTURE_DIR=str(tmp_path), _env_file=None)
    monkeypatch.setattr(storage, "get_settings", lambda: settings)
    monkeypatch.setattr(capture_file, "get_settings", lambda: settings)
    (tmp_path / "capture-20261003T120000-cap_h.pcapng").write_bytes(b"x")
    respx.get(DEVICE_INFO_URL).mock(return_value=httpx.Response(200, json={}))
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_pcap_download_url",
            "arguments": {"capture_id": "cap_h"},
        },
    }
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=call,
            headers={"Authorization": "Bearer t", **headers, **MCP_HEADERS},
        )
    result = response.json()["result"]["structuredContent"]
    if expected is None:
        assert "download_url" not in result and "curl" not in result
        assert result["download_path"].startswith("/pcap/")
    else:
        assert result["download_url"].startswith(expected)
        # IPv6 brackets are quoted for the shell; -g stops curl globbing them.
        args = shlex.split(result["curl"])
        assert args[0] == "curl" and "g" in args[1]
        assert args[-1] == result["download_url"]
