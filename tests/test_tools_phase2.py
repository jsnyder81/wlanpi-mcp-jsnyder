import httpx
import pytest
import respx
from mcp.server.mcpserver import Context

# ── WLAN ─────────────────────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_scan_wlan_uses_canonical_endpoint():
    from unittest.mock import AsyncMock, MagicMock

    from mcp.server.mcpserver import MCPServer

    from wlanpi_mcp.tools.wlan import register

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"nets": []})

    mcp = MCPServer("test")
    register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["scan_wlan"].fn
    await tool_fn(ctx=Context(), interface="wlan0", detail="full")

    mock_client.get.assert_called_once()
    path = mock_client.get.call_args.args[0]
    params = mock_client.get.call_args.kwargs["params"]
    assert path == "/api/v1/utils/wlan/scan"
    assert params == {"hidden": True, "detail": "full", "iface": "wlan0"}


def test_deprecated_wlan_tools_removed():
    """Verify deprecated /network/wlan tools were removed.

    /network/wlan/set returns 410 Gone and getInterfaces/getConnected are
    deprecated upstream — their tools were removed in favour of the netconfig
    tools (create/activate config, config status).
    """
    from unittest.mock import MagicMock

    from mcp.server.mcpserver import MCPServer

    from wlanpi_mcp.tools.wlan import register

    mcp = MCPServer("test")
    register(mcp, MagicMock())

    tools = mcp._tool_manager._tools
    assert "connect_wlan" not in tools
    assert "get_wlan_interfaces" not in tools
    assert "get_connected_network" not in tools
    assert "scan_wlan" in tools
    # /network/wlan/revert now reverts everything Core manages and is
    # deprecated; deactivate_network_config + reset_network_namespaces replace it.
    assert "revert_wlan" not in tools


# ── VLAN ─────────────────────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_get_vlans(client):
    respx.get("https://localhost:31415/api/v1/network/ethernet/all/vlan").mock(
        return_value=httpx.Response(200, json={"eth0.10": []})
    )
    result = await client.get("/api/v1/network/ethernet/all/vlan")
    assert "eth0.10" in result


@respx.mock
@pytest.mark.asyncio
async def test_create_vlan(client):
    respx.post("https://localhost:31415/api/v1/network/ethernet/eth0/vlan/10").mock(
        return_value=httpx.Response(200, json={"result": {}})
    )
    result = await client.post(
        "/api/v1/network/ethernet/eth0/vlan/10",
        json=[{"family": "inet", "local": "192.168.10.1", "prefixlen": 24}],
    )
    assert "result" in result


@respx.mock
@pytest.mark.asyncio
async def test_delete_vlan(client):
    respx.delete("https://localhost:31415/api/v1/network/ethernet/eth0/vlan/10").mock(
        return_value=httpx.Response(200, json={"result": {}})
    )
    result = await client.delete("/api/v1/network/ethernet/eth0/vlan/10")
    assert "result" in result


# ── Profiler ──────────────────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_get_profiler_status(client):
    respx.get("https://localhost:31415/api/v1/profiler/status").mock(
        return_value=httpx.Response(200, json={"running": False, "ssid": None})
    )
    result = await client.get("/api/v1/profiler/status")
    assert "running" in result


@respx.mock
@pytest.mark.asyncio
async def test_start_profiler_builds_minimal_body():
    from unittest.mock import AsyncMock, MagicMock

    from mcp.server.mcpserver import MCPServer

    from wlanpi_mcp.tools.profiler import register

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"success": True})

    mcp = MCPServer("test")
    register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["start_profiler"].fn
    await tool_fn(interface="wlan0", channel=6)

    body = mock_client.post.call_args.kwargs["json"]
    assert body["interface"] == "wlan0"
    assert body["channel"] == 6
    assert "frequency" not in body  # omitted None fields


async def test_start_profiler_forwards_newer_flags():
    from unittest.mock import AsyncMock, MagicMock

    from mcp.server.mcpserver import MCPServer

    from wlanpi_mcp.tools.profiler import register

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"success": True})

    mcp = MCPServer("test")
    register(mcp, mock_client)

    await mcp._tool_manager._tools["start_profiler"].run(
        {
            "noprep": True,
            "noprofilertlv": True,
            "oui_update": False,
            "no_bpf_filters": True,
        },
        Context(),
    )

    assert mock_client.post.call_args.kwargs["json"] == {
        "noprep": True,
        "noprofilertlv": True,
        "oui_update": False,
        "no_bpf_filters": True,
    }


async def test_start_profiler_returns_core_failure_reason():
    from unittest.mock import AsyncMock, MagicMock

    from mcp.server.mcpserver import MCPServer

    from wlanpi_mcp.tools.profiler import register

    failure = {
        "success": False,
        "reason": "country_code_detection",
        "message": "No regulatory domain set",
    }
    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=failure)

    mcp = MCPServer("test")
    register(mcp, mock_client)

    tool = mcp._tool_manager._tools["start_profiler"]
    result = await tool.run({"interface": "wlan0"}, Context())

    assert result == failure
    # The tool description tells the client how to read the result.
    for word in ("success", "message", "already_running", "starting"):
        assert word in tool.description


async def test_purge_profiler_data_posts_to_purge():
    from unittest.mock import AsyncMock, MagicMock

    from mcp.server.mcpserver import MCPServer

    from wlanpi_mcp.tools.profiler import register

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"files": 12, "bytes": 48213})

    mcp = MCPServer("test")
    register(mcp, mock_client)

    result = await mcp._tool_manager._tools["purge_profiler_data"].run({}, Context())

    mock_client.post.assert_awaited_once_with("/api/v1/profiler/purge")
    assert result == {"files": 12, "bytes": 48213}


async def test_get_reachability_forwards_targets():
    from unittest.mock import AsyncMock, MagicMock

    from mcp.server.mcpserver import MCPServer

    from wlanpi_mcp.tools.utils import register

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={})

    mcp = MCPServer("test")
    register(mcp, mock_client)
    tool = mcp._tool_manager._tools["get_reachability"]

    await tool.run({"targets": ["8.8.8.8", "1.1.1.1"]}, Context())
    assert mock_client.get.call_args.kwargs["params"] == {
        "targets": ["8.8.8.8", "1.1.1.1"]
    }

    await tool.run({"namespace": "ns_a"}, Context())
    assert mock_client.get.call_args.kwargs["params"] == {"namespace": "ns_a"}

    await tool.run({"targets": ["8.8.8.8"], "namespace": "ns_a"}, Context())
    assert mock_client.get.call_args.kwargs["params"] == {
        "targets": ["8.8.8.8"],
        "namespace": "ns_a",
    }

    await tool.run({}, Context())
    assert mock_client.get.call_args.kwargs["params"] is None


REACHABILITY = "https://localhost:31415/api/v1/utils/reachability"


@pytest.fixture
def reachability_tool(client):
    from mcp.server.mcpserver import MCPServer

    from wlanpi_mcp.tools.utils import register

    mcp = MCPServer("test")
    register(mcp, client)
    return mcp._tool_manager._tools["get_reachability"]


@respx.mock
async def test_get_reachability_unknown_namespace_raises(reachability_tool):
    from mcp.server.mcpserver.exceptions import ToolError

    from wlanpi_mcp.client.core_client import CoreAPIError

    route = respx.get(REACHABILITY).mock(
        return_value=httpx.Response(400, json={"error": "unknown namespace: ns_x"})
    )
    with pytest.raises(ToolError) as exc:
        await reachability_tool.run({"namespace": "ns_x"}, Context())
    cause = exc.value.__cause__
    assert isinstance(cause, CoreAPIError)
    assert cause.status_code == 400
    assert "unknown namespace: ns_x" in str(exc.value)
    assert "namespace=ns_x" in str(route.calls.last.request.url)


@respx.mock
async def test_get_reachability_no_gateway_is_returned(reachability_tool):
    respx.get(REACHABILITY).mock(
        return_value=httpx.Response(503, json={"error": "No default gateway found"})
    )
    result = await reachability_tool.run({"namespace": "ns_a"}, Context())
    assert result == {"error": "No default gateway found", "namespace": "ns_a"}


@respx.mock
@pytest.mark.parametrize(
    ("args", "expected_ns"), [({}, "root"), ({"namespace": "ns_a"}, "ns_a")]
)
async def test_get_reachability_plain_text_no_gateway(
    reachability_tool, args, expected_ns
):
    respx.get(REACHABILITY).mock(
        return_value=httpx.Response(503, text="No default gateway")
    )
    result = await reachability_tool.run(args, Context())
    assert result == {"error": "No default gateway", "namespace": expected_ns}


@respx.mock
async def test_get_reachability_other_503_raises(reachability_tool):
    from mcp.server.mcpserver.exceptions import ToolError

    from wlanpi_mcp.client.core_client import CoreAPIError

    respx.get(REACHABILITY).mock(
        return_value=httpx.Response(503, json={"error": "Reachability check failed"})
    )
    with pytest.raises(ToolError) as exc:
        await reachability_tool.run({}, Context())
    cause = exc.value.__cause__
    assert isinstance(cause, CoreAPIError)
    assert cause.status_code == 503


# ── Bluetooth ─────────────────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_get_bluetooth_status(client):
    respx.get("https://localhost:31415/api/v1/bluetooth/status").mock(
        return_value=httpx.Response(
            200, json={"name": "WLAN Pi", "power": True, "paired_devices": []}
        )
    )
    result = await client.get("/api/v1/bluetooth/status")
    assert result["name"] == "WLAN Pi"


@respx.mock
@pytest.mark.asyncio
async def test_set_bluetooth_power_on(client):
    respx.post("https://localhost:31415/api/v1/bluetooth/power/on").mock(
        return_value=httpx.Response(200, json={"status": "success", "action": "on"})
    )
    result = await client.post("/api/v1/bluetooth/power/on")
    assert result["action"] == "on"


# ── Network Config ────────────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_list_network_configs(client):
    respx.get("https://localhost:31415/api/v1/network/config/").mock(
        return_value=httpx.Response(200, json={"office": True, "home": False})
    )
    result = await client.get("/api/v1/network/config/")
    assert "office" in result


@respx.mock
@pytest.mark.asyncio
async def test_activate_network_config(client):
    respx.post("https://localhost:31415/api/v1/network/config/activate/office").mock(
        return_value=httpx.Response(
            200,
            json={"id": "office", "message": "Configuration activated successfully"},
        )
    )
    result = await client.post("/api/v1/network/config/activate/office")
    assert result["id"] == "office"
