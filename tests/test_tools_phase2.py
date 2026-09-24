import httpx
import pytest
import respx

# ── WLAN ─────────────────────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_scan_wlan_uses_canonical_endpoint():
    from unittest.mock import AsyncMock, MagicMock

    from wlanpi_mcp._compat import FastMCP
    from wlanpi_mcp.tools.wlan import register

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"nets": []})

    mcp = FastMCP("test")
    register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["scan_wlan"].fn
    await tool_fn(interface="wlan0", detail="full")

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

    from wlanpi_mcp._compat import FastMCP
    from wlanpi_mcp.tools.wlan import register

    mcp = FastMCP("test")
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

    from wlanpi_mcp._compat import FastMCP
    from wlanpi_mcp.tools.profiler import register

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"success": True})

    mcp = FastMCP("test")
    register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["start_profiler"].fn
    await tool_fn(interface="wlan0", channel=6)

    body = mock_client.post.call_args.kwargs["json"]
    assert body["interface"] == "wlan0"
    assert body["channel"] == 6
    assert "frequency" not in body  # omitted None fields


async def test_start_profiler_forwards_newer_flags():
    from unittest.mock import AsyncMock, MagicMock

    from wlanpi_mcp._compat import FastMCP
    from wlanpi_mcp.tools.profiler import register

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"success": True})

    mcp = FastMCP("test")
    register(mcp, mock_client)

    await mcp._tool_manager._tools["start_profiler"].run(
        {
            "noprep": True,
            "noprofilertlv": True,
            "oui_update": False,
            "no_bpf_filters": True,
        }
    )

    assert mock_client.post.call_args.kwargs["json"] == {
        "noprep": True,
        "noprofilertlv": True,
        "oui_update": False,
        "no_bpf_filters": True,
    }


async def test_get_reachability_forwards_targets():
    from unittest.mock import AsyncMock, MagicMock

    from wlanpi_mcp._compat import FastMCP
    from wlanpi_mcp.tools.utils import register

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={})

    mcp = FastMCP("test")
    register(mcp, mock_client)
    tool = mcp._tool_manager._tools["get_reachability"]

    await tool.run({"targets": ["8.8.8.8", "1.1.1.1"]})
    assert mock_client.get.call_args.kwargs["params"] == {
        "targets": ["8.8.8.8", "1.1.1.1"]
    }

    await tool.run({})
    assert mock_client.get.call_args.kwargs["params"] is None


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
