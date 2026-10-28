"""Tests for the coverage-gap tools added against wlanpi-core 2.1.11."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from mcp.server.mcpserver import Context, MCPServer


def _register(module):
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={})
    mock_client.post = AsyncMock(return_value={})
    mcp = MCPServer("test")
    module.register(mcp, mock_client)
    return mcp._tool_manager._tools, mock_client


# ── System ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_restart_service_calls_api_for_allowed_service():
    from wlanpi_mcp.tools import system

    tools, mock_client = _register(system)
    await tools["restart_service"].fn(name="wlanpi-profiler")
    mock_client.post.assert_called_once_with(
        "/api/v1/system/service/restart", params={"name": "wlanpi-profiler"}
    )


@pytest.mark.asyncio
async def test_reboot_allowed_by_default(monkeypatch):
    from wlanpi_mcp.tools import system

    monkeypatch.delenv("ALLOW_POWER_CONTROL", raising=False)
    tools, mock_client = _register(system)
    await tools["reboot_device"].fn(ctx=Context())
    mock_client.post.assert_called_once_with("/api/v1/system/reboot")


@pytest.mark.asyncio
async def test_reboot_blocked_when_power_control_disabled(monkeypatch):
    from wlanpi_mcp.tools import system

    monkeypatch.setenv("ALLOW_POWER_CONTROL", "false")
    tools, mock_client = _register(system)
    result = await tools["reboot_device"].fn(ctx=Context())
    assert "error" in result
    mock_client.post.assert_not_called()


@pytest.mark.asyncio
async def test_shutdown_blocked_when_power_control_disabled(monkeypatch):
    from wlanpi_mcp.tools import system

    monkeypatch.setenv("ALLOW_POWER_CONTROL", "false")
    tools, mock_client = _register(system)
    result = await tools["shutdown_device"].fn(ctx=Context())
    assert "error" in result
    mock_client.post.assert_not_called()


@pytest.mark.asyncio
async def test_set_timezone_sends_body():
    from wlanpi_mcp.tools import system

    tools, mock_client = _register(system)
    await tools["set_timezone"].fn(timezone="America/Denver")
    mock_client.post.assert_called_once_with(
        "/api/v1/system/timezone/set", json={"timezone": "America/Denver"}
    )


@pytest.mark.asyncio
async def test_hotspot_clients_omits_iface_when_not_given():
    from wlanpi_mcp.tools import system

    tools, mock_client = _register(system)
    await tools["get_hotspot_clients"].fn()
    mock_client.get.assert_called_once_with(
        "/api/v1/system/hotspot/clients", params=None
    )


# ── Network diagnostics ──────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_get_routing_table(client):
    respx.get("https://localhost:31415/api/v1/network/routing").mock(
        return_value=httpx.Response(
            200, json={"routes": [{"dst": "default", "dev": "eth0"}]}
        )
    )
    result = await client.get("/api/v1/network/routing")
    assert "routes" in result


@respx.mock
@pytest.mark.asyncio
async def test_get_dhcp_leases(client):
    respx.get("https://localhost:31415/api/v1/network/dhcp/leases").mock(
        return_value=httpx.Response(200, json={"leases": []})
    )
    result = await client.get("/api/v1/network/dhcp/leases")
    assert "leases" in result


@pytest.mark.asyncio
async def test_routing_table_passes_namespace():
    from wlanpi_mcp.tools import network

    tools, mock_client = _register(network)
    await tools["get_routing_table"].fn(namespace="testns")
    mock_client.get.assert_called_once_with(
        "/api/v1/network/routing", params={"namespace": "testns"}
    )


@pytest.mark.asyncio
async def test_renew_dhcp_lease_uses_path_param():
    from wlanpi_mcp.tools import network

    tools, mock_client = _register(network)
    await tools["renew_dhcp_lease"].fn(interface="eth0")
    mock_client.post.assert_called_once_with("/api/v1/network/interfaces/eth0/renew")


# ── WiFi ─────────────────────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_get_wifi_capabilities(client):
    respx.get("https://localhost:31415/api/v1/wifi/capabilities").mock(
        return_value=httpx.Response(200, json={"phys": [{"phy": "phy0"}]})
    )
    result = await client.get("/api/v1/wifi/capabilities")
    assert "phys" in result


@pytest.mark.asyncio
async def test_hotspot_stations_passes_iface():
    from wlanpi_mcp.tools import wifi

    tools, mock_client = _register(wifi)
    await tools["get_hotspot_stations"].fn(iface="wlan0")
    mock_client.get.assert_called_once_with(
        "/api/v1/wifi/hotspot/stations", params={"iface": "wlan0"}
    )


# ── Utils ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_speedtest_uses_long_timeout():
    from wlanpi_mcp.tools import utils

    tools, mock_client = _register(utils)
    await tools["run_speedtest"].fn()
    mock_client.get.assert_called_once()
    assert mock_client.get.call_args.kwargs["timeout"] >= 120.0


@pytest.mark.asyncio
async def test_start_blinker_defaults_to_eth0():
    from wlanpi_mcp.tools import utils

    tools, mock_client = _register(utils)
    await tools["start_blinker"].fn()
    mock_client.post.assert_called_once_with(
        "/api/v1/utils/blinker/start", params={"interface": "eth0"}
    )


# ── Bluetooth ────────────────────────────────────────────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_start_bluetooth_pairing(client):
    respx.post("https://localhost:31415/api/v1/bluetooth/pair").mock(
        return_value=httpx.Response(200, json={"status": "pairing"})
    )
    result = await client.post("/api/v1/bluetooth/pair")
    assert result["status"] == "pairing"
