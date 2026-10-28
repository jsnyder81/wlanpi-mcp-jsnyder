"""Tests for the coverage-gap tools added against wlanpi-core 2.1.11."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from mcp.server.mcpserver import Context, MCPServer

from tests.test_capture_tools import _task_ctx


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


# ── run_speedtest as an MCP Task (#91) ───────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_task_store():
    from wlanpi_mcp import tasks

    tasks.TASKS.clear()
    yield
    tasks.TASKS.clear()


def _parking_get():
    """Return a client.get stand-in, its start event and its release event."""
    started = asyncio.Event()
    release = asyncio.Event()

    async def get(path, **kwargs):
        started.set()
        await release.wait()
        return {"download_mbps": 100.0}

    return get, started, release


async def test_run_speedtest_as_task_completes_with_the_core_result():
    from wlanpi_mcp import tasks
    from wlanpi_mcp.tools import utils

    tools, mock_client = _register(utils)
    mock_client.get = AsyncMock(return_value={"download_mbps": 100.0})
    result = await tools["run_speedtest"].run({}, _task_ctx(capable=True))

    assert isinstance(result, tasks.TaskCallResult)
    assert result.result_type == "task"
    assert result.structured_content == {"status": "running"}
    record = tasks.TASKS.get(result.task_id)
    await asyncio.wait_for(record.work, timeout=5)
    assert record.status == "completed"
    assert record.result == {"download_mbps": 100.0}
    mock_client.get.assert_called_once_with("/api/v1/utils/speedtest", timeout=180.0)


async def test_run_speedtest_task_failure_publishes_an_error_result():
    from wlanpi_mcp import tasks
    from wlanpi_mcp.tools import utils

    tools, mock_client = _register(utils)
    mock_client.get = AsyncMock(side_effect=RuntimeError("core is down"))
    result = await tools["run_speedtest"].run({}, _task_ctx(capable=True))
    record = tasks.TASKS.get(result.task_id)
    await asyncio.wait_for(record.work, timeout=5)

    assert record.status == "failed"
    assert "core is down" in record.result["error"]


async def test_run_speedtest_task_progress_reports_elapsed_time():
    from wlanpi_mcp import tasks
    from wlanpi_mcp.tools import utils

    tools, mock_client = _register(utils)
    mock_client.get, started, _release = _parking_get()
    result = await tools["run_speedtest"].run({}, _task_ctx(capable=True))
    record = tasks.TASKS.get(result.task_id)
    await asyncio.wait_for(started.wait(), timeout=5)

    # The LibreSpeed phases live inside wlanpi-core; elapsed time is all this
    # side can observe, so that is what the statusMessage carries.
    assert tasks.wire(record)["statusMessage"].startswith("speedtest running for ")

    await tasks.TASKS.cancel(record)
    assert record.status == "cancelled"


async def test_run_speedtest_task_cancel_abandons_the_wait():
    from wlanpi_mcp import tasks
    from wlanpi_mcp.tools import utils

    tools, mock_client = _register(utils)
    mock_client.get, started, _release = _parking_get()
    result = await tools["run_speedtest"].run({}, _task_ctx(capable=True))
    record = tasks.TASKS.get(result.task_id)
    await asyncio.wait_for(started.wait(), timeout=5)

    await tasks.TASKS.cancel(record)
    # No cancel endpoint exists on core: the wait is abandoned at the
    # asyncio-task level and the record goes terminal cancelled, with no
    # result to report (tasks/get omits the key, as for any #90 cancel).
    assert record.status == "cancelled"
    assert record.result is None


async def test_run_speedtest_task_cancel_after_completion_keeps_completed():
    from wlanpi_mcp import tasks
    from wlanpi_mcp.tools import utils

    tools, mock_client = _register(utils)
    mock_client.get = AsyncMock(return_value={"download_mbps": 100.0})
    result = await tools["run_speedtest"].run({}, _task_ctx(capable=True))
    record = tasks.TASKS.get(result.task_id)
    await asyncio.wait_for(record.work, timeout=5)

    await tasks.TASKS.cancel(record)
    # The work was not cut short: the completed outcome stands.
    assert record.status == "completed"
    assert record.result == {"download_mbps": 100.0}


async def test_run_speedtest_without_task_support_is_unchanged():
    from wlanpi_mcp import tasks
    from wlanpi_mcp.tools import utils

    tools, mock_client = _register(utils)
    result = await tools["run_speedtest"].run({}, _task_ctx(capable=False))

    assert isinstance(result, dict)
    mock_client.get.assert_called_once_with("/api/v1/utils/speedtest", timeout=180.0)
    assert len(tasks.TASKS) == 0
