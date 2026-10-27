from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context, MCPServer

# ── Advanced (mode, regulatory, battery) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_get_device_mode_uses_api():
    from wlanpi_mcp.tools import advanced

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"mode": "hotspot", "model": "R4"})
    mcp = MCPServer("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_device_mode"].fn
    result = await tool_fn()

    mock_client.get.assert_awaited_once_with("/api/v1/system/device/info")
    assert result["mode"] == "hotspot"
    assert result["valid"] is True


@pytest.mark.asyncio
async def test_get_device_mode_flags_unknown_mode():
    from wlanpi_mcp.tools import advanced

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"mode": "bogus"})
    mcp = MCPServer("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_device_mode"].fn
    result = await tool_fn()

    assert result["mode"] == "bogus"
    assert result["valid"] is False


@pytest.mark.asyncio
async def test_get_battery_status_uses_api():
    from wlanpi_mcp.tools import advanced

    mock_client = MagicMock()
    mock_client.get = AsyncMock(
        return_value={"present": True, "capacity_percent": 78, "status": "Discharging"}
    )
    mcp = MCPServer("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_battery_status"].fn
    result = await tool_fn()

    mock_client.get.assert_awaited_once_with("/api/v1/system/battery")
    assert result["present"] is True
    assert result["capacity_percent"] == 78


@pytest.mark.asyncio
async def test_get_regulatory_domain_uses_api():
    from wlanpi_mcp.tools import advanced

    mock_client = MagicMock()
    mock_client.get = AsyncMock(
        return_value={"country": "US", "raw": "country US: DFS-FCC"}
    )
    mcp = MCPServer("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_regulatory_domain"].fn
    result = await tool_fn()

    mock_client.get.assert_awaited_once_with("/api/v1/system/reg-domain")
    assert result["country"] == "US"


@pytest.mark.asyncio
async def test_set_regulatory_domain_validates_code():
    from wlanpi_mcp.tools import advanced

    mock_client = MagicMock()
    mcp = MCPServer("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["set_regulatory_domain"].fn
    result = await tool_fn(country_code="USA", ctx=Context())  # invalid, 3 letters
    assert "error" in result


@pytest.mark.asyncio
async def test_set_regulatory_domain_accepts_valid_code():
    from wlanpi_mcp.tools import advanced

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"country": "US"})
    mcp = MCPServer("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["set_regulatory_domain"].fn
    result = await tool_fn(country_code="us", ctx=Context())

    mock_client.post.assert_awaited_once_with(
        "/api/v1/system/reg-domain/set", json={"country": "US"}
    )
    assert result["country"] == "US"
