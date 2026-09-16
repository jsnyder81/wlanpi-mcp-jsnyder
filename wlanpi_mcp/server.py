from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.prompts import diagnostics
from wlanpi_mcp.resources import (
    bluetooth as bt_res,
    device,
    mode as mode_res,
    netconfig as netconfig_res,
    network as net_res,
    profiler as profiler_res,
    services,
)
from wlanpi_mcp.tools import (
    advanced,
    bluetooth,
    capture,
    capture_file,
    netconfig,
    network,
    profiler,
    system,
    utils,
    vlan,
    wifi,
    wlan,
)


def create_server(
    client: CoreClient, host: str = "127.0.0.1", port: int = 8766
) -> FastMCP:
    mcp = FastMCP(
        "WLAN Pi",
        instructions=(
            "WLAN Pi MCP server — exposes Wi-Fi network testing and analysis capabilities "
            "including device info, network interfaces, service management, Wi-Fi scanning, "
            "profiler control, and diagnostics."
        ),
        host=host,
        port=port,
    )

    # Phase 1 — system, network, utils
    system.register(mcp, client)
    network.register(mcp, client)
    utils.register(mcp, client)

    # Phase 2 — WLAN, VLAN, profiler, Bluetooth, network configs
    wlan.register(mcp, client)
    vlan.register(mcp, client)
    profiler.register(mcp, client)
    bluetooth.register(mcp, client)
    netconfig.register(mcp, client)
    wifi.register(mcp, client)

    # Phase 3 — regulatory domain, mode, battery
    advanced.register(mcp, client)

    # Packet capture — wlanpi-core's streaming WebSocket, not REST
    capture.register(mcp, client)
    # File-backed capture: background pcapng to /tmp, fetched as a blob
    capture_file.register(mcp, client)

    # Resources — Phase 1
    device.register(mcp, client)
    net_res.register(mcp, client)
    services.register(mcp, client)

    # Resources — Phase 2
    bt_res.register(mcp, client)
    profiler_res.register(mcp, client)
    netconfig_res.register(mcp, client)

    # Resources — Phase 3
    mode_res.register(mcp, client)

    # Prompts
    diagnostics.register(mcp)

    return mcp
