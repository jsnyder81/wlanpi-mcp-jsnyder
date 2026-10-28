"""Assemble the WLAN Pi MCP server and register all tools, resources, and prompts."""

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from wlanpi_mcp import elicit
from wlanpi_mcp.__version__ import __version__
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.prompts import diagnostics
from wlanpi_mcp.resources import bluetooth as bt_res
from wlanpi_mcp.resources import device, services
from wlanpi_mcp.resources import mode as mode_res
from wlanpi_mcp.resources import netconfig as netconfig_res
from wlanpi_mcp.resources import network as net_res
from wlanpi_mcp.resources import profiler as profiler_res
from wlanpi_mcp.tasks import Tasks
from wlanpi_mcp.tools import (
    advanced,
    bluetooth,
    capture,
    capture_file,
    netconfig,
    network,
    profiler,
    profiler_reports,
    system,
    utils,
    vlan,
    wifi,
    wlan,
)

#: Tools that run as an MCP Task (wlanpi_mcp/tasks.py) when the client
#: declares the tasks extension: the ones that block for long enough to trip a
#: client's per-request timer, or that run until a condition is met. Without
#: the extension they run synchronously as before.
TASK_TOOLS = frozenset(
    {
        "start_pcap_file",
        "capture_scan",
        "capture_observe",
        "run_speedtest",
        "profile_clients",
    }
)


def create_server(client: CoreClient) -> MCPServer:
    """Create a WLAN Pi MCP server with all tools, resources, and prompts registered."""
    mcp = MCPServer(
        "WLAN Pi",
        instructions=(
            "WLAN Pi MCP server — exposes Wi-Fi network testing and analysis capabilities "
            "including device info, network interfaces, service management, Wi-Fi scanning, "
            "profiler control, and diagnostics."
        ),
        version=__version__,
        # Seals the multi-round-trip state elicitation confirms carry,
        # bound to the caller's JWT (wlanpi_mcp/elicit.py).
        request_state_security=elicit.request_state_security(),
        extensions=[Tasks(TASK_TOOLS)],
    )

    # Phase 1 — system, network, utils
    system.register(mcp, client)
    network.register(mcp, client)
    utils.register(mcp, client)

    # Phase 2 — WLAN, VLAN, profiler, Bluetooth, network configs
    wlan.register(mcp, client)
    vlan.register(mcp, client)
    profiler.register(mcp, client)
    # Reads the profiler's files directly until core serves them (#58)
    profiler_reports.register(mcp, client)
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


def create_http_app(mcp: MCPServer) -> Starlette:
    """Build the streamable HTTP ASGI app with the daemon's transport settings."""
    return mcp.streamable_http_app(
        # Streamable HTTP, stateless, on /mcp. Stateless means every POST is a
        # complete exchange with no server-side session: a client that
        # reconnects after a daemon restart or an idle gap cannot strand
        # itself on a stale session (the legacy SSE transport did exactly
        # that with Claude Code, every tool call failing with -32602 until
        # the client was restarted). Nothing here needs server-initiated
        # messages, so nothing is lost. json_response returns each result as
        # a plain JSON body instead of an SSE-wrapped stream, which keeps the
        # nginx front and curl debugging simple.
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        # The daemon binds loopback-only behind nginx, which forwards the
        # client's real Host header (e.g. 10.254.102.51:8767). MCPServer would
        # otherwise auto-enable DNS rebinding protection for a loopback bind
        # and answer every /mcp request with 421 Misdirected Request. The
        # Bearer JWT gate in middleware/bearer_token.py is what protects the
        # transport: a rebinding page in a browser cannot attach that header.
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
    )
