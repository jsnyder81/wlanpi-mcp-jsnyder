"""Assemble the WLAN Pi MCP server and register all tools, resources, and prompts."""

from collections.abc import Collection

from wlanpi_mcp._compat import FastMCP, TransportSecuritySettings
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.prompts import diagnostics
from wlanpi_mcp.resources import bluetooth as bt_res
from wlanpi_mcp.resources import device, services
from wlanpi_mcp.resources import mode as mode_res
from wlanpi_mcp.resources import netconfig as netconfig_res
from wlanpi_mcp.resources import network as net_res
from wlanpi_mcp.resources import profiler as profiler_res
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


def restrict_tools(mcp: FastMCP, allowed: Collection[str]) -> None:
    """
    Remove every registered tool not named in ``allowed``.

    Raises ValueError if ``allowed`` names a tool that does not exist, so a
    typo in a classroom allowlist fails at startup instead of silently
    hiding a tool the instructor meant to expose.
    """
    registered = {tool.name for tool in mcp._tool_manager.list_tools()}
    unknown = set(allowed) - registered
    if unknown:
        raise ValueError(f"tool allowlist names unknown tools: {sorted(unknown)}")
    for name in registered - set(allowed):
        mcp.remove_tool(name)


def create_server(
    client: CoreClient,
    host: str = "127.0.0.1",
    port: int = 8768,
    tools: Collection[str] | None = None,
) -> FastMCP:
    """
    Create a WLAN Pi MCP server with its tools, resources, and prompts registered.

    ``tools`` limits the exposed tools to those names (see
    ``Settings.enabled_tools``); None exposes every tool.
    """
    mcp = FastMCP(
        "WLAN Pi",
        instructions=(
            "WLAN Pi MCP server — exposes Wi-Fi network testing and analysis capabilities "
            "including device info, network interfaces, service management, Wi-Fi scanning, "
            "profiler control, and diagnostics."
        ),
        host=host,
        port=port,
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
        # client's real Host header (e.g. 10.254.102.51:8767). FastMCP would
        # otherwise auto-enable DNS rebinding protection for a loopback bind
        # and answer every /mcp request with 421 Misdirected Request. The
        # Bearer JWT gate in middleware/bearer_token.py is what protects the
        # transport: a rebinding page in a browser cannot attach that header.
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
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

    if tools is not None:
        restrict_tools(mcp, tools)

    return mcp
