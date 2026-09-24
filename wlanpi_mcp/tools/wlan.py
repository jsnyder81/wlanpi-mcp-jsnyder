"""MCP tools for WLAN scanning."""

from typing import Any, Literal

from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import hints


def register(mcp: FastMCP, client: CoreClient) -> None:
    """Register the WLAN scan tool."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def scan_wlan(
        interface: str | None = None,
        namespace: str | None = None,
        include_hidden: bool = True,
        detail: Literal["short", "full"] = "short",
    ) -> dict[str, Any]:
        """
        Scan for Wi-Fi networks.

        Namespace-aware, with automatic monitor adapter selection. If multiple
        monitor adapters exist and no interface is given, returns
        'needsSelection' with candidates instead of scanning — call again with
        one of the candidate interfaces.

        Errors: 409 with error SCAN_IN_PROGRESS (that adapter is already
        scanning; retry shortly) or MONITOR_IN_USE (a capture holds a monitor
        on the same Intel radio; the capture must stop first). 422 with
        NO_SCAN_ADAPTER: no suitable adapter. 503: scan command unavailable.

        To connect to a network found by this scan, create and activate a network
        configuration (create_network_config / activate_network_config).

        Args:
            interface: WLAN interface to scan with (e.g. 'wlan0'); auto-selected if omitted
            namespace: Optional network namespace the interface lives in
            include_hidden: Include hidden SSIDs in results
            detail: 'short' for list-friendly fields plus RF extensions; 'full'
                also adds each BSS's raw 'iw scan' dump (much larger)
        """
        params: dict[str, Any] = {"hidden": include_hidden, "detail": detail}
        if interface:
            params["iface"] = interface
        if namespace:
            params["namespace"] = namespace
        return await client.get("/api/v1/utils/wlan/scan", params=params)
