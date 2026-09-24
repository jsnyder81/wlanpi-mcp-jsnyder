"""MCP tools for WLAN Pi utilities: reachability, speedtest, UFW, and blinker."""

from typing import Any

from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import hints


def register(mcp: FastMCP, client: CoreClient) -> None:
    """Register the utility tools."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_reachability(targets: list[str] | None = None) -> dict[str, Any]:
        """
        Test WLAN Pi network reachability.

        Pings the default gateway, checks DNS resolution, and verifies internet
        access. Use this to diagnose connectivity problems.

        Args:
            targets: Optional extra hostnames or IPs to ping as well
                (e.g. ['8.8.8.8', 'intranet.example.com'])
        """
        params = {"targets": targets} if targets else None
        return await client.get("/api/v1/utils/reachability", params=params)

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_usb_interfaces() -> dict[str, Any]:
        """List USB network adapters currently plugged into the WLAN Pi."""
        return await client.get("/api/v1/utils/usb")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_ufw_status() -> dict[str, Any]:
        """Get the current UFW firewall status and active rules on the WLAN Pi."""
        return await client.get("/api/v1/utils/ufw")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def run_speedtest() -> dict[str, Any]:
        """
        Run an internet speed test from the WLAN Pi.

        Uses LibreSpeed CLI; slow, typically taking 30-90 seconds to complete.
        Returns download/upload speed, ping, IP address, and the test server
        used.
        """
        return await client.get("/api/v1/utils/speedtest", timeout=180.0)

    @mcp.tool(annotations=hints.ADDITIVE)
    async def start_blinker(interface: str = "eth0") -> dict[str, Any]:
        """
        Start the Ethernet port blinker.

        This is a cable finder: it flashes the port LED so the cable can be
        located at the switch end.

        Args:
            interface: Ethernet interface to blink (default 'eth0')
        """
        return await client.post(
            "/api/v1/utils/blinker/start", params={"interface": interface}
        )

    @mcp.tool(annotations=hints.ADDITIVE)
    async def stop_blinker() -> dict[str, Any]:
        """Stop the Ethernet port blinker."""
        return await client.post("/api/v1/utils/blinker/stop")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_blinker_status() -> dict[str, Any]:
        """Check whether the Ethernet port blinker is currently running."""
        return await client.get("/api/v1/utils/blinker/status")
