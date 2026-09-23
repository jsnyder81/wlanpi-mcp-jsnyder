"""MCP tools for controlling the wlanpi-profiler."""

from typing import Any

from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:
    """Register the profiler control tools."""

    @mcp.tool()
    async def get_profiler_status() -> dict[str, Any]:
        """
        Get the current status of the wlanpi-profiler.

        Returns whether the profiler is running, its SSID, channel, and
        interface.
        """
        return await client.get("/api/v1/profiler/status")

    @mcp.tool()
    async def start_profiler(
        interface: str | None = None,
        channel: int | None = None,
        frequency: int | None = None,
        ssid: str | None = None,
        no11r: bool | None = None,
        no11ax: bool | None = None,
        no11be: bool | None = None,
        wpa3_personal: bool | None = None,
        wpa3_personal_transition: bool | None = None,
        noAP: bool | None = None,
        debug: bool | None = None,
    ) -> dict[str, Any]:
        """
        Start the wlanpi-profiler to capture 802.11 client capability information.

        The profiler brings up a fake AP and captures association frames from clients
        to determine their 802.11 capabilities (PHY support, spatial streams, etc.).

        Args:
            interface: Optional WLAN interface to use. Omit it to let the
                profiler use its own configured interface (the interface
                setting in its config.ini, normally 'wlan0'). Pass one only
                to pick a specific adapter; get_network_interfaces lists them.
            channel: 802.11 channel number to operate on
            frequency: Frequency in MHz (alternative to channel)
            ssid: SSID for the fake AP (default chosen by profiler)
            no11r: Disable 802.11r (Fast BSS Transition) support
            no11ax: Disable 802.11ax (Wi-Fi 6) support
            no11be: Disable 802.11be (Wi-Fi 7) support
            wpa3_personal: Enable WPA3-Personal only mode
            wpa3_personal_transition: Enable WPA3-Personal Transition mode
            noAP: Run without bringing up an AP (passive capture only)
            debug: Enable debug logging in profiler
        """
        body: dict[str, Any] = {}
        if interface is not None:
            body["interface"] = interface
        if channel is not None:
            body["channel"] = channel
        if frequency is not None:
            body["frequency"] = frequency
        if ssid is not None:
            body["ssid"] = ssid
        if no11r is not None:
            body["no11r"] = no11r
        if no11ax is not None:
            body["no11ax"] = no11ax
        if no11be is not None:
            body["no11be"] = no11be
        if wpa3_personal is not None:
            body["wpa3_personal"] = wpa3_personal
        if wpa3_personal_transition is not None:
            body["wpa3_personal_transition"] = wpa3_personal_transition
        if noAP is not None:
            body["noAP"] = noAP
        if debug is not None:
            body["debug"] = debug

        return await client.post("/api/v1/profiler/start", json=body)

    @mcp.tool()
    async def stop_profiler() -> dict[str, Any]:
        """Stop the wlanpi-profiler and return summary results."""
        return await client.post("/api/v1/profiler/stop")
