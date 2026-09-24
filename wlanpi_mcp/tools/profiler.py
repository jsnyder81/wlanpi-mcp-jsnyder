"""MCP tools for controlling the wlanpi-profiler."""

from typing import Any

from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import hints


def register(mcp: FastMCP, client: CoreClient) -> None:
    """Register the profiler control tools."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_profiler_status() -> dict[str, Any]:
        """
        Get the current status of the wlanpi-profiler.

        Returns whether the profiler is running, its SSID, channel, and
        interface.
        """
        return await client.get("/api/v1/profiler/status")

    @mcp.tool(annotations=hints.DESTRUCTIVE)
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
        noprep: bool | None = None,
        noprofilertlv: bool | None = None,
        oui_update: bool | None = None,
        no_bpf_filters: bool | None = None,
        debug: bool | None = None,
    ) -> dict[str, Any]:
        """
        Start the wlanpi-profiler to capture 802.11 client capability information.

        The profiler brings up a fake AP and captures association frames from clients
        to determine their 802.11 capabilities (PHY support, spatial streams, etc.).

        Args:
            interface: WLAN interface to use (e.g. 'wlan0')
            channel: 802.11 channel number to operate on (1-233)
            frequency: Frequency in MHz (alternative to channel)
            ssid: SSID for the fake AP (default chosen by profiler)
            no11r: Disable 802.11r (Fast BSS Transition) support
            no11ax: Disable 802.11ax (Wi-Fi 6) support
            no11be: Disable 802.11be (Wi-Fi 7) support
            wpa3_personal: Enable WPA3-Personal only mode
            wpa3_personal_transition: Enable WPA3-Personal Transition mode
            noAP: Run without bringing up an AP (passive capture only)
            noprep: Skip interface preparation (use when the interface is
                already set up in monitor mode on the right channel)
            noprofilertlv: Don't add the profiler's vendor TLVs to beacons
            oui_update: Update the OUI (manufacturer) database from the
                Internet before starting; needs Internet access
            no_bpf_filters: Remove the sniffer's BPF filters (sees more
                frames, but may reduce profiler performance)
            debug: Enable debug logging in profiler
        """
        args = {
            "interface": interface,
            "channel": channel,
            "frequency": frequency,
            "ssid": ssid,
            "no11r": no11r,
            "no11ax": no11ax,
            "no11be": no11be,
            "wpa3_personal": wpa3_personal,
            "wpa3_personal_transition": wpa3_personal_transition,
            "noAP": noAP,
            "noprep": noprep,
            "noprofilertlv": noprofilertlv,
            "oui_update": oui_update,
            "no_bpf_filters": no_bpf_filters,
            "debug": debug,
        }
        body = {k: v for k, v in args.items() if v is not None}

        return await client.post("/api/v1/profiler/start", json=body)

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def stop_profiler() -> dict[str, Any]:
        """Stop the wlanpi-profiler and return summary results."""
        return await client.post("/api/v1/profiler/stop")
