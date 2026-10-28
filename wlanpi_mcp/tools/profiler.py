"""MCP tools for controlling the wlanpi-profiler."""

from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp_types import InputRequiredResult

from wlanpi_mcp import elicit
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import hints


def register(mcp: MCPServer, client: CoreClient) -> None:
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

        Core waits (up to about 25 s) for the profiler to run or fail, then
        returns {"success": bool, "reason": str | null, "message": str | null}.

        success false means the profiler did NOT start - do not report it as
        started. Show the user 'message', which says why. 'reason' is one of:
            - the profiler's own exit reason when it exited during startup,
              e.g. 'country_code_detection' (no regulatory domain set) or
              'interface_validation' (unknown interface)
            - 'exited': it exited during startup without giving a reason
            - 'already_running': a profiler started by core is still running;
              stop it (stop_profiler) first if new settings are wanted
            - 'spawn_failed': the profiler could not be launched

        success true with reason 'starting' means it was still starting when
        the wait ended. In AP mode, poll get_profiler_status until 'running'
        is true before telling the user clients can connect.
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
        """
        Stop the wlanpi-profiler.

        Returns {"success": bool}. success false means no profiler started by
        wlanpi-core was running (nothing to stop), not that stopping failed.
        This returns no client data: call get_profiler_reports for the
        profiles the run captured.
        """
        return await client.post("/api/v1/profiler/stop")

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def purge_profiler_data(
        ctx: Context,
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Delete every profiler client profile, capture and session report.

        This cannot be undone. Always confirm with the user first, and only
        call it when they asked to clear the profiler's saved data - never as
        cleanup after a profiling run. When the client supports elicitation,
        the user is asked to confirm directly; a 'not_performed' status means
        they declined - do not retry.

        Returns {"files": N, "bytes": N}: how many files and symlinks were
        removed and their total size.

        Errors: 409 while the profiler is starting, running or stopping - stop
        it (stop_profiler) and wait for get_profiler_status to show it stopped,
        then retry.
        """

        async def message() -> str:
            name = await elicit.device_name(client)
            return (
                f"Delete every saved profiler client profile, capture and "
                f"report on {name}? This cannot be undone."
            )

        stop = await elicit.confirm(
            ctx, "purge", message, "delete the profiler's saved data"
        )
        if stop is not None:
            return stop
        return await client.post("/api/v1/profiler/purge")
