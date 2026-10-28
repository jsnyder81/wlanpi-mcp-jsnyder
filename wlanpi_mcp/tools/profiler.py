"""MCP tools for controlling the wlanpi-profiler."""

import asyncio
import logging
import time
from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp_types import InputRequiredResult

from wlanpi_mcp import elicit, tasks
from wlanpi_mcp.client.core_client import (
    CoreAPIError,
    CoreBadResponseError,
    CoreClient,
    CoreUnavailableError,
)
from wlanpi_mcp.tools import hints
from wlanpi_mcp.tools.profiler_reports import build_reports, clients_since

log = logging.getLogger(__name__)

#: How often profile_clients checks the profiler's results, in seconds.
PROFILE_POLL_S = 5.0

#: The longest profile_clients run, in minutes, before it must be extended.
MAX_PROFILE_MINUTES = 120

#: How long a profiler that core reported as still 'starting' may take to
#: show running before profile_clients treats it as having exited, in seconds.
STARTUP_GRACE_S = 60

#: How long profile_clients waits for an answer to "Keep going?", in seconds,
#: before stopping as if the user said no.
ANSWER_TIMEOUT_S = 300.0


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

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def profile_clients(
        ctx: Context,
        until_clients: int = 1,
        max_minutes: float = 10,
        output: Literal["json", "links", "zip"] = "json",
        interface: str | None = None,
        channel: int | None = None,
        frequency: int | None = None,
        ssid: str | None = None,
        no11r: bool | None = None,
        no11ax: bool | None = None,
        no11be: bool | None = None,
        wpa3_personal: bool | None = None,
        wpa3_personal_transition: bool | None = None,
        ask_to_extend: bool = True,
    ) -> dict[str, Any]:
        """
        Profile Wi-Fi clients until enough have been seen, then return their profiles.

        Runs as an MCP Task (the client must support MCP Tasks): starts the
        profiler, reports how many clients have been profiled so far, and
        finishes when until_clients clients have been profiled or max_minutes
        pass. It then stops the profiler and returns the get_profiler_reports
        result for the clients profiled during this run only, plus a 'run'
        summary (clients profiled, target, elapsed_s, stopped_because:
        target_reached | time_limit | profiler_exited). Cancelling the task
        stops the profiler.

        Tell the user to connect their devices to the profiler's SSID while
        it runs; the progress message names the SSID but not the passphrase
        (get_profiler_status has it). At the time limit, a client that can
        show elicitation forms is asked whether to keep going (no answer
        within 5 minutes is a no); other clients just stop there. Without
        task support this returns an error: use start_profiler, poll
        get_profiler_reports, then stop_profiler.

        Args:
            until_clients: Stop once this many clients have been profiled (>= 1)
            max_minutes: Stop after this long even with fewer clients (max 120)
            output: How to return the profiles, as in get_profiler_reports
            interface: WLAN interface for the profiler's AP (e.g. 'wlan0')
            channel: 802.11 channel for the AP
            frequency: Frequency in MHz (alternative to channel)
            ssid: SSID for the profiler's AP
            no11r: Disable 802.11r
            no11ax: Disable 802.11ax
            no11be: Disable 802.11be
            wpa3_personal: WPA3-Personal only
            wpa3_personal_transition: WPA3-Personal transition mode
            ask_to_extend: When max_minutes pass with fewer clients, ask the
                user whether to keep going instead of stopping (only where
                the client supports elicitation)
        """
        if not tasks.in_task():
            return {
                "error": (
                    "profile_clients runs as an MCP Task and this client did "
                    "not declare task support. Use start_profiler, poll "
                    "get_profiler_reports, then stop_profiler instead."
                )
            }
        if until_clients < 1:
            return {"error": "until_clients must be 1 or more"}
        if not 0 < max_minutes <= MAX_PROFILE_MINUTES:
            return {
                "error": f"max_minutes must be over 0 and at most {MAX_PROFILE_MINUTES}"
            }

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
        }
        # Ask "Keep going?" only where the client can show the question; a
        # task parked on a question nobody sees would hold the radio.
        can_ask = ask_to_extend and elicit.can_form(ctx)
        # This server runs on the device, so its clock is the one core stamps
        # the profile files with. Taken before the start call: core can take
        # ~25 s to bring the AP up, and clients profiled meanwhile count.
        started = time.time()
        profiled: list[str] = []
        deadline = started + max_minutes * 60
        stopped_because = "time_limit"
        seen_running = False
        ap_ssid: str | None = None

        def progress() -> str:
            minutes, seconds = divmod(int(time.time() - started), 60)
            # The SSID only: status messages reach the model and the client's
            # logs, so the passphrase stays in get_profiler_status.
            joined = f"; profiler SSID '{ap_ssid}'" if ap_ssid else ""
            return (
                f"{len(profiled)} of {until_clients} clients profiled, "
                f"{minutes}m{seconds:02d}s elapsed{joined}"
            )

        async def poll(path: str, fallback: Any) -> Any:
            # One failed poll (a core restart, a timeout) does not end the
            # run: keep the last answer and let the deadline decide.
            try:
                if path == "files":
                    return await clients_since(client, started)
                return await client.get(path)
            except (CoreAPIError, CoreUnavailableError, CoreBadResponseError) as exc:
                log.warning("profile_clients poll failed: %r", exc)
                return fallback

        # Claimed before the start call: a cancel landing while core is still
        # starting the profiler must still stop whatever core goes on to run.
        owned = True
        try:
            async with tasks.reporting(progress):
                start = await client.post(
                    "/api/v1/profiler/start",
                    json={k: v for k, v in args.items() if v is not None},
                )
                if not start.get("success"):
                    # Includes 'already_running': that profiler is not ours.
                    owned = False
                    return {"error": "the profiler did not start", "start": start}
                while True:
                    profiled = await poll("files", profiled)
                    if len(profiled) >= until_clients:
                        stopped_because = "target_reached"
                        break
                    status = await poll("/api/v1/profiler/status", None)
                    if status is not None and status.get("running"):
                        seen_running = True
                        ap_ssid = status.get("ssid") or ap_ssid
                    elif status is not None and (
                        seen_running or time.time() > started + STARTUP_GRACE_S
                    ):
                        stopped_because = "profiler_exited"
                        break
                    if time.time() >= deadline:
                        if not can_ask or not await _keep_going(
                            len(profiled), until_clients, max_minutes
                        ):
                            break
                        deadline = time.time() + max_minutes * 60
                    await asyncio.sleep(PROFILE_POLL_S)
        finally:
            # Also on cancel: never leave the profiler running for a task
            # that no longer exists.
            if owned:
                try:
                    await client.post("/api/v1/profiler/stop")
                except Exception as exc:  # noqa: BLE001 - the outcome matters more
                    log.warning("stopping the profiler after profile_clients: %r", exc)

        result = await build_reports(
            client, output=output, max_clients=0, since=started
        )
        result["run"] = {
            "clients_profiled": len(profiled),
            "target": until_clients,
            "elapsed_s": int(time.time() - started),
            "stopped_because": stopped_because,
        }
        return result


async def _keep_going(profiled: int, target: int, minutes: float) -> bool:
    """Ask the user mid-task whether to profile for another ``minutes``.

    No answer within ANSWER_TIMEOUT_S counts as no: the profiler holds a
    radio while the question waits.
    """
    try:
        reply = await tasks.request_input(
            elicit.form_request(
                f"Only {profiled} of {target} clients profiled so far. Keep the "
                f"profiler running for another {minutes:g} minutes?"
            ),
            label="extend",
            timeout_s=ANSWER_TIMEOUT_S,
        )
    except TimeoutError:
        log.info("profile_clients: no answer to 'keep going', stopping")
        return False
    return reply.get("action") == "accept"
