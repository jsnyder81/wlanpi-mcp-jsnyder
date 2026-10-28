"""MCP tools for controlling the wlanpi-profiler."""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import InputRequiredResult

from wlanpi_mcp import tasks
from wlanpi_mcp.client.core_client import (
    CoreAPIError,
    CoreBadResponseError,
    CoreClient,
    CoreUnavailableError,
)
from wlanpi_mcp.tools import confirms, hints, profiler_reports

log = logging.getLogger(__name__)

#: Seconds between client-count polls while a profile_clients task runs.
CLIENT_POLL_S = 2.0

#: How long a profile_clients task waits for the answer to its "Keep
#: going?" question before treating no answer as a decline: the parked
#: profiler holds a radio, so the wait cannot be open-ended.
ANSWER_TIMEOUT_S = 300.0


@dataclass
class _ProfileRun:
    """One profiler session, run as the body of an MCP task (issue #92).

    Starts the profiler through core, polls the client count out of core's
    profiler files manifest (the same listing get_profiler_reports reads;
    core's status endpoint carries no count), and stops it through the
    existing stop path when the end condition lands. ``teardown`` is the
    spawn hook that keeps that promise even when a cancel publishes the
    outcome first, so the radio is never left taken by an unowned run.
    """

    client: CoreClient
    start_body: dict[str, Any]
    until_clients: int
    window_s: float
    output: str
    can_ask: bool
    record: tasks.TaskRecord | None = None
    started_at: float = 0.0
    count: int = 0
    deadline: float = 0.0
    owned: bool = False
    stopped: bool = False

    async def session(self) -> dict[str, Any]:
        """Run the session to its end condition and return the reports."""
        # Claim the baseline and the ownership before the POST: core waits
        # up to ~25 s for the profiler to come up, clients profiled during
        # that startup belong to this run, and a cancel landing mid-POST
        # must still leave a teardown that stops whatever core went on to
        # spawn.
        self.started_at = time.time()
        self.owned = True
        start = await self.client.post("/api/v1/profiler/start", json=self.start_body)
        if not start.get("success"):
            # Nothing of ours is running: 'already_running' is someone
            # else's profiler, which this task must never stop.
            self.owned = False
            why = start.get("message") or start.get("reason") or "unknown reason"
            return {"error": f"profiler did not start: {why}"}
        self.deadline = time.monotonic() + self.window_s
        while True:
            self.count = await self._count()
            if self.count >= self.until_clients:
                break
            remaining = self.deadline - time.monotonic()
            if remaining > 0:
                await asyncio.sleep(min(CLIENT_POLL_S, remaining))
                continue
            # The window ended short of the target.
            if not self.can_ask:
                break
            self.count = await self._count()  # fresh number for the question
            if self.count >= self.until_clients:
                break
            if not confirms.answer_confirms(await self._ask()):
                break
            self.deadline = time.monotonic() + self.window_s
        return await self._finish()

    async def _count(self) -> int:
        try:
            manifest = await self.client.get(profiler_reports.FILES_PATH)
        except (
            CoreAPIError,
            CoreUnavailableError,
            CoreBadResponseError,
        ) as exc:
            # One failed poll is not the end of the session: keep the last
            # count and let the end condition decide. A core restart surfaces
            # as CoreUnavailableError, not a status error.
            log.warning("profiler files poll failed: %s", exc)
            return self.count
        return profiler_reports.count_clients(manifest, since=self.started_at)

    async def _ask(self) -> dict[str, Any] | None:
        """Park the task on 'Keep going?' and return the answer content."""
        if self.record is None:  # pragma: no cover - the task path sets it
            return None
        future = tasks.TASKS.request_input(
            self.record,
            confirms.confirm_input_requests(
                f"Keep going? {self.count} of {self.until_clients} clients "
                "profiled so far."
            ),
        )
        try:
            return await asyncio.wait_for(future, ANSWER_TIMEOUT_S)
        except TimeoutError:
            # No answer ever arrived: clear the parked question and treat
            # the silence as a decline, so the profiler is released.
            tasks.TASKS.answer(self.record, None)
            return None

    async def _finish(self) -> dict[str, Any]:
        await self._stop()
        return await profiler_reports.get_reports(self.client, output=self.output)

    async def _stop(self) -> None:
        if self.owned and not self.stopped:
            await self.client.post("/api/v1/profiler/stop")
            self.stopped = True

    async def teardown(self) -> None:
        await self._stop()

    def progress(self) -> str:
        """Live statusMessage: clients this run has profiled so far."""
        return f"profiled {self.count} of {self.until_clients} clients"

    def partial(self) -> dict[str, Any]:
        """Report what a cancelled run had profiled; the stop is teardown's."""
        return {
            "clients_profiled": self.count,
            "note": "profiler stopping; fetch the profiles with get_profiler_reports",
        }


def _failed(exc: BaseException) -> dict[str, Any]:
    """Map a background session failure to the dict the task reports."""
    log.exception("task-backed profiling failed")
    return {"error": f"profiling failed: {type(exc).__name__}: {exc}"}


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
    async def profile_clients(
        until_clients: int,
        max_minutes: float = 10,
        interface: str | None = None,
        channel: int | None = None,
        ssid: str | None = None,
        output: Literal["json", "links", "zip"] = "json",
        ctx: Context[Any, Any] | None = None,
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Profile clients until a target count is reached or a time limit ends.

        This is start_profiler, a client-count watch, stop_profiler and
        get_profiler_reports combined into one MCP Task: the call answers
        with a task handle (for clients that support elicitation, first
        over one confirm round trip), the profiler runs in the background,
        and the task completes when this run has profiled until_clients
        clients or max_minutes minutes have elapsed. Before starting, the
        server asks the user to confirm over the MCP channel (the profiler
        takes over a radio for the session), so do not ask "are you sure"
        yourself. A profiler started by core that is already running is not
        interrupted: this task's start fails with already_running instead.

        Requires the MCP Tasks extension: without it this call fails with a
        tool error. Use start_profiler and stop_profiler with
        get_profiler_reports for the same ground step by step.

        While working, tasks/get reports how many clients this run has
        profiled so far in statusMessage. A failed count poll is retried
        until the deadline rather than ending the task. When max_minutes
        elapse with fewer than until_clients clients:
        - a client that also supports form elicitation sees the task go
          input_required with a "Keep going?" question: tasks/update with
          the answer {"confirm": true} runs another max_minutes window (the
          same rule applies again); any other answer stops the profiler and
          completes the task with the reports taken so far. An unanswered
          question is treated as a decline after 5 minutes, so the radio is
          not held forever.
        - a task-capable client without elicitation support is not asked:
          the task completes at the limit with the reports taken then.
        tasks/cancel stops the profiler and cancels the task at any point;
        profiles captured so far remain readable with get_profiler_reports.

        Only clients profiled by this run count toward until_clients
        (earlier runs' profiles still appear in the final reports).

        Args:
            until_clients: Stop once this run has profiled this many
                clients. At least 1.
            max_minutes: Time limit per window, in minutes (default 10). An
                accepted "Keep going?" extends the run by one more window.
            interface: WLAN interface to use (e.g. 'wlan0'), as in
                start_profiler.
            channel: 802.11 channel number to profile on, as in
                start_profiler.
            ssid: SSID for the fake AP, as in start_profiler. Other
                start_profiler options are not forwarded here; call
                start_profiler directly when you need them (this task's
                start would then report already_running).
            output: Report shape once the task completes, exactly as
                get_profiler_reports' output: 'json' (default), 'links' or
                'zip'.

        Returns a task handle. The task's result is the
        get_profiler_reports dict, or {"error": ...} when the profiler did
        not start.
        """
        if until_clients < 1:
            return {"error": "until_clients must be at least 1"}
        if max_minutes <= 0:
            return {"error": "max_minutes must be greater than 0"}
        if ctx is None or not tasks.tasks_supported(ctx):
            raise ToolError(
                "profile_clients runs as an MCP Task and this client did "
                "not declare the tasks extension. Use start_profiler, "
                "stop_profiler and get_profiler_reports instead."
            )
        gate = confirms.confirm_gate(
            ctx,
            f"Start the profiler to profile {until_clients} client(s)? It "
            "takes over a radio until this session ends "
            f"(up to {max_minutes:g} minutes at a time).",
        )
        if gate is not None:
            return gate
        args = {"interface": interface, "channel": channel, "ssid": ssid}
        run = _ProfileRun(
            client=client,
            start_body={k: v for k, v in args.items() if v is not None},
            until_clients=until_clients,
            window_s=max_minutes * 60,
            output=output,
            can_ask=confirms.form_elicitations_supported(ctx),
        )
        run.record = tasks.TASKS.create(progress=run.progress, cancel_work=True)
        tasks.spawn(
            run.record,
            run.session(),
            teardown=run.teardown,
            on_cancel=run.partial,
            on_error=_failed,
        )
        return tasks.task_call_result(
            run.record,
            message=(
                f"profiling up to {until_clients} clients as task "
                f"'{run.record.task_id}'; poll tasks/get with that taskId "
                "for progress and the final reports, or tasks/cancel to "
                "stop early"
            ),
            payload={
                "until_clients": until_clients,
                "max_minutes": max_minutes,
                "output": output,
            },
        )

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def purge_profiler_data(
        ctx: Context[Any, Any],
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Delete every profiler client profile, capture and session report.

        This cannot be undone. The server asks the user to confirm over the
        MCP channel before deleting, so do not ask "are you sure" yourself.
        Only call it when they asked to clear the profiler's saved data, never
        as cleanup after a profiling run.

        Returns {"files": N, "bytes": N}: how many files and symlinks were
        removed and their total size.

        Errors: 409 while the profiler is starting, running or stopping - stop
        it (stop_profiler) and wait for get_profiler_status to show it stopped,
        then retry.
        """
        gate = confirms.confirm_gate(
            ctx,
            "Delete every profiler client profile, capture and session report? "
            "This cannot be undone.",
        )
        if gate is not None:
            return gate
        return await client.post("/api/v1/profiler/purge")
