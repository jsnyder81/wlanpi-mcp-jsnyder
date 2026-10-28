"""MCP tools for WLAN Pi utilities: reachability, speedtest, UFW, and blinker."""

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from mcp.server.mcpserver import Context, MCPServer

from wlanpi_mcp import tasks
from wlanpi_mcp.client.core_client import CoreAPIError, CoreClient
from wlanpi_mcp.tools import hints

log = logging.getLogger(__name__)

#: Core runs the whole LibreSpeed test inside this one request; it can take
#: 30-90 s, so the HTTP wait gets a generous bound.
SPEEDTEST_TIMEOUT_S = 180.0


@dataclass
class _SpeedtestRun:
    """One speedtest request, awaited inline or as the body of an MCP task.

    The phases (ping, download, upload) happen inside wlanpi-core's LibreSpeed
    call and a single REST GET exposes none of them, so progress is elapsed
    time only, and a cancel can only abandon the wait: the test itself runs to
    completion on the device.
    """

    client: CoreClient
    started: float = field(default_factory=time.monotonic)
    record: tasks.TaskRecord | None = None

    async def request(self) -> dict[str, Any]:
        """Ask core for the speedtest result (the blocking path's body)."""
        return await self.client.get(
            "/api/v1/utils/speedtest", timeout=SPEEDTEST_TIMEOUT_S
        )

    def progress(self) -> str:
        """Live statusMessage: how long the test has been running."""
        return f"speedtest running for {int(time.monotonic() - self.started)}s"


def _failed(exc: BaseException) -> dict[str, Any]:
    """Map a background speedtest failure to the dict the task reports."""
    log.exception("task-backed speedtest failed")
    return {"error": f"speedtest failed: {type(exc).__name__}: {exc}"}


def register(mcp: MCPServer, client: CoreClient) -> None:
    """Register the utility tools."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_reachability(
        targets: list[str] | None = None, namespace: str | None = None
    ) -> dict[str, Any]:
        """
        Test WLAN Pi network reachability.

        Pings the default gateway, checks DNS resolution, and verifies internet
        access. Use this to diagnose connectivity problems.

        Args:
            targets: Optional extra hostnames or IPs to ping as well
                (e.g. ['8.8.8.8', 'intranet.example.com'])
            namespace: Optional network namespace to test from (default: root
                namespace, usually Ethernet). The gateway lookup, DNS (using
                /etc/netns/<namespace>/resolv.conf if present) and every check
                run inside that namespace, so this tests whatever link that
                namespace holds (typically a profile's Wi-Fi client). Any
                existing namespace is accepted, e.g. names from
                get_network_config_status / get_network_config. Omit or pass
                "root" for the root namespace.

        Returns:
            The reachability results. A 400 from wlanpi-core (invalid name or
            'unknown namespace: <ns>') is raised as a tool error. A 503 'No
            default gateway found' is returned as an error dict: the namespace
            has no default route, which is a finding about that link.
        """
        params: dict[str, Any] = {}
        if targets:
            params["targets"] = targets
        if namespace:
            params["namespace"] = namespace
        try:
            return await client.get("/api/v1/utils/reachability", params=params or None)
        except CoreAPIError as exc:
            detail = exc.detail
            message = detail.get("error") if isinstance(detail, dict) else detail
            if not isinstance(message, str):
                message = str(exc)
            if exc.status_code != 503 or not message.lower().startswith(
                "no default gateway"
            ):
                raise
            return {"error": message, "namespace": namespace or "root"}

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_usb_interfaces() -> dict[str, Any]:
        """List USB network adapters currently plugged into the WLAN Pi."""
        return await client.get("/api/v1/utils/usb")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_ufw_status() -> dict[str, Any]:
        """Get the current UFW firewall status and active rules on the WLAN Pi."""
        return await client.get("/api/v1/utils/ufw")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def run_speedtest(
        ctx: Context[Any, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Run an internet speed test from the WLAN Pi.

        Uses LibreSpeed CLI; slow, typically taking 30-90 seconds to complete.
        Returns download/upload speed, ping, IP address, and the test server
        used.

        When your client supports MCP Tasks this call instead returns a task
        handle right away: the test continues in the background and tasks/get
        reports how long it has been running (the ping, download and upload
        phases happen inside wlanpi-core and are not observable from here)
        and, once terminal, the result this call would have returned, or an
        error dict if the test failed. Cancelling the task abandons the wait;
        the test itself still runs to completion on the device. Without task
        support the call blocks and returns this result directly.
        """
        if not tasks.tasks_supported(ctx):
            return await client.get(
                "/api/v1/utils/speedtest", timeout=SPEEDTEST_TIMEOUT_S
            )
        run = _SpeedtestRun(client=client)
        run.record = tasks.TASKS.create(progress=run.progress, cancel_work=True)
        tasks.spawn(run.record, run.request(), on_error=_failed)
        return tasks.task_call_result(
            run.record,
            message=(
                f"running speedtest as task '{run.record.task_id}'; poll "
                "tasks/get with that taskId for progress and the final result, "
                "or tasks/cancel to stop waiting"
            ),
            payload={"status": "running"},
        )

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
