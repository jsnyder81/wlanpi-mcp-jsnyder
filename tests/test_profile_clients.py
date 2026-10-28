"""
profile_clients: a profiler session run as an MCP Task (issue #92).

The tool starts the profiler, polls the client count out of core's files
manifest, and stops the profiler when N clients are profiled or the time
window ends. These pin the end conditions, the "Keep going?" park (the
first use of the tasks store's input_required route), the cancel path,
and the capability gates. Windows are fractions of a minute and
CLIENT_POLL_S / ANSWER_TIMEOUT_S are monkeypatched, so every test runs in
milliseconds; LONG windows make only the intended end condition able to
fire.
"""

import asyncio
import itertools
import json
import time
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import (
    ClientCapabilities,
    ElicitationCapability,
    ElicitResult,
    FormElicitationCapability,
    InputRequiredResult,
)

from tests.test_profiler_reports import MAC, OTHER, PROFILE, _core_error
from wlanpi_mcp import tasks
from wlanpi_mcp.client.core_client import CoreBadResponseError, CoreUnavailableError
from wlanpi_mcp.tools import profiler, profiler_reports
from wlanpi_mcp.tools.confirms import CONFIRM_KEY

MODERN = "2026-07-28"
#: max_minutes values: a 0.03 s window, and one that cannot expire in a
#: test (10000 minutes).
SHORT = 0.0005
LONG = 10_000
TASK_ONLY = ClientCapabilities(extensions={tasks.TASKS_EXTENSION_ID: {}})
TASK_FORM = ClientCapabilities(
    extensions={tasks.TASKS_EXTENSION_ID: {}},
    elicitation=ElicitationCapability(form=FormElicitationCapability()),
)


def _ctx(capabilities: ClientCapabilities, state: str | None = None) -> Context:
    """Fake a Context: negotiated version, client caps, optional retry echo."""
    ctx = MagicMock(spec=Context)
    ctx.client_capabilities = capabilities
    ctx.protocol_version = MODERN
    ctx.request_state = state
    ctx.input_responses = (
        {CONFIRM_KEY: ElicitResult(action="accept", content={"confirm": True})}
        if state is not None
        else None
    )
    return ctx


def _manifest(*macs: str) -> dict[str, Any]:
    """Core's files manifest, stamped now: these clients count as profiled."""
    return {
        "clients": [
            {
                "mac": m,
                "files": [
                    {
                        "path": f"clients/{m}/{m}_5GHz.json",
                        "size": 100,
                        "modified": datetime.now(UTC)
                        .isoformat()
                        .replace("+00:00", "Z"),
                    }
                ],
            }
            for m in macs
        ],
        "reports": [],
    }


class FakeCore:
    """wlanpi-core's profiler control and files endpoints.

    ``manifests`` are the client sets served, one per files poll (the last
    repeats), so a test scripts the count climbing. Manifest timestamps are
    taken at poll time, so every listed client counts as profiled after the
    run started.
    """

    def __init__(
        self,
        start_result: dict[str, Any] | None = None,
        manifests: list[tuple[str, ...]] | None = None,
    ):
        self.start_result = start_result or {"success": True, "reason": "starting"}
        self.manifests = manifests or [()]
        self.posts: list[tuple[str, Any]] = []
        self.polls = itertools.count()
        #: When set, served manifests stamp this mtime instead of "now".
        self.served_mtime: float | None = None
        self.get = AsyncMock(side_effect=self._get)
        self.get_bytes = AsyncMock(side_effect=self._get_bytes)
        self.post = AsyncMock(side_effect=self._post)

    async def _post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        self.posts.append((path, kwargs.get("json")))
        if path == "/api/v1/profiler/start":
            return self.start_result
        return {"success": True}

    async def _get(self, path: str, params: Any = None) -> dict[str, Any]:
        assert path == profiler_reports.FILES_PATH
        manifest = _manifest(
            *self.manifests[min(next(self.polls), len(self.manifests) - 1)]
        )
        if self.served_mtime is not None:
            for entry in manifest["clients"]:
                for f in entry["files"]:
                    f["modified"] = (
                        datetime.fromtimestamp(self.served_mtime, UTC)
                        .isoformat()
                        .replace("+00:00", "Z")
                    )
        return manifest

    async def _get_bytes(self, path: str) -> tuple[bytes, str]:
        prefix = "/api/v1/profiler/files/clients/"
        assert path.startswith(prefix), path
        mac = path.rsplit("/", 1)[-1].split("_")[0]
        return json.dumps({**PROFILE, "mac": mac}).encode(), "application/json"

    @property
    def stopped(self) -> bool:
        return ("/api/v1/profiler/stop", None) in self.posts


@pytest.fixture(autouse=True)
def _fast_clock(monkeypatch):
    tasks.TASKS.clear()
    profiler_reports._TICKETS.clear()
    monkeypatch.setattr(profiler, "CLIENT_POLL_S", 0.005)
    yield
    tasks.TASKS.clear()
    profiler_reports._TICKETS.clear()


def _tool(core: FakeCore):
    mcp = MCPServer("test")
    profiler.register(mcp, core)
    return mcp._tool_manager._tools["profile_clients"]


async def _start(
    tool, args: dict[str, Any], capabilities: ClientCapabilities
) -> tasks.TaskRecord:
    """Call the tool, answering the start confirm when the client can."""
    out = await tool.run(args, _ctx(capabilities))
    if isinstance(out, InputRequiredResult):
        out = await tool.run(args, _ctx(capabilities, state=out.request_state))
    assert isinstance(out, tasks.TaskCallResult)
    record = tasks.TASKS.get(out.task_id)
    assert record is not None
    return record


async def _wait_status(record: tasks.TaskRecord, want: str, timeout: float = 5.0):
    async def check():
        while record.status != want:
            await asyncio.sleep(0.005)

    await asyncio.wait_for(check(), timeout)


# ── gates and validation ─────────────────────────────────────────────────────


async def test_client_without_tasks_gets_a_clear_error():
    core = FakeCore()
    tool = _tool(core)

    with pytest.raises(ToolError, match="start_profiler"):
        await tool.run(
            {"until_clients": 2, "max_minutes": 1}, _ctx(ClientCapabilities())
        )
    assert len(tasks.TASKS) == 0
    assert core.posts == []


async def test_until_clients_must_be_positive():
    core = FakeCore()
    tool = _tool(core)

    result = await tool.run({"until_clients": 0, "max_minutes": 1}, _ctx(TASK_FORM))
    assert "error" in result
    assert core.posts == []


async def test_max_minutes_must_be_positive():
    core = FakeCore()
    tool = _tool(core)

    result = await tool.run({"until_clients": 1, "max_minutes": 0}, _ctx(TASK_FORM))
    assert "error" in result
    assert core.posts == []


async def test_confirm_is_asked_before_the_profiler_starts():
    core = FakeCore()
    tool = _tool(core)

    first = await tool.run({"until_clients": 2, "max_minutes": 1}, _ctx(TASK_FORM))
    assert isinstance(first, InputRequiredResult)
    message = first.input_requests[CONFIRM_KEY].params.message
    assert "radio" in message
    assert core.posts == []  # nothing starts while the answer is pending

    ctx = _ctx(TASK_FORM, state=first.request_state)
    ctx.input_responses = {
        CONFIRM_KEY: ElicitResult(action="accept", content={"confirm": False})
    }
    assert await tool.run({"until_clients": 2, "max_minutes": 1}, ctx) == {
        "performed": False,
        "reason": "user declined or dismissed",
    }
    assert core.posts == []
    assert len(tasks.TASKS) == 0


async def test_no_confirm_asked_without_elicitation_support():
    core = FakeCore()
    tool = _tool(core)

    out = await tool.run({"until_clients": 5, "max_minutes": SHORT}, _ctx(TASK_ONLY))
    assert isinstance(out, tasks.TaskCallResult)
    record = tasks.TASKS.get(out.task_id)
    await _wait_status(record, "completed")  # the short window ends unasked
    assert record.input_requests is None


# ── completes at N ───────────────────────────────────────────────────────────


async def test_completes_when_the_target_count_is_reached():
    # Poll 1 sees one client, poll 2 sees two (the target); the final
    # get_profiler_reports read re-serves the last manifest.
    core = FakeCore(manifests=[(MAC,), (MAC, OTHER)])
    tool = _tool(core)
    record = await _start(
        tool,
        {
            "until_clients": 2,
            "max_minutes": LONG,
            "interface": "wlan0",
            "channel": 36,
        },
        TASK_FORM,
    )

    await _wait_status(record, "completed")
    assert core.posts[0] == (
        "/api/v1/profiler/start",
        {"interface": "wlan0", "channel": 36},
    )
    assert core.stopped  # stopped through the existing stop path
    assert record.result["total_clients"] == 2
    assert {c["mac"] for c in record.result["clients"]} == {MAC, OTHER}
    assert "session_reports" in record.result


async def test_clients_profiled_during_startup_are_counted():
    # Core's start waits for the profiler to come up: a client that
    # associated during that window has an older file mtime than the POST's
    # return, and must still count toward the target.
    core = FakeCore(manifests=[(MAC,)])

    async def post(path, **kwargs):
        core.posts.append((path, kwargs.get("json")))
        if path == "/api/v1/profiler/start":
            core.served_mtime = time.time()  # the profile lands mid-startup
            await asyncio.sleep(0.02)  # core's startup wait
            return core.start_result
        return {"success": True}

    core.post.side_effect = post
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 1, "max_minutes": LONG}, TASK_ONLY)

    await _wait_status(record, "completed")
    assert record.result["total_clients"] == 1
    assert core.stopped


async def test_start_failure_completes_with_the_error_and_never_stops():
    # 'already_running' is someone else's profiler: stopping it would break
    # the ownership rule, so the task reports why nothing ran.
    core = FakeCore(
        start_result={
            "success": False,
            "reason": "already_running",
            "message": "a profiler is already running",
        }
    )
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 2, "max_minutes": LONG}, TASK_ONLY)

    await _wait_status(record, "completed")
    assert record.result == {
        "error": "profiler did not start: a profiler is already running"
    }
    assert not core.stopped


async def test_progress_counts_clients_while_working():
    core = FakeCore(manifests=[(MAC,)])
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": LONG}, TASK_ONLY)

    async def check():
        while "profiled 1 of 5" not in (tasks.wire(record).get("statusMessage") or ""):
            await asyncio.sleep(0.005)

    await asyncio.wait_for(check(), 5)
    await tasks.TASKS.cancel(record)


# ── time limit: ask, extend, decline ─────────────────────────────────────────


async def test_time_limit_asks_and_accept_runs_a_second_window(monkeypatch):
    parks: list[dict[str, Any]] = []
    real_request_input = tasks.TASKS.request_input

    def spy(record, input_requests):
        parks.append(input_requests)
        return real_request_input(record, input_requests)

    monkeypatch.setattr(tasks.TASKS, "request_input", spy)
    core = FakeCore(manifests=[()])  # the count never reaches the target
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": SHORT}, TASK_FORM)

    await _wait_status(record, "input_required")
    ask = tasks.wire(record)["inputRequests"][CONFIRM_KEY]
    assert ask.params.message == "Keep going? 0 of 5 clients profiled so far."
    assert ask.params.requested_schema["properties"]["confirm"]["type"] == "boolean"

    tasks.TASKS.answer(record, {"confirm": True})

    async def second_window():
        while len(parks) < 2:
            await asyncio.sleep(0.005)

    await asyncio.wait_for(second_window(), 5)  # the extension ran and ended
    tasks.TASKS.answer(record, {"confirm": False})
    await _wait_status(record, "completed")
    assert core.stopped
    assert record.result["total_clients"] == 0


async def test_the_deadline_recount_can_reach_the_target_without_asking():
    # The last client landed between the loop's count and the one taken for
    # the question: the fresh count hits the target, so the run completes
    # instead of asking.
    core = FakeCore(manifests=[(), (MAC, OTHER)])
    run = profiler._ProfileRun(
        client=core,
        start_body={},
        until_clients=2,
        window_s=0,  # the window is already over at the first count
        output="json",
        can_ask=True,
    )
    run.record = tasks.TASKS.create(progress=run.progress)

    result = await run.session()
    assert result["total_clients"] == 2
    assert "inputRequests" not in tasks.wire(run.record)
    assert core.stopped
    tasks.TASKS.complete(run.record, result)


async def test_decline_stops_and_completes_with_the_reports():
    core = FakeCore(manifests=[(MAC,)])
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": SHORT}, TASK_FORM)

    await _wait_status(record, "input_required")
    tasks.TASKS.answer(record, {"confirm": False})
    await _wait_status(record, "completed")
    assert core.stopped
    assert record.result["total_clients"] == 1


async def test_no_answer_is_a_decline_and_releases_the_radio(monkeypatch):
    monkeypatch.setattr(profiler, "ANSWER_TIMEOUT_S", 0.05)
    core = FakeCore(manifests=[()])
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": SHORT}, TASK_FORM)

    await _wait_status(record, "input_required")
    await _wait_status(record, "completed")  # nobody answered
    assert core.stopped


async def test_time_limit_without_elicitation_completes_unasked():
    core = FakeCore(manifests=[(MAC,)])
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": SHORT}, TASK_ONLY)

    await _wait_status(record, "completed")
    assert record.input_requests is None  # never parked
    assert core.stopped
    assert record.result["total_clients"] == 1


async def test_reports_output_is_forwarded():
    core = FakeCore(manifests=[(MAC,)])
    tool = _tool(core)
    record = await _start(
        tool, {"until_clients": 1, "max_minutes": LONG, "output": "links"}, TASK_ONLY
    )

    await _wait_status(record, "completed")
    assert record.result["single_use"] is True
    assert [f["path"] for f in record.result["files"]] == [
        f"clients/{MAC}/{MAC}_5GHz.json"
    ]


# ── cancel ───────────────────────────────────────────────────────────────────


async def test_a_transient_poll_error_does_not_abort_the_session():
    # One failed count poll is a blip, not the end of the session: the run
    # keeps its last count and polls on to the next one.
    core = FakeCore(manifests=[(MAC,)])
    real_get = core._get
    calls = itertools.count()

    async def flaky(path, params=None):
        if next(calls) == 0:
            raise _core_error(500, "Internal Server Error")
        return await real_get(path, params)

    core.get.side_effect = flaky
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 1, "max_minutes": LONG}, TASK_ONLY)

    await _wait_status(record, "completed")
    assert record.result["total_clients"] == 1
    assert core.stopped


@pytest.mark.parametrize("error_cls", [CoreUnavailableError, CoreBadResponseError])
async def test_a_non_status_core_error_midrun_is_tolerated_by_the_count_poll(
    error_cls,
):
    # A core restart surfaces as CoreUnavailableError (a transport error, not
    # a status one), and a malformed body as CoreBadResponseError: the count
    # poll swallows both and keeps polling, exactly like a 5xx.
    core = FakeCore(manifests=[(MAC,)])
    real_get = core._get
    calls = itertools.count()

    async def flaky(path, params=None):
        if next(calls) == 0:
            raise error_cls("wlanpi-core hiccup")
        return await real_get(path, params)

    core.get.side_effect = flaky
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 1, "max_minutes": LONG}, TASK_ONLY)

    await _wait_status(record, "completed")
    assert record.result["total_clients"] == 1
    assert core.stopped


async def test_persistent_poll_errors_end_at_the_deadline():
    # Core refuses every poll: the session runs to its window, stops the
    # profiler, and fails only because the final report read fails too.
    core = FakeCore(manifests=[()])
    core.get.side_effect = _core_error(500, "Internal Server Error")
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": SHORT}, TASK_ONLY)

    await _wait_status(record, "failed")
    assert "500" in record.result["error"]
    assert core.stopped


async def test_cancel_stops_the_profiler():
    core = FakeCore(manifests=[()])
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": LONG}, TASK_ONLY)

    async def check():
        while not any(p == "/api/v1/profiler/start" for p, _ in core.posts):
            await asyncio.sleep(0.005)

    await asyncio.wait_for(check(), 5)
    await tasks.TASKS.cancel(record)
    assert record.status == "cancelled"
    assert record.result["clients_profiled"] == 0
    assert core.stopped


async def test_cancel_wakes_a_parked_ask_and_stops_the_profiler():
    core = FakeCore(manifests=[()])
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": SHORT}, TASK_FORM)

    await _wait_status(record, "input_required")
    await asyncio.wait_for(tasks.TASKS.cancel(record), timeout=5)
    assert record.status == "cancelled"
    assert core.stopped


async def test_cancel_during_the_start_post_stops_the_profiler():
    # Core's start waits up to ~25 s for the profiler to come up: a cancel
    # landing inside that window must still stop whatever core went on to
    # spawn, so ownership is claimed before the POST is issued.
    core = FakeCore()
    in_post = asyncio.Event()
    hold = asyncio.Event()

    async def post(path, **kwargs):
        core.posts.append((path, kwargs.get("json")))
        if path == "/api/v1/profiler/start":
            in_post.set()
            await hold.wait()
            return core.start_result
        return {"success": True}

    core.post.side_effect = post
    tool = _tool(core)
    record = await _start(tool, {"until_clients": 5, "max_minutes": LONG}, TASK_ONLY)

    await asyncio.wait_for(in_post.wait(), 5)
    await asyncio.wait_for(tasks.TASKS.cancel(record), timeout=5)
    assert record.status == "cancelled"
    assert core.stopped


async def test_a_cut_short_stop_is_issued_again_by_teardown():
    # The narrow race: a cancel lands while the stop POST is in flight. The
    # run must not mark itself stopped, so teardown re-issues and the radio
    # is never left taken.
    run = profiler._ProfileRun(
        client=MagicMock(),
        start_body={},
        until_clients=2,
        window_s=1,
        output="json",
        can_ask=False,
    )
    run.owned = True
    cut_short = asyncio.CancelledError()
    run.client.post = AsyncMock(side_effect=[cut_short, {"success": True}])

    with pytest.raises(asyncio.CancelledError):
        await run._stop()
    await run.teardown()
    assert run.client.post.await_count == 2


# ── the shared count helper ──────────────────────────────────────────────────


def test_count_clients_since_ignores_older_profiles():
    now = time.time()
    manifest = {
        "clients": [
            {
                "mac": m.replace("-", ":"),
                "files": [
                    {
                        "path": f"clients/{m}/{m}_5GHz.json",
                        "size": 10,
                        "modified": datetime.fromtimestamp(t, UTC)
                        .isoformat()
                        .replace("+00:00", "Z"),
                    }
                ],
            }
            for m, t in ((MAC, now - 500), (OTHER, now))
        ],
        "reports": [],
    }
    assert profiler_reports.count_clients(manifest) == 2
    assert profiler_reports.count_clients(manifest, since=now - 100) == 1
