"""The MCP Tasks extension (wlanpi_mcp/tasks.py) over the real /mcp dispatch (#90-#92)."""

import asyncio
import json
import re
import time
from datetime import UTC, datetime

import httpx
import pytest
import respx

from tests import wire
from tests.test_profiler_reports import MAC, PROFILE
from tests.test_server import _serve
from wlanpi_mcp import tasks
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.server import TASK_TOOLS, create_server
from wlanpi_mcp.tools import profiler

CORE = wire.CORE
SPEEDTEST = f"{CORE}/api/v1/utils/speedtest"
SPEED = {"download": 512.0, "upload": 256.0, "ping": 4.2}


@pytest.fixture
def mcp(settings):
    return create_server(CoreClient(settings))


@pytest.fixture(autouse=True)
async def _clean_tasks():
    tasks._TASKS.clear()
    yield
    for record in list(tasks._TASKS.values()):
        if record.job is not None and not record.job.done():
            record.job.cancel()
            try:
                await record.job
            except BaseException:  # noqa: BLE001 - teardown swallows everything
                pass
    tasks._TASKS.clear()


async def _until(http, task_id, *statuses, timeout=5.0, **kw):
    """Poll tasks/get until the task reaches one of ``statuses``."""
    deadline = time.monotonic() + timeout
    while True:
        body = await wire.task_method(http, "tasks/get", task_id, **kw)
        result = body["result"]
        if result["status"] in statuses:
            return result
        assert time.monotonic() < deadline, f"stuck at {result}"
        await asyncio.sleep(0.01)


async def _started(http, task_id):
    """Wait until the tool itself is running (it has reported progress).

    Until then core's state must not change: profile_clients counts only
    clients profiled after it started.
    """
    deadline = time.monotonic() + 5
    while "statusMessage" not in (result := await _until(http, task_id, "working")):
        assert time.monotonic() < deadline, f"never started: {result}"
        await asyncio.sleep(0.01)
    return result


def _held(gate: asyncio.Event, response: httpx.Response):
    """Build a respx side effect that answers only once ``gate`` is set."""

    async def respond(_request):
        await gate.wait()
        return response

    return respond


# ── creation and polling ────────────────────────────────────────────────────


@respx.mock
async def test_without_the_extension_the_call_runs_synchronously(mcp):
    respx.get(SPEEDTEST).mock(return_value=httpx.Response(200, json=SPEED))
    async with _serve(mcp) as http:
        body = await wire.call(http, "run_speedtest", capabilities=wire.FORM)
    assert body["result"]["structuredContent"] == SPEED


@respx.mock
async def test_a_task_completes_with_the_same_result_as_a_sync_call(mcp):
    respx.get(SPEEDTEST).mock(return_value=httpx.Response(200, json=SPEED))
    async with _serve(mcp) as http:
        sync = (await wire.call(http, "run_speedtest", capabilities=wire.NONE))[
            "result"
        ]
        created = (await wire.call(http, "run_speedtest", capabilities=wire.TASKS))[
            "result"
        ]
        assert created["resultType"] == "task"
        assert created["status"] == "working"
        assert created["ttlMs"] is None
        assert created["pollIntervalMs"] == tasks.POLL_INTERVAL_MS
        # Claude Code: at most 128 printable ASCII characters, no spaces.
        assert re.fullmatch(r"[\x21-\x7e]{1,128}", created["taskId"])
        for stamp in (created["createdAt"], created["lastUpdatedAt"]):
            assert datetime.fromisoformat(stamp).tzinfo is UTC

        done = await _until(http, created["taskId"], "completed")
    assert done["resultType"] == "complete"
    assert done["result"]["structuredContent"] == sync["structuredContent"]
    assert done["result"]["content"] == sync["content"]
    assert done["result"]["isError"] is False
    assert isinstance(done["ttlMs"], int) and done["ttlMs"] > 0


@respx.mock
async def test_status_message_reports_progress_while_running(mcp):
    gate = asyncio.Event()
    respx.get(SPEEDTEST).mock(side_effect=_held(gate, httpx.Response(200, json=SPEED)))
    async with _serve(mcp) as http:
        task_id = (await wire.call(http, "run_speedtest", capabilities=wire.TASKS))[
            "result"
        ]["taskId"]
        running = await _started(http, task_id)
        assert running["statusMessage"].startswith("speed test running")
        gate.set()
        await _until(http, task_id, "completed")


@respx.mock
async def test_a_tool_error_completes_with_is_error_not_failed(mcp):
    # The spec keeps 'failed' for JSON-RPC errors; a tool error is a result.
    respx.get(SPEEDTEST).mock(
        return_value=httpx.Response(503, json={"detail": "librespeed missing"})
    )
    async with _serve(mcp) as http:
        task_id = (await wire.call(http, "run_speedtest", capabilities=wire.TASKS))[
            "result"
        ]["taskId"]
        done = await _until(http, task_id, "completed", "failed")
    assert done["status"] == "completed"
    assert done["result"]["isError"] is True
    assert "503" in done["result"]["content"][0]["text"]


@respx.mock
async def test_only_the_allowlisted_tools_become_tasks(mcp):
    respx.get(f"{CORE}/api/v1/system/device/info").mock(
        return_value=httpx.Response(200, json={"hostname": "wlanpi-9be"})
    )
    async with _serve(mcp) as http:
        body = await wire.call(http, "get_device_info", capabilities=wire.TASKS)
    assert body["result"]["structuredContent"] == {"hostname": "wlanpi-9be"}
    assert tasks._TASKS == {}


def test_task_tools_are_real_tools(mcp):
    names = {t.name for t in mcp._tool_manager.list_tools()}
    assert TASK_TOOLS <= names


def test_the_extension_is_advertised(mcp):
    assert mcp._lowlevel_server.extensions == {tasks.EXTENSION_ID: {}}


# ── access ──────────────────────────────────────────────────────────────────


@respx.mock
async def test_unknown_and_other_tokens_tasks_are_both_invalid_params(mcp):
    gate = asyncio.Event()
    respx.get(SPEEDTEST).mock(side_effect=_held(gate, httpx.Response(200, json=SPEED)))
    async with _serve(mcp) as http:
        task_id = (
            await wire.call(
                http, "run_speedtest", capabilities=wire.TASKS, token="alice"
            )
        )["result"]["taskId"]
        for method in ("tasks/get", "tasks/cancel", "tasks/update"):
            extra = {"inputResponses": {}} if method == "tasks/update" else {}
            theirs = await wire.task_method(
                http, method, task_id, token="mallory", **extra
            )
            unknown = await wire.task_method(
                http, method, "nope", token="alice", **extra
            )
            assert theirs["error"]["code"] == unknown["error"]["code"] == -32602
        # mallory's cancel did nothing
        assert (await wire.task_method(http, "tasks/get", task_id, token="alice"))[
            "result"
        ]["status"] == "working"
        gate.set()


async def test_tasks_methods_require_the_extension(mcp):
    async with _serve(mcp) as http:
        body = await wire.task_method(http, "tasks/get", "x", capabilities=wire.NONE)
    assert body["error"]["code"] == -32021


# ── cancellation ────────────────────────────────────────────────────────────


@respx.mock
async def test_cancel_stops_the_running_call(mcp):
    respx.get(SPEEDTEST).mock(
        side_effect=_held(asyncio.Event(), httpx.Response(200, json=SPEED))
    )
    async with _serve(mcp) as http:
        task_id = (await wire.call(http, "run_speedtest", capabilities=wire.TASKS))[
            "result"
        ]["taskId"]
        ack = await wire.task_method(http, "tasks/cancel", task_id)
        assert ack["result"] == {"resultType": "complete", **ack["result"]}
        done = await _until(http, task_id, "cancelled")
    assert "inputRequests" not in done and "result" not in done


@respx.mock
async def test_cancel_before_the_job_starts_still_ends_cancelled(mcp):
    respx.get(SPEEDTEST).mock(return_value=httpx.Response(200, json=SPEED))
    async with _serve(mcp) as http:
        task_id = (await wire.call(http, "run_speedtest", capabilities=wire.TASKS))[
            "result"
        ]["taskId"]
        # The very next message, before the job has had a turn.
        tasks._TASKS[task_id].job.cancel()
        done = await _until(http, task_id, "cancelled", "completed")
    assert done["status"] == "cancelled"


# ── profile_clients (#92): in-task input through tasks/update ───────────────

FILES = f"{CORE}/api/v1/profiler/files"
PROFILE_PATH = f"clients/{MAC}/{MAC}_5GHz.json"


class Profiler:
    """wlanpi-core's profiler as profile_clients sees it."""

    def __init__(self, router):
        self.clients: list[dict] = []
        self.running = True
        self.start = router.post(f"{CORE}/api/v1/profiler/start").mock(
            return_value=httpx.Response(200, json={"success": True, "reason": None})
        )
        self.stop = router.post(f"{CORE}/api/v1/profiler/stop").mock(
            return_value=httpx.Response(200, json={"success": True})
        )
        router.get(f"{CORE}/api/v1/profiler/status").mock(
            side_effect=lambda _r: httpx.Response(
                200,
                json={
                    "running": self.running,
                    "ssid": "Profiler 9be",
                    "passphrase": "p",
                },
            )
        )
        router.get(FILES).mock(
            side_effect=lambda _r: httpx.Response(
                200, json={"clients": self.clients, "reports": []}
            )
        )
        router.get(f"{FILES}/{PROFILE_PATH}").mock(
            return_value=httpx.Response(200, content=json.dumps(PROFILE).encode())
        )

    def profile_one(self):
        modified = datetime.now(UTC).isoformat()
        self.clients = [
            {
                "mac": MAC.replace("-", ":"),
                "files": [{"path": PROFILE_PATH, "size": 10, "modified": modified}],
            }
        ]


@pytest.fixture
def fast_profiler(monkeypatch):
    monkeypatch.setattr(profiler, "PROFILE_POLL_S", 0.01)


async def test_profile_clients_completes_when_the_target_is_reached(mcp, fast_profiler):
    with respx.mock(assert_all_called=False) as router:
        core = Profiler(router)
        async with _serve(mcp) as http:
            task_id = (
                await wire.call(
                    http,
                    "profile_clients",
                    {"until_clients": 1, "max_minutes": 5},
                    capabilities=wire.TASKS,
                )
            )["result"]["taskId"]
            running = await _started(http, task_id)
            core.profile_one()
            done = await _until(http, task_id, "completed")
    result = done["result"]["structuredContent"]
    assert result["run"]["stopped_because"] == "target_reached"
    assert result["run"]["clients_profiled"] == 1
    assert [c["mac"] for c in result["clients"]] == [MAC]
    assert core.stop.called
    assert running["status"] == "working"


async def test_profile_clients_asks_to_keep_going_at_the_time_limit(mcp, fast_profiler):
    with respx.mock(assert_all_called=False) as router:
        core = Profiler(router)
        async with _serve(mcp) as http:
            task_id = (
                await wire.call(
                    http,
                    "profile_clients",
                    {"until_clients": 2, "max_minutes": 0.001},
                    capabilities=wire.TASKS,
                )
            )["result"]["taskId"]
            waiting = await _until(http, task_id, "input_required")
            ((key, request),) = waiting["inputRequests"].items()
            assert request["method"] == "elicitation/create"
            assert "Only 0 of 2 clients profiled" in request["params"]["message"]
            assert not core.stop.called

            ack = await wire.task_method(
                http, "tasks/update", task_id, inputResponses={key: wire.DECLINE}
            )
            assert ack["result"]["resultType"] == "complete"
            done = await _until(http, task_id, "completed")
    run = done["result"]["structuredContent"]["run"]
    assert run["stopped_because"] == "time_limit"
    assert core.stop.called


async def test_profile_clients_keeps_going_when_the_user_accepts(mcp, fast_profiler):
    with respx.mock(assert_all_called=False) as router:
        core = Profiler(router)
        async with _serve(mcp) as http:
            task_id = (
                await wire.call(
                    http,
                    "profile_clients",
                    {"until_clients": 1, "max_minutes": 0.001},
                    capabilities=wire.TASKS,
                )
            )["result"]["taskId"]
            waiting = await _until(http, task_id, "input_required")
            ((key, _request),) = waiting["inputRequests"].items()
            await wire.task_method(
                http, "tasks/update", task_id, inputResponses={key: wire.accept()}
            )
            core.profile_one()
            done = await _until(http, task_id, "completed")
    assert done["result"]["structuredContent"]["run"]["stopped_because"] == (
        "target_reached"
    )


async def test_cancelling_profile_clients_stops_the_profiler(mcp, fast_profiler):
    with respx.mock(assert_all_called=False) as router:
        core = Profiler(router)
        async with _serve(mcp) as http:
            task_id = (
                await wire.call(
                    http,
                    "profile_clients",
                    {"until_clients": 3},
                    capabilities=wire.TASKS,
                )
            )["result"]["taskId"]
            await _started(http, task_id)
            await wire.task_method(http, "tasks/cancel", task_id)
            await _until(http, task_id, "cancelled")
    assert core.start.called
    assert core.stop.called


async def test_profile_clients_reports_an_exited_profiler(mcp, fast_profiler):
    with respx.mock(assert_all_called=False) as router:
        core = Profiler(router)
        async with _serve(mcp) as http:
            task_id = (
                await wire.call(
                    http,
                    "profile_clients",
                    {"until_clients": 3},
                    capabilities=wire.TASKS,
                )
            )["result"]["taskId"]
            await _started(http, task_id)
            core.running = False
            done = await _until(http, task_id, "completed")
    assert done["result"]["structuredContent"]["run"]["stopped_because"] == (
        "profiler_exited"
    )


async def test_profile_clients_does_not_stop_a_profiler_it_did_not_start(mcp):
    with respx.mock(assert_all_called=False) as router:
        core = Profiler(router)
        core.start.mock(
            return_value=httpx.Response(
                200, json={"success": False, "reason": "already_running"}
            )
        )
        async with _serve(mcp) as http:
            task_id = (
                await wire.call(http, "profile_clients", capabilities=wire.TASKS)
            )["result"]["taskId"]
            done = await _until(http, task_id, "completed")
    assert done["result"]["structuredContent"]["error"] == "the profiler did not start"
    assert not core.stop.called


async def test_profile_clients_needs_task_support(mcp):
    with respx.mock(assert_all_called=False) as router:
        core = Profiler(router)
        async with _serve(mcp) as http:
            body = await wire.call(http, "profile_clients", capabilities=wire.FORM)
    assert "MCP Task" in body["result"]["structuredContent"]["error"]
    assert not core.start.called


# ── reporting() ─────────────────────────────────────────────────────────────


async def test_reporting_is_a_no_op_outside_a_task():
    async with tasks.reporting(lambda: 1 / 0):  # never called
        pass


async def test_reporting_updates_and_finally_refreshes_the_status():
    record = tasks.TaskRecord(task_id="t", tool="x", owner=None)
    counter = {"n": 0}

    def describe():
        counter["n"] += 1
        return f"step {counter['n']}"

    reset = tasks._current.set(record)
    try:
        async with tasks.reporting(describe, every_s=0.01):
            await asyncio.sleep(0.05)
    finally:
        tasks._current.reset(reset)
    assert counter["n"] >= 2
    assert record.status_message == f"step {counter['n']}"
