"""
MCP Tasks support (issue #90).

Covers the task store lifecycle, the capability gate, and the tasks/*
extension methods over the real streamable HTTP app.
"""

import asyncio
import string
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context
from mcp.types import ClientCapabilities

from tests.test_capture_tools import (
    AUTH_OK,
    BEACON_A,
    CAPTURE_ENDED,
    CONFIG_APPLIED,
    StubWS,
    pcapng_chunks,
    sessions_event,
    started_event,
)
from tests.test_server import MCP_HEADERS, _serve
from wlanpi_mcp import tasks
from wlanpi_mcp.capture import storage
from wlanpi_mcp.capture.ws_client import CaptureSocket
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import Settings
from wlanpi_mcp.server import create_server
from wlanpi_mcp.tools import capture as capture_tools
from wlanpi_mcp.tools import capture_file

MODERN = "2026-07-28"
TASK_CAPS = ClientCapabilities(extensions={tasks.TASKS_EXTENSION_ID: {}})


def _ctx(
    capabilities: ClientCapabilities | None, version: str | None = MODERN
) -> Context[Any, Any]:
    """Build a Context fake exposing only the properties the gate reads."""
    ctx = MagicMock(spec=Context)
    ctx.client_capabilities = capabilities
    ctx.protocol_version = version
    return ctx


@pytest.fixture(autouse=True)
def _clean_store():
    tasks.TASKS.clear()
    yield
    tasks.TASKS.clear()


# ── store lifecycle ──────────────────────────────────────────────────────────


def test_create_returns_a_working_task_with_a_clean_id():
    record = tasks.TASKS.create()
    assert record.status == "working"
    assert len(record.task_id) <= 128
    assert all(c in string.printable and not c.isspace() for c in record.task_id)
    assert tasks.TASKS.get(record.task_id) is record


def test_complete_reports_the_outcome():
    record = tasks.TASKS.create()
    tasks.TASKS.complete(record, {"capture_id": "cap1"})
    assert record.status == "completed"
    assert record.result == {"capture_id": "cap1"}
    assert tasks.TASKS.get(record.task_id) is record


def test_first_terminal_transition_wins():
    record = tasks.TASKS.create()
    tasks.TASKS.complete(record, {"ok": True})
    tasks.TASKS.fail(record, {"error": "late"})
    assert record.status == "completed"
    assert record.result == {"ok": True}


def test_terminal_task_expires_after_its_ttl():
    record = tasks.TASKS.create(ttl_ms=1000)
    tasks.TASKS.complete(record, {})
    record.created -= 2  # past created + ttl
    assert tasks.TASKS.get(record.task_id) is None


def test_working_task_is_never_ttl_pruned():
    record = tasks.TASKS.create(ttl_ms=1000)
    record.created -= 10  # long past, but still running
    assert tasks.TASKS.get(record.task_id) is record


def test_unknown_id_is_absent():
    assert tasks.TASKS.get("never-existed") is None


async def test_cancel_runs_the_hook_and_terminates():
    stopped = []

    async def hook():
        stopped.append(True)

    record = tasks.TASKS.create(cancel=hook)
    await tasks.TASKS.cancel(record)
    assert stopped == [True]
    assert record.status == "cancelled"
    assert record.cancel_requested is True


async def test_cancel_of_a_terminal_task_is_a_noop():
    record = tasks.TASKS.create()
    tasks.TASKS.complete(record, {"done": True})
    await tasks.TASKS.cancel(record)
    assert record.status == "completed"
    assert record.result == {"done": True}


async def test_work_path_outcome_wins_over_the_cancel_transition():
    # The hook lets the work publish its own terminal state first; the
    # store's guarded transition must not overwrite it.

    async def hook():
        tasks.TASKS.complete(record, {"capture_id": "cap1"})

    record = tasks.TASKS.create(cancel=hook)
    await tasks.TASKS.cancel(record)
    assert record.status == "completed"


# ── input_required plumbing (#92 will use it from a tool) ────────────────────


async def test_request_input_parks_the_task_until_answered():
    record = tasks.TASKS.create()
    future = tasks.TASKS.request_input(record, {"q": "confirm?"})
    assert record.status == "input_required"
    assert tasks.wire(record)["inputRequests"] == {"q": "confirm?"}

    tasks.TASKS.answer(record, {"confirm": True})
    assert await asyncio.wait_for(future, 1) == {"confirm": True}
    assert record.status == "working"
    assert "inputRequests" not in tasks.wire(record)


def test_answer_without_a_pending_question_is_ignored():
    record = tasks.TASKS.create()
    tasks.TASKS.answer(record, {"confirm": True})
    assert record.status == "working"


def test_wire_carries_progress_message_while_working():
    record = tasks.TASKS.create(progress=lambda: "4096 bytes written")
    out = tasks.wire(record)
    assert out["statusMessage"] == "4096 bytes written"
    assert out["pollIntervalMs"] == tasks.POLL_INTERVAL_MS
    tasks.TASKS.complete(record, {})
    assert "statusMessage" not in tasks.wire(record)


async def test_spawn_survives_a_failing_teardown():
    # A wedged socket must not turn the task (or tasks/cancel) into an error:
    # the teardown failure is logged and the outcome still publishes.
    async def bad_teardown():
        raise OSError("wedged socket")

    async def work():
        return {"ok": True}

    record = tasks.TASKS.create()
    await asyncio.wait_for(tasks.spawn(record, work(), teardown=bad_teardown), 5)
    assert record.status == "completed"
    assert record.result == {"ok": True}


# ── the capability gate ──────────────────────────────────────────────────────


def test_gate_true_for_a_task_capable_client():
    assert tasks.tasks_supported(_ctx(TASK_CAPS)) is True


def test_gate_false_without_the_extension():
    assert tasks.tasks_supported(_ctx(ClientCapabilities())) is False
    assert tasks.tasks_supported(_ctx(None)) is False


def test_gate_false_on_an_older_protocol():
    assert tasks.tasks_supported(_ctx(TASK_CAPS, version="2025-11-25")) is False


def test_gate_false_outside_a_request():
    assert tasks.tasks_supported(Context()) is False
    assert tasks.tasks_supported(None) is False


async def test_cancel_wakes_a_parked_input_required_task():
    record = tasks.TASKS.create()
    future = tasks.TASKS.request_input(record, {"q": "go?"})

    await tasks.TASKS.cancel(record)
    assert record.status == "cancelled"
    # The parked work must not await forever: cancel resolves the future.
    assert await asyncio.wait_for(future, 1) is None
    assert "inputRequests" not in tasks.wire(record)


async def test_cancel_wakes_work_the_hook_is_awaiting():
    # The #92 shape: the work coroutine parks on the answer future and the
    # cancel hook awaits that work. Waking the future must happen before the
    # hook runs, or the two wait on each other forever. The wait_for turns a
    # regression into a failure instead of a hang.
    record = tasks.TASKS.create()
    future = tasks.TASKS.request_input(record, {"q": "go?"})
    woke = asyncio.Event()

    async def work():
        await future
        woke.set()

    work_task = asyncio.create_task(work())

    async def hook():
        await work_task

    record.cancel = hook
    await asyncio.wait_for(tasks.TASKS.cancel(record), timeout=2)

    assert record.status == "cancelled"
    await asyncio.wait_for(woke.wait(), timeout=2)


# ── tasks/* over the real HTTP app ───────────────────────────────────────────


@pytest.fixture
def mcp():
    return create_server(CoreClient(Settings(_env_file=None)))


def _request(method: str, params: dict[str, Any], name: str | None = None) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            **params,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": (
                    TASK_CAPS.model_dump(by_alias=True)
                ),
            },
        },
    }
    headers = {"Mcp-Method": method, "MCP-Protocol-Version": MODERN}
    if name:
        headers["Mcp-Name"] = name
    return {"json": payload, "headers": headers}


async def test_tasks_get_reports_the_outcome(mcp):
    record = tasks.TASKS.create()
    tasks.TASKS.complete(record, {"capture_id": "cap1", "size_bytes": 42})
    req = _request("tasks/get", {"taskId": record.task_id})
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=req["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **req["headers"]},
        )
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert result["status"] == "completed"
    assert result["result"] == {"capture_id": "cap1", "size_bytes": 42}
    assert result["resultType"] == "complete"


async def test_tasks_get_unknown_id_is_invalid_params(mcp):
    req = _request("tasks/get", {"taskId": "ghost"})
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=req["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **req["headers"]},
        )
    error = response.json()["error"]
    assert error["code"] == -32602
    assert "unknown or expired" in error["message"]


async def test_tasks_cancel_stops_the_work(mcp):
    stopped = []

    async def hook():
        stopped.append(True)

    record = tasks.TASKS.create(cancel=hook)
    req = _request("tasks/cancel", {"taskId": record.task_id})
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=req["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **req["headers"]},
        )
    assert response.json()["result"]["status"] == "cancelled"
    assert stopped == [True]


async def test_tasks_update_answers_an_input_required_task(mcp):
    record = tasks.TASKS.create()
    future = tasks.TASKS.request_input(record, {"q": "go?"})
    req = _request("tasks/update", {"taskId": record.task_id, "answer": {"go": True}})
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=req["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **req["headers"]},
        )
    assert response.json()["result"]["status"] == "working"
    assert await asyncio.wait_for(future, 1) == {"go": True}


# ── start_pcap_file as a task, end to end over HTTP ──────────────────────────


@pytest.fixture
async def pcap_app(monkeypatch, tmp_path):
    """Build the full server with the capture socket stubbed and files in tmp_path."""
    settings = Settings(PCAP_CAPTURE_DIR=str(tmp_path), _env_file=None)
    monkeypatch.setattr(capture_file, "get_settings", lambda: settings)
    monkeypatch.setattr(storage, "get_settings", lambda: settings)

    def use(stub):
        async def fake_connect(_settings):
            return CaptureSocket(stub, url="ws://test/api/v1/streaming/capture")

        monkeypatch.setattr(capture_file, "connect_capture", fake_connect)
        return stub

    mcp = create_server(CoreClient(settings))
    return mcp, use


def _ended_script(session_id):
    return StubWS(
        [
            AUTH_OK,
            sessions_event(),
            CONFIG_APPLIED,
            started_event(session_id),
            *pcapng_chunks(BEACON_A),
            CAPTURE_ENDED,
        ]
    )


async def test_start_pcap_file_to_a_task_client_returns_a_task(pcap_app):
    mcp, use = pcap_app
    stub = use(_ended_script("cap_task"))
    req = _request(
        "tools/call",
        {"name": "start_pcap_file", "arguments": {"channels": [6], "duration_s": 30}},
        name="start_pcap_file",
    )
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=req["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **req["headers"]},
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result["resultType"] == "task"
        assert result["status"] == "working"
        task_id = result["taskId"]
        assert result["structuredContent"]["capture_id"] == "cap_task"

        # The capture runs in the background; await its end, then a single
        # poll collects the outcome.
        await capture_file._CAPTURES["cap_task"].task
        get = _request("tasks/get", {"taskId": task_id})
        poll = await http.post(
            "/mcp",
            json=get["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **get["headers"]},
        )
        body = poll.json()["result"]
    assert body["status"] == "completed"
    assert body["result"]["capture_id"] == "cap_task"
    assert body["result"]["size_bytes"] > 0
    # The ownership rule holds: the background path stopped the core session.
    assert "stop" in stub.commands


async def test_start_pcap_file_to_a_plain_client_is_unchanged(pcap_app):
    mcp, use = pcap_app
    use(_ended_script("cap_plain"))
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "start_pcap_file",
            "arguments": {"channels": [6], "duration_s": 30},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=call,
            headers={
                "Authorization": "Bearer t",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "start_pcap_file",
                "MCP-Protocol-Version": MODERN,
                **MCP_HEADERS,
            },
        )
    result = response.json()["result"]
    # The gate holds: no task shape for a client that cannot parse it.
    assert result["resultType"] == "complete"
    assert "taskId" not in result
    assert result["structuredContent"]["status"] == "running"
    assert len(tasks.TASKS) == 0
    entry = capture_file._CAPTURES["cap_plain"]
    await entry.task


async def test_task_poll_without_the_extension_is_refused(mcp):
    record = tasks.TASKS.create()
    req = _request("tasks/get", {"taskId": record.task_id})
    meta = req["json"]["params"]["_meta"]
    meta["io.modelcontextprotocol/clientCapabilities"] = {}
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=req["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **req["headers"]},
        )
    assert response.json()["error"]["code"] == -32021


async def test_tasks_get_on_an_older_wire_is_method_not_found(mcp):
    # The bindings are gated to the revision that introduced the task
    # shapes; a 2025-11-25 poll must not reach the handler at all.
    record = tasks.TASKS.create()
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/get",
        "params": {"taskId": record.task_id},
    }
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=call,
            headers={
                "Authorization": "Bearer t",
                "MCP-Protocol-Version": "2025-11-25",
                **MCP_HEADERS,
            },
        )
    assert response.json()["error"]["code"] == -32601


# ── capture_scan as a task, end to end over HTTP ─────────────────────────────


@pytest.fixture
async def scan_app(monkeypatch, tmp_path):
    """Full server with the streaming capture socket stubbed and files in tmp."""
    settings = Settings(PCAP_CAPTURE_DIR=str(tmp_path), _env_file=None)
    monkeypatch.setattr(capture_tools, "get_settings", lambda: settings)
    monkeypatch.setattr(storage, "get_settings", lambda: settings)

    def use(stub):
        async def fake_connect(_settings):
            return CaptureSocket(stub, url="ws://test/api/v1/streaming/capture")

        monkeypatch.setattr(capture_tools, "connect_capture", fake_connect)
        return stub

    mcp = create_server(CoreClient(settings))
    return mcp, use


async def test_capture_scan_to_a_task_client_returns_a_task(scan_app):
    mcp, use = scan_app
    use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_http"),
                *pcapng_chunks(BEACON_A),
                CAPTURE_ENDED,
            ]
        )
    )
    req = _request(
        "tools/call",
        {"name": "capture_scan", "arguments": {"channels": [6], "duration_s": 5}},
        name="capture_scan",
    )
    async with _serve(mcp) as http:
        response = await http.post(
            "/mcp",
            json=req["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **req["headers"]},
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result["resultType"] == "task"
        assert result["status"] == "working"
        task_id = result["taskId"]
        assert result["structuredContent"]["session_id"] == "cap_http"

        # The window runs in the background; await its end, then a single
        # poll collects the outcome.
        await asyncio.wait_for(tasks.TASKS.get(task_id).work, timeout=5)
        get = _request("tasks/get", {"taskId": task_id})
        poll = await http.post(
            "/mcp",
            json=get["json"],
            headers={"Authorization": "Bearer t", **MCP_HEADERS, **get["headers"]},
        )
        body = poll.json()["result"]
    assert body["status"] == "completed"
    assert body["result"]["role"] == "owner"
    assert body["result"]["ap_count"] == 1
