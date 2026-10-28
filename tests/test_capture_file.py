"""Tests for the file-backed capture tools (start/stop/list/fetch)."""

import asyncio
import base64
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, EmbeddedResource

from tests.test_capture_tools import (
    AUTH_OK,
    BEACON_A,
    BEACON_B,
    CAPTURE_ENDED,
    CONFIG_APPLIED,
    StubWS,
    pcapng_chunks,
    session,
    sessions_event,
    started_event,
)
from wlanpi_mcp import tasks
from wlanpi_mcp.capture import storage
from wlanpi_mcp.capture.ws_client import CaptureSocket
from wlanpi_mcp.client.core_client import CoreAPIError
from wlanpi_mcp.config import Settings
from wlanpi_mcp.tools import capture_file


class BlockingWS(StubWS):
    """Like StubWS but, once its script is exhausted, blocks instead of raising.

    The capture stays 'running' until an early stop trips the poll.
    """

    async def recv(self):
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        await asyncio.sleep(3600)


@pytest.fixture(autouse=True)
async def _clean_registry():
    capture_file._CAPTURES.clear()
    yield
    for entry in list(capture_file._CAPTURES.values()):
        task = entry.task
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except BaseException:  # noqa: BLE001 - teardown swallows everything
                pass
    capture_file._CAPTURES.clear()


@pytest.fixture
def capdir(monkeypatch, tmp_path):
    """Point the capture dir at tmp_path and let a test install its stub WS."""
    settings = Settings(PCAP_CAPTURE_DIR=str(tmp_path), _env_file=None)
    monkeypatch.setattr(capture_file, "get_settings", lambda: settings)
    # The dir/filename helpers read settings via the storage module.
    monkeypatch.setattr(storage, "get_settings", lambda: settings)

    def use(stub):
        async def fake_connect(_settings):
            return CaptureSocket(stub, url="ws://test/api/v1/streaming/capture")

        monkeypatch.setattr(capture_file, "connect_capture", fake_connect)
        return stub

    return tmp_path, use


def _register():
    client = MagicMock()
    client.current_token = MagicMock(return_value="fake.jwt.token")
    mcp = MCPServer("test")
    capture_file.register(mcp, client)
    return mcp._tool_manager._tools


async def _await_capture(session_id):
    entry = capture_file._CAPTURES[session_id]
    await asyncio.wait_for(entry.task, timeout=5)
    return entry


# ── start_pcap_file ──────────────────────────────────────────────────────────


async def test_start_returns_immediately_then_writes_the_pcapng_file(capdir):
    tmp, use = capdir
    stub = use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_file"),
                *pcapng_chunks(BEACON_A, BEACON_B),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    result = await tools["start_pcap_file"].fn(
        interface="wlanpi0", channels=[6], duration_s=30
    )

    assert result["status"] == "running"
    assert result["session_id"] == "cap_file"
    path = Path(result["path"])
    assert path.parent == tmp and path.suffix == ".pcapng"

    entry = await _await_capture("cap_file")
    assert entry.status == "completed"
    # The background task always stops+closes in its finally (never leave an
    # ownerless capture), so a trailing best-effort 'stop' is expected.
    assert stub.commands == ["auth", "list_sessions", "configure", "start", "stop"]
    assert stub.closed is True
    # The raw pcapng byte stream landed on disk (pcapng section header magic).
    data = path.read_bytes()
    assert data[:4] == b"\x0a\x0d\x0d\x0a"
    assert len(data) == entry.bytes_written > 0


# ── start_pcap_file as an MCP Task (#90) ────────────────────────────────────


async def _in_task(coro):
    """Run ``coro`` as if under an MCP Task; return (task record, its job)."""
    record = tasks.TaskRecord(task_id="t", tool="start_pcap_file", owner=None)

    async def run():
        tasks._current.set(record)
        return await coro

    record.job = asyncio.create_task(run())
    return record, record.job


def _tasks_cancel(record):
    """Deliver a cancel the way tasks/cancel does."""
    record.cancel_requested = True
    record.job.cancel()


async def _writing(session_id):
    """Wait until the capture has written its first bytes."""
    for _ in range(100):
        entry = capture_file._CAPTURES.get(session_id)
        if entry is not None and entry.bytes_written:
            return entry
        await asyncio.sleep(0.01)
    raise AssertionError(f"{session_id} never wrote")


async def test_under_a_task_start_completes_when_the_capture_ends(capdir):
    _tmp, use = capdir
    use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_task"),
                *pcapng_chunks(BEACON_A),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    record, job = await _in_task(
        tools["start_pcap_file"].fn(channels=[6], duration_s=30)
    )
    result = await asyncio.wait_for(job, timeout=5)
    assert result["status"] == "completed"
    assert result["capture_id"] == "cap_task"
    assert result["size_bytes"] > 0
    assert "fetch_pcap_file(capture_id='cap_task')" in result["message"]
    assert record.status_message.startswith("capture_id cap_task:")


async def test_cancelling_the_task_stops_the_capture_and_keeps_the_file(capdir):
    _tmp, use = capdir
    stub = use(
        BlockingWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_cancel"),
                *pcapng_chunks(BEACON_A),
            ]
        )
    )
    tools = _register()
    _record, job = await _in_task(
        tools["start_pcap_file"].fn(channels=[6], duration_s=600)
    )
    entry = await _writing("cap_cancel")

    # Not tasks/cancel (e.g. the daemon shutting down): the task is cancelled.
    job.cancel()
    with pytest.raises(asyncio.CancelledError):
        await job
    # Stopped the way stop_pcap_file stops it, not torn down mid-write.
    assert entry.status == "stopped"
    assert stub.commands[-1] == "stop" and stub.closed is True
    assert Path(entry.path).read_bytes()[:4] == b"\x0a\x0d\x0d\x0a"


async def test_tasks_cancel_completes_with_the_kept_file(capdir):
    # A cancelled Task carries no result, so tasks/cancel stops the capture
    # early and the task completes with the file it kept.
    _tmp, use = capdir
    stub = use(
        BlockingWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_early"),
                *pcapng_chunks(BEACON_A),
            ]
        )
    )
    tools = _register()
    record, job = await _in_task(
        tools["start_pcap_file"].fn(channels=[6], duration_s=600)
    )
    await _writing("cap_early")

    _tasks_cancel(record)
    result = await asyncio.wait_for(job, timeout=5)
    assert result["cancelled"] is True
    assert result["status"] == "stopped"
    assert result["size_bytes"] > 0
    assert "fetch_pcap_file(capture_id='cap_early')" in result["message"]
    assert stub.commands.count("stop") == 1 and stub.closed is True


async def test_start_rejects_a_busy_interface(capdir):
    _tmp, use = capdir
    stub = use(StubWS([AUTH_OK, sessions_event(session("cap_x", ["wlanpi0"]))]))
    tools = _register()
    result = await tools["start_pcap_file"].fn(interface="wlanpi0", channels=[6])

    assert "already captured" in result["error"]
    assert "configure" not in stub.commands
    assert stub.closed is True
    assert capture_file._CAPTURES == {}


async def test_start_clamps_duration_to_the_maximum(capdir):
    _tmp, use = capdir
    use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_dur"),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    result = await tools["start_pcap_file"].fn(channels=[6], duration_s=999999)

    assert result["duration_s"] == 3600
    await _await_capture("cap_dur")


async def test_invalid_width_is_rejected_before_connecting(capdir):
    _tmp, use = capdir
    stub = use(StubWS())
    tools = _register()
    result = await tools["start_pcap_file"].fn(width=25, channels=[6])

    assert "20" in result["error"]
    assert stub.sent == []


# ── stop_pcap_file ───────────────────────────────────────────────────────────


async def test_stop_ends_a_running_capture_early(capdir):
    _tmp, use = capdir
    use(
        BlockingWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_run"),
                *pcapng_chunks(BEACON_A),
            ]
        )
    )
    tools = _register()
    started = await tools["start_pcap_file"].fn(channels=[6], duration_s=30)
    assert started["status"] == "running"
    assert started["capture_id"] == "cap_run"

    stopped = await tools["stop_pcap_file"].fn(capture_id="cap_run")
    assert stopped["status"] == "stopped"
    assert stopped["capture_id"] == "cap_run"


async def test_stop_unknown_session_is_an_error(capdir):
    _tmp, _use = capdir
    tools = _register()
    result = await tools["stop_pcap_file"].fn(capture_id="nope")
    assert "no file capture" in result["error"]


async def test_bytes_written_advances_while_the_capture_is_running(capdir):
    _tmp, use = capdir
    use(
        BlockingWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_prog"),
                *pcapng_chunks(BEACON_A, BEACON_B),
            ]
        )
    )
    tools = _register()
    started = await tools["start_pcap_file"].fn(channels=[6], duration_s=30)
    assert started["status"] == "running"

    entry = capture_file._CAPTURES["cap_prog"]
    for _ in range(50):  # let the background task drain the delivered chunks
        if entry.bytes_written > 0:
            break
        await asyncio.sleep(0.02)

    # bytes_written tracks progress mid-capture, not only at completion.
    assert entry.status == "running"
    assert entry.bytes_written > 0
    assert entry.bytes_written == Path(entry.path).stat().st_size

    await tools["stop_pcap_file"].fn(capture_id="cap_prog")


async def test_fetch_without_identifier_or_path_is_an_error(capdir):
    _tmp, _use = capdir
    tools = _register()
    with pytest.raises(ToolError, match="pass capture_id or path"):
        await tools["fetch_pcap_file"].run({}, Context())


async def test_fetch_via_real_dispatch_path_resolves_capture_id(capdir):
    # Go through MCPServer's argument validation + dispatch (tool.run), not .fn:
    # this is the path a real MCP client hits, where the earlier session_id
    # collision surfaced.
    _tmp, use = capdir
    use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_run_path"),
                *pcapng_chunks(BEACON_A),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    await tools["start_pcap_file"].fn(channels=[6])
    await _await_capture("cap_run_path")

    by_capture_id = await tools["fetch_pcap_file"].fn(capture_id="cap_run_path")
    by_alias = await tools["fetch_pcap_file"].fn(session_id="cap_run_path")
    for result in (by_capture_id, by_alias):
        assert isinstance(result, EmbeddedResource)
        assert result.resource.mime_type == "application/vnd.tcpdump.pcapng"


# ── list_pcap_files ──────────────────────────────────────────────────────────


async def test_list_reports_started_captures(capdir):
    _tmp, use = capdir
    use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_list"),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    await tools["start_pcap_file"].fn(channels=[6])
    await _await_capture("cap_list")

    listing = await tools["list_pcap_files"].fn()
    assert listing["count"] == 1
    assert listing["captures"][0]["session_id"] == "cap_list"


# ── fetch_pcap_file ──────────────────────────────────────────────────────────


async def test_fetch_returns_a_pcapng_blob(capdir):
    _tmp, use = capdir
    use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_fetch"),
                *pcapng_chunks(BEACON_A, BEACON_B),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    await tools["start_pcap_file"].fn(channels=[6])
    entry = await _await_capture("cap_fetch")

    fetched = await tools["fetch_pcap_file"].fn(capture_id="cap_fetch")
    assert isinstance(fetched, EmbeddedResource)
    assert fetched.resource.mime_type == "application/vnd.tcpdump.pcapng"
    assert base64.b64decode(fetched.resource.blob) == Path(entry.path).read_bytes()
    # The deprecated session_id alias still resolves the same capture.
    via_alias = await tools["fetch_pcap_file"].fn(session_id="cap_fetch")
    assert isinstance(via_alias, EmbeddedResource)
    assert via_alias.resource.blob == fetched.resource.blob


async def test_fetch_sends_the_blob_once_without_structured_content(capdir):
    # Issue #50: with structured output on, MCPServer also serialised the
    # EmbeddedResource into structuredContent, doubling the payload. Go through
    # the real conversion path and check only unstructured content comes back.
    tmp, _use = capdir
    target = tmp / "capture-20260101T000000Z-cap_once.pcapng"
    target.write_bytes(b"\x0a\x0d\x0d\x0a" + b"x" * 4096)
    tools = _register()
    tool = tools["fetch_pcap_file"]

    assert tool.output_schema is None
    converted = await tool.run(
        {"capture_id": "cap_once"}, Context(), convert_result=True
    )
    assert isinstance(converted, CallToolResult)
    assert converted.structured_content is None
    assert len(converted.content) == 1
    (item,) = converted.content
    assert isinstance(item, EmbeddedResource)
    assert base64.b64decode(item.resource.blob) == target.read_bytes()


async def test_fetch_unknown_session_is_an_error(capdir):
    _tmp, _use = capdir
    tools = _register()
    with pytest.raises(ToolError, match="no capture file"):
        await tools["fetch_pcap_file"].run({"session_id": "ghost"}, Context())


async def test_fetch_refuses_a_path_outside_the_capture_dir(capdir):
    _tmp, _use = capdir
    tools = _register()
    with pytest.raises(ToolError, match="outside"):
        await tools["fetch_pcap_file"].run({"path": "/etc/passwd"}, Context())


async def test_fetch_by_path_within_the_capture_dir_works(capdir):
    tmp, _use = capdir
    target = tmp / "capture-wlanpi0-manual.pcapng"
    target.write_bytes(b"\x0a\x0d\x0d\x0a" + b"payload")
    tools = _register()
    fetched = await tools["fetch_pcap_file"].fn(path=str(target))
    assert isinstance(fetched, EmbeddedResource)
    assert base64.b64decode(fetched.resource.blob) == target.read_bytes()


async def test_fetch_by_session_id_falls_back_to_disk_after_registry_loss(capdir):
    _tmp, use = capdir
    use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_disk"),
                *pcapng_chunks(BEACON_A),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    await tools["start_pcap_file"].fn(channels=[6])
    entry = await _await_capture("cap_disk")
    expected = Path(entry.path).read_bytes()

    # Simulate a server restart: the in-memory registry is gone, file remains.
    capture_file._CAPTURES.clear()
    fetched = await tools["fetch_pcap_file"].fn(capture_id="cap_disk")
    assert isinstance(fetched, EmbeddedResource)
    assert base64.b64decode(fetched.resource.blob) == expected


async def test_list_includes_on_disk_files_after_registry_loss(capdir):
    _tmp, use = capdir
    use(
        StubWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_orphan"),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    await tools["start_pcap_file"].fn(channels=[6])
    await _await_capture("cap_orphan")

    capture_file._CAPTURES.clear()
    listing = await tools["list_pcap_files"].fn()
    assert listing["count"] == 1
    record = listing["captures"][0]
    assert record["status"] == "on_disk"
    assert record["capture_id"] == "cap_orphan"


# ── get_pcap_download_url ────────────────────────────────────────────────────


def _register_with_core(core_get):
    client = MagicMock()
    client.current_token = MagicMock(return_value="fake.jwt.token")
    client.get = core_get
    mcp = MCPServer("test")
    capture_file.register(mcp, client)
    return mcp


@pytest.fixture(autouse=True)
def _clean_tickets():
    capture_file._TICKETS.clear()
    yield
    capture_file._TICKETS.clear()


async def _ok(*_args, **_kwargs):
    return {"hostname": "wlanpi-test"}


async def test_download_link_needs_an_identifier(capdir):
    tools = _register_with_core(_ok)._tool_manager._tools
    result = await tools["get_pcap_download_url"].run({}, Context())
    assert result == {"error": "pass capture_id or path"}
    assert capture_file._TICKETS == {}


async def test_download_link_refuses_a_path_outside_the_capture_dir(capdir):
    tools = _register_with_core(_ok)._tool_manager._tools
    result = await tools["get_pcap_download_url"].run(
        {"path": "/etc/passwd"}, Context()
    )
    assert "outside the managed capture directory" in result["error"]
    assert capture_file._TICKETS == {}


async def test_download_link_is_not_minted_when_core_rejects_the_token(capdir):
    tmp_path, _ = capdir
    pcap = tmp_path / "capture-20261003T120000-cap_abc.pcapng"
    pcap.write_bytes(b"\x0a\x0d\x0d\x0a" * 8)

    async def refuse(*_args, **_kwargs):
        raise _core_error(401, "Invalid token")

    tools = _register_with_core(refuse)._tool_manager._tools
    result = await tools["get_pcap_download_url"].run(
        {"capture_id": "cap_abc"}, Context()
    )
    assert "refused this token" in result["error"]
    assert "Invalid token" in result["error"]
    assert capture_file._TICKETS == {}


def _core_error(status, detail):
    request = httpx.Request("GET", "https://localhost:31415/api/v1/system/device/info")
    return CoreAPIError(
        httpx.Response(status, json={"detail": detail}, request=request)
    )


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (_core_error(500, "boom"), "could not check the token with wlanpi-core"),
        (httpx.ConnectError("refused"), "could not check the token with wlanpi-core"),
    ],
)
async def test_download_link_does_not_blame_the_token_for_core_failures(
    capdir, failure, expected
):
    # Only a 401/403 means the token was refused; a 500 or a dead core must
    # say so instead of sending the user off to get a new JWT.
    tmp_path, _ = capdir
    (tmp_path / "capture-20261003T120000-cap_abc.pcapng").write_bytes(b"x")

    async def fail(*_args, **_kwargs):
        raise failure

    tools = _register_with_core(fail)._tool_manager._tools
    result = await tools["get_pcap_download_url"].run(
        {"capture_id": "cap_abc"}, Context()
    )
    assert result["error"].startswith(expected)
    assert "refused this token" not in result["error"]
    assert capture_file._TICKETS == {}


async def test_download_link_without_http_context_returns_path_size_and_hash(capdir):
    import hashlib

    tmp_path, _ = capdir
    data = b"\x0a\x0d\x0d\x0a" + bytes(range(200))
    pcap = tmp_path / "capture-20261003T120000-cap_abc.pcapng"
    pcap.write_bytes(data)
    tools = _register_with_core(_ok)._tool_manager._tools
    result = await tools["get_pcap_download_url"].run(
        {"capture_id": "cap_abc"}, Context()
    )
    assert result["capture_id"] == "cap_abc"
    assert result["filename"] == pcap.name
    assert result["size_bytes"] == len(data)
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["single_use"] is True
    assert result["download_path"].startswith(capture_file.DOWNLOAD_PREFIX)
    assert "download_url" not in result
    ticket = result["download_path"].removeprefix(capture_file.DOWNLOAD_PREFIX)
    assert capture_file._TICKETS[ticket][0] == str(pcap.resolve())


async def test_download_link_warns_while_the_capture_is_running(capdir):
    _, use = capdir
    use(
        BlockingWS(
            [
                AUTH_OK,
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_run"),
                *pcapng_chunks(BEACON_A),
            ]
        )
    )
    tools = _register_with_core(_ok)._tool_manager._tools
    start = await tools["start_pcap_file"].fn(
        interface="wlanpi0", channels=[6], duration_s=60
    )
    assert start["status"] == "running"
    await asyncio.sleep(0.05)  # let the background task write the first bytes
    result = await tools["get_pcap_download_url"].run(
        {"capture_id": "cap_run"}, Context()
    )
    assert result["status"] == "running"
    assert "partial" in result["warning"]


async def test_download_link_warns_when_a_running_capture_is_named_by_path(capdir):
    tmp_path, _ = capdir
    pcap = tmp_path / "capture-20261003T120000-cap_live.pcapng"
    pcap.write_bytes(b"\x0a\x0d\x0d\x0a")
    capture_file._CAPTURES["cap_live"] = capture_file.FileCapture(
        session_id="cap_live",
        interface="wlanpi0",
        path=str(pcap),
        duration_s=60,
        started_at=0.0,
        stop_event=asyncio.Event(),
    )
    try:
        tools = _register_with_core(_ok)._tool_manager._tools
        result = await tools["get_pcap_download_url"].run(
            {"path": str(pcap)}, Context()
        )
    finally:
        capture_file._CAPTURES.pop("cap_live", None)
    assert result["status"] == "running"
    assert "partial" in result["warning"]
