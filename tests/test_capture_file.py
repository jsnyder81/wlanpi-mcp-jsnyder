"""Tests for the file-backed capture tools (start/stop/list/fetch)."""

import asyncio
import base64
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from mcp.types import EmbeddedResource

from tests.test_capture_tools import (
    AUTH_OK,
    BEACON_A,
    BEACON_B,
    CAPTURE_ENDED,
    CONFIG_APPLIED,
    StubWS,
    event,
    pcapng_chunks,
    session,
    sessions_event,
    started_event,
)
from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.capture import storage
from wlanpi_mcp.capture.ws_client import CaptureSocket
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
    mcp = FastMCP("test")
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


async def test_start_without_an_interface_uses_the_only_capture_adapter(capdir):
    _tmp, use = capdir
    stub = use(
        StubWS(
            [
                AUTH_OK,
                event("SUPPORTED_FREQUENCIES", {"wlanpi3": [2412, 2437]}),
                sessions_event(),
                CONFIG_APPLIED,
                started_event("cap_auto"),
                CAPTURE_ENDED,
            ]
        )
    )
    tools = _register()
    result = await tools["start_pcap_file"].run({"duration_s": 30})

    assert result["interface"] == "wlanpi3"
    await _await_capture("cap_auto")
    assert stub.commands[:4] == [
        "auth",
        "get_supported_frequencies",
        "list_sessions",
        "configure",
    ]
    assert stub.payload("configure")["interfaces"]["wlanpi3"]["channels"] == [
        {"freq": 2412, "width": 20},
        {"freq": 2437, "width": 20},
    ]


async def test_start_without_an_interface_asks_when_there_are_several(capdir):
    _tmp, use = capdir
    stub = use(
        StubWS(
            [
                AUTH_OK,
                event("SUPPORTED_FREQUENCIES", {"wlanpi1": [5180], "wlanpi2": [2412]}),
            ]
        )
    )
    tools = _register()
    result = await tools["start_pcap_file"].fn(channels=[6])

    assert result["needsSelection"] is True
    assert [c["interface"] for c in result["candidates"]] == ["wlanpi1", "wlanpi2"]
    assert "configure" not in stub.commands
    assert stub.closed is True
    assert capture_file._CAPTURES == {}


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
    result = await tools["start_pcap_file"].fn(
        interface="wlanpi0", channels=[6], duration_s=999999
    )

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
    started = await tools["start_pcap_file"].fn(
        interface="wlanpi0", channels=[6], duration_s=30
    )
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
    started = await tools["start_pcap_file"].fn(
        interface="wlanpi0", channels=[6], duration_s=30
    )
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
    result = await tools["fetch_pcap_file"].fn()
    assert "pass capture_id or path" in result["error"]


async def test_fetch_via_real_dispatch_path_resolves_capture_id(capdir):
    # Go through FastMCP's argument validation + dispatch (tool.run), not .fn —
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
    await tools["start_pcap_file"].fn(interface="wlanpi0", channels=[6])
    await _await_capture("cap_run_path")

    by_capture_id = await tools["fetch_pcap_file"].fn(capture_id="cap_run_path")
    by_alias = await tools["fetch_pcap_file"].fn(session_id="cap_run_path")
    for result in (by_capture_id, by_alias):
        assert isinstance(result, EmbeddedResource)
        assert result.resource.mimeType == "application/vnd.tcpdump.pcapng"


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
    await tools["start_pcap_file"].fn(interface="wlanpi0", channels=[6])
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
    await tools["start_pcap_file"].fn(interface="wlanpi0", channels=[6])
    entry = await _await_capture("cap_fetch")

    fetched = await tools["fetch_pcap_file"].fn(capture_id="cap_fetch")
    assert isinstance(fetched, EmbeddedResource)
    assert fetched.resource.mimeType == "application/vnd.tcpdump.pcapng"
    assert base64.b64decode(fetched.resource.blob) == Path(entry.path).read_bytes()
    # The deprecated session_id alias still resolves the same capture.
    via_alias = await tools["fetch_pcap_file"].fn(session_id="cap_fetch")
    assert isinstance(via_alias, EmbeddedResource)
    assert via_alias.resource.blob == fetched.resource.blob


async def test_fetch_unknown_session_is_an_error(capdir):
    _tmp, _use = capdir
    tools = _register()
    result = await tools["fetch_pcap_file"].fn(session_id="ghost")
    assert "no capture file" in result["error"]


async def test_fetch_refuses_a_path_outside_the_capture_dir(capdir):
    _tmp, _use = capdir
    tools = _register()
    result = await tools["fetch_pcap_file"].fn(path="/etc/passwd")
    assert "outside" in result["error"]


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
    await tools["start_pcap_file"].fn(interface="wlanpi0", channels=[6])
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
    await tools["start_pcap_file"].fn(interface="wlanpi0", channels=[6])
    await _await_capture("cap_orphan")

    capture_file._CAPTURES.clear()
    listing = await tools["list_pcap_files"].fn()
    assert listing["count"] == 1
    record = listing["captures"][0]
    assert record["status"] == "on_disk"
    assert record["capture_id"] == "cap_orphan"
