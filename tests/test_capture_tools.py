"""Tests for the capture tools that drive the wlanpi-core capture WebSocket."""

import asyncio
import json
import ssl
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tests.test_capture_dot11 import beacon, radiotap
from tests.test_capture_pcapng import epb, idb, shb
from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.capture import storage
from wlanpi_mcp.capture.ws_client import CaptureSocket
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import Settings
from wlanpi_mcp.tools import capture as capture_tools

# ── scripted WebSocket stub ──────────────────────────────────────────────────


class ClosedByServer(Exception):
    """Stands in for websockets' ConnectionClosed, which carries a close code."""

    def __init__(self, code: int) -> None:
        super().__init__(f"closed with {code}")
        self.code = code


class StubWS:
    """Replays a queued script of server messages and records what was sent."""

    def __init__(self, script=None) -> None:
        self.sent = []
        self.script = list(script or [])
        self.closed = False

    async def send(self, raw):
        self.sent.append(json.loads(raw))

    async def recv(self):
        if not self.script:
            raise ConnectionResetError("stub capture socket ran out of script")
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def close(self):
        self.closed = True

    @property
    def commands(self):
        return [message.get("command") for message in self.sent]

    def payload(self, command):
        for message in self.sent:
            if message.get("command") == command:
                return message
        raise AssertionError(f"{command!r} was never sent; sent {self.commands}")


def event(code, data=None, event_type="status"):
    return json.dumps(
        {"type": "event", "event": event_type, "code": code, "data": data or {}}
    )


AUTH_OK = event("AUTH_OK", {"did": "did:test:mcp"})
AUTH_FAILED = event("AUTH_FAILED", {"message": "Token verification failed."}, "error")
CONFIG_APPLIED = event("CONFIG_APPLIED", {"message": "Configured: wlanpi0"}, "config")
CAPTURE_ENDED = event("CAPTURE_ENDED", {"message": "Capture ended."})
CHANNEL_SET = event("CHANNEL_SET", {"message": "wlanpi0: 2437 MHz / 20 MHz"}, "info")
CHANNEL_SET_FAILED = event(
    "CHANNEL_SET_FAILED",
    {
        "message": "wlanpi0: failed to set 5180 MHz / 20 MHz (Device or resource busy (-16))"
    },
    "error",
)

RUNNING_CONFIG = {
    "interfaces": {
        "wlanpi0": {"channels": [{"freq": 2437, "width": 20}], "dwell_time": 250}
    },
    "pcap_filter": "",
}


def sessions_event(*sessions):
    return event("SESSIONS", {"sessions": list(sessions)})


def session(session_id="cap_ab12", interfaces=("wlanpi0",), owner="did:test:webui"):
    return {
        "session_id": session_id,
        "owner": owner,
        "interfaces": list(interfaces),
        "namespace": "capture-ns",
        "config": RUNNING_CONFIG,
    }


def started_event(session_id="cap_owned"):
    return event(
        "CAPTURE_STARTED",
        {
            "message": "Started capture on wlanpi0",
            "session_id": session_id,
            "interfaces": ["wlanpi0"],
            "config": RUNNING_CONFIG,
        },
    )


def subscribed_event(session_id="cap_ab12"):
    return event("SUBSCRIBED", session(session_id=session_id))


def pcapng_chunks(*frames, split_at=25):
    """One pcapng stream carrying `frames`, delivered as two binary messages."""
    stream = shb() + idb(127)
    for frame in frames:
        stream += epb(frame)
    return [stream[:split_at], stream[split_at:]]


BEACON_A = beacon(bssid="00:11:22:33:44:55", ssid=b"lab-24", rt=radiotap(2437, -40))
BEACON_B = beacon(bssid="66:77:88:99:aa:bb", ssid=b"lab-5", rt=radiotap(5180, -60))


@pytest.fixture
def ws(monkeypatch, tmp_path):
    """Monkeypatches connect_capture to hand back a CaptureSocket on a stub."""
    stub = StubWS()

    async def fake_connect(settings):
        stub.settings = settings
        return CaptureSocket(stub, url="ws://test/api/v1/streaming/capture")

    monkeypatch.setattr(capture_tools, "connect_capture", fake_connect)
    # capture_scan/observe tee the raw pcapng to the managed dir; keep that in
    # tmp_path so tests don't write into the real default location.
    settings = Settings(PCAP_CAPTURE_DIR=str(tmp_path), _env_file=None)
    monkeypatch.setattr(storage, "get_settings", lambda: settings)
    stub.capture_dir = tmp_path
    return stub


def _register(client=None):
    mock_client = client
    if mock_client is None:
        mock_client = MagicMock()
        mock_client.current_token = MagicMock(return_value="fake.jwt.token")
    mcp = FastMCP("test")
    capture_tools.register(mcp, mock_client)
    return mcp._tool_manager._tools, mock_client


# ── auth ─────────────────────────────────────────────────────────────────────


async def test_auth_is_the_first_message_sent(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event(),
        *pcapng_chunks(BEACON_A),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    await tools["capture_scan"].fn(interface="wlanpi0", channels=[6], duration_s=1)

    assert ws.sent[0] == {"command": "auth", "token": "fake.jwt.token"}
    assert ws.commands[1] == "list_sessions"


async def test_auth_failure_returns_an_error_dict(ws):
    ws.script = [AUTH_FAILED]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    assert "AUTH_FAILED" in result["error"]
    assert "Token verification failed." in result["error"]
    assert "start" not in ws.commands and "configure" not in ws.commands
    assert ws.closed is True


async def test_close_with_4401_is_reported_as_a_token_problem(ws):
    ws.script = [ClosedByServer(4401)]
    tools, _ = _register()
    result = await tools["list_capture_sessions"].fn()

    assert "4401" in result["error"]
    assert "token" in result["error"]


async def test_missing_token_returns_an_error_without_connecting(ws):
    client = CoreClient(Settings(WLANPI_CORE_TOKEN="", _env_file=None))
    tools, _ = _register(client)
    result = await tools["capture_scan"].fn(duration_s=1)

    assert "error" in result and "token" in result["error"]
    assert ws.sent == []


async def test_token_falls_back_to_settings_in_stdio_mode(ws):
    ws.script = [AUTH_OK, sessions_event()]
    client = CoreClient(Settings(WLANPI_CORE_TOKEN="env-token", _env_file=None))
    tools, _ = _register(client)
    await tools["list_capture_sessions"].fn()

    assert ws.sent[0]["token"] == "env-token"


async def test_bearer_token_context_wins_over_settings(ws, bearer_token):
    ws.script = [AUTH_OK, sessions_event()]
    client = CoreClient(Settings(WLANPI_CORE_TOKEN="env-token", _env_file=None))
    tools, _ = _register(client)
    await tools["list_capture_sessions"].fn()

    assert ws.sent[0]["token"] == bearer_token


# ── capture_scan: owner flow ─────────────────────────────────────────────────


async def test_owner_flow_returns_dissected_aps_and_stops_the_capture(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event("cap_owned"),
        *pcapng_chunks(BEACON_A, BEACON_B),
        CHANNEL_SET,
        # The capture is still running when the window elapses (a quiet recv
        # that times out, like the real duration deadline), not a self-report.
        TimeoutError(),
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6, 36], duration_s=1
    )

    assert result["role"] == "owner"
    assert result["session_id"] == "cap_owned"
    assert result["config"] == RUNNING_CONFIG
    assert result["ap_count"] == 2
    assert {ap["ssid"] for ap in result["aps"]} == {"lab-24", "lab-5"}
    assert result["channel_issues"] == []
    assert "note" not in result
    # A normal full-window capture that we stopped is not "ended early".
    assert result["capture_ended_early"] is False
    # The window ends without a self-reported end, so the owner stops the
    # capture and then drains before the tool returns.
    assert ws.commands == ["auth", "list_sessions", "configure", "start", "stop"]
    assert ws.closed is True


async def test_owner_flow_returns_per_frame_records_and_type_counts(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event("cap_owned"),
        *pcapng_chunks(BEACON_A, BEACON_B),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6, 36], duration_s=1
    )

    assert result["frame_total"] == 2
    assert result["frame_types"] == {"mgmt/beacon": 2}
    kinds = [f["kind"] for f in result["frames"]]
    assert kinds == ["mgmt/beacon", "mgmt/beacon"]
    first = result["frames"][0]
    assert first["addr1"] == "ff:ff:ff:ff:ff:ff"
    assert first["addr2"] == "00:11:22:33:44:55"
    assert first["result"] == {"ssid": "lab-24"}
    assert "channel" in first["radiotap"]["present"]


async def test_max_frames_zero_keeps_counts_but_no_records(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event("cap_owned"),
        *pcapng_chunks(BEACON_A, BEACON_B),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1, max_frames=0
    )

    assert result["frames"] == []
    assert result["frame_total"] == 2
    assert result["frame_types"] == {"mgmt/beacon": 2}


async def test_owner_flow_saves_the_raw_pcap_and_returns_its_path(ws, tmp_path):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event("cap_owned"),
        *pcapng_chunks(BEACON_A, BEACON_B),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    path = Path(result["pcap_path"])
    assert path.parent == tmp_path and path.suffix == ".pcapng"
    data = path.read_bytes()
    assert data[:4] == b"\x0a\x0d\x0d\x0a"  # pcapng section-header magic
    assert result["pcap_bytes"] == len(data) > 0
    # The saved capture is discoverable by capture_id (core's session id).
    assert path.name.endswith("-cap_owned.pcapng")


async def test_negative_max_frames_returns_all_frames_uncapped(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event("cap_owned"),
        *pcapng_chunks(BEACON_A, BEACON_B),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1, max_frames=-1
    )

    assert result["frame_total"] == 2
    assert result["frames_returned"] == 2
    assert result["frames_truncated"] is False


async def test_owner_flow_maps_channel_numbers_and_frequencies(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event(),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    await tools["capture_scan"].fn(
        interface="wlanpi0",
        channels=[1, 36, 5955],
        width=40,
        dwell_ms=300,
        duration_s=1,
    )

    configure = ws.payload("configure")
    assert configure["interfaces"]["wlanpi0"] == {
        "channels": [
            {"freq": 2412, "width": 40},
            {"freq": 5180, "width": 40},
            {"freq": 5955, "width": 40},  # 6 GHz passed through as MHz
        ],
        "dwell_time": 300,
    }


async def test_owner_flow_hops_supported_channels_when_none_are_given(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        event("SUPPORTED_FREQUENCIES", {"wlanpi0": [2412, 2437], "wlanpi1": [5180]}),
        CONFIG_APPLIED,
        started_event(),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    await tools["capture_scan"].fn(interface="wlanpi0", duration_s=1)

    assert ws.commands[2] == "get_supported_frequencies"
    assert ws.payload("configure")["interfaces"]["wlanpi0"]["channels"] == [
        {"freq": 2412, "width": 20},
        {"freq": 2437, "width": 20},
    ]


async def test_unknown_interface_in_supported_frequencies_is_an_error(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        event("SUPPORTED_FREQUENCIES", {"wlanpi0": [2412], "wlanpi1": [5180]}),
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(interface="wlanpi7", duration_s=1)

    assert "wlanpi7" in result["error"]
    assert "wlanpi0" in result["error"]
    assert "configure" not in ws.commands


async def test_unknown_interface_is_not_swapped_for_the_only_adapter(ws):
    # A stale name must fail, not silently borrow the one real adapter's
    # frequencies and then configure/start the name that does not exist.
    ws.script = [
        AUTH_OK,
        sessions_event(),
        event("SUPPORTED_FREQUENCIES", {"wlanpi1": [2412, 2437]}),
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(interface="wlanpi0", duration_s=1)

    assert "'wlanpi0'" in result["error"]
    assert "wlanpi1" in result["error"]
    assert "configure" not in ws.commands


async def test_omitted_interface_picks_the_only_capture_adapter(ws):
    ws.script = [
        AUTH_OK,
        # An adapter with no usable channels is not a candidate.
        event("SUPPORTED_FREQUENCIES", {"wlanpi1": [], "wlanpi2": [2412, 2437]}),
        sessions_event(),
        CONFIG_APPLIED,
        started_event(),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    # Through FastMCP's dispatch, so the optional argument is really optional.
    result = await tools["capture_scan"].run({"duration_s": 1})

    assert result["interface"] == "wlanpi2"
    # Supported frequencies are fetched once, and before the session check
    # so that check runs against the picked interface.
    assert ws.commands[:4] == [
        "auth",
        "get_supported_frequencies",
        "list_sessions",
        "configure",
    ]
    assert list(ws.payload("configure")["interfaces"]) == ["wlanpi2"]
    assert ws.payload("start")["interfaces"] == ["wlanpi2"]


async def test_omitted_interface_with_several_adapters_asks_for_a_choice(ws):
    ws.script = [
        AUTH_OK,
        event("SUPPORTED_FREQUENCIES", {"wlanpi1": [5180, 5200], "wlanpi2": [2412]}),
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(channels=[6], duration_s=1)

    assert result["needsSelection"] is True
    assert result["candidates"] == [
        {"interface": "wlanpi1", "channel_count": 2},
        {"interface": "wlanpi2", "channel_count": 1},
    ]
    assert ws.commands == ["auth", "get_supported_frequencies"]
    assert ws.closed is True


async def test_omitted_interface_with_no_adapters_is_an_error(ws):
    ws.script = [AUTH_OK, event("SUPPORTED_FREQUENCIES", {"wlanpi0": []})]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(duration_s=1)

    assert "no capture interfaces" in result["error"]
    assert "configure" not in ws.commands


async def test_channel_set_failures_are_surfaced_with_the_single_radio_hint(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        # Core sends CHANNEL_SET_FAILED as an error event, including before
        # CAPTURE_STARTED — it must degrade the result, not fail the tool.
        CHANNEL_SET_FAILED,
        started_event(),
        *pcapng_chunks(BEACON_A),
        CHANNEL_SET_FAILED,
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6, 36], duration_s=1
    )

    assert result["role"] == "owner"
    assert len(result["channel_issues"]) == 2
    issue = result["channel_issues"][0]
    assert issue["code"] == "CHANNEL_SET_FAILED"
    assert issue["freq"] == 5180 and issue["channel"] == 36
    assert "Device or resource busy" in issue["message"]
    assert "partial" in result["note"]


async def test_config_invalid_is_returned_as_an_error(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        event(
            "CONFIG_INVALID",
            {"message": "Invalid capture interface configuration."},
            "error",
        ),
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    assert "CONFIG_INVALID" in result["error"]
    assert "start" not in ws.commands


async def test_owner_stops_the_capture_even_when_consuming_raises(ws, monkeypatch):
    ws.script = [AUTH_OK, sessions_event(), CONFIG_APPLIED, started_event()]

    async def boom(sock, duration_s, frame_log, *, owner=False, raw_sink=None):
        raise RuntimeError("dissector exploded")

    monkeypatch.setattr(capture_tools, "_run_window", boom)
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    assert "dissector exploded" in result["error"]
    assert ws.commands[-1] == "stop"  # never leave an ownerless capture running
    assert ws.closed is True


async def test_owner_drains_tail_frames_delivered_after_stop(monkeypatch, tmp_path):
    # Keep the teed pcapng out of the real default dir.
    monkeypatch.setattr(
        storage,
        "get_settings",
        lambda: Settings(PCAP_CAPTURE_DIR=str(tmp_path), _env_file=None),
    )
    # The window carries two beacons; a third beacon plus CAPTURE_STOPPED are
    # released only once the owner has sent 'stop', standing in for dumpcap's
    # flush on stop. The drain must read them, so the tail beacon lands in the
    # AP table instead of being cut off when the socket closes.
    window = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event("cap_owned"),
        *pcapng_chunks(BEACON_A, BEACON_B),
    ]
    tail_beacon = beacon(
        bssid="cc:dd:ee:ff:00:11", ssid=b"lab-tail", rt=radiotap(2437, -50)
    )
    tail = [
        *pcapng_chunks(tail_beacon),
        event("CAPTURE_STOPPED", {"message": "Capture stopped."}),
    ]

    class DrainStub(StubWS):
        def __init__(self):
            super().__init__(window)
            self._window_ended = False

        async def recv(self):
            if self.script:
                item = self.script.pop(0)
                if isinstance(item, BaseException):
                    raise item
                return item
            if not self._window_ended:
                # End the capture window: no more data until 'stop' is sent.
                self._window_ended = True
                raise ConnectionResetError("window quiet")
            if "stop" in self.commands and tail:
                item = tail.pop(0)
                if isinstance(item, BaseException):
                    raise item
                return item
            raise ConnectionResetError("stream done")

    stub = DrainStub()

    async def fake_connect(settings):
        return CaptureSocket(stub, url="ws://test/api/v1/streaming/capture")

    monkeypatch.setattr(capture_tools, "connect_capture", fake_connect)
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    assert result["role"] == "owner"
    assert "stop" in stub.commands
    # The tail beacon arrived only after 'stop'; the drain still dissected it.
    assert result["ap_count"] == 3
    assert "lab-tail" in {ap["ssid"] for ap in result["aps"]}
    assert stub.closed is True


async def test_invalid_width_is_rejected_before_connecting(ws):
    tools, _ = _register()
    result = await tools["capture_scan"].fn(width=25, duration_s=1)

    assert "20" in result["error"]
    assert ws.sent == []


async def test_duration_is_clamped_to_the_maximum(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        started_event(),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=9999
    )

    assert result["duration_s"] == 60


# ── capture_scan: busy interface auto-subscribes ─────────────────────────────


async def test_busy_interface_auto_subscribes_and_reports_the_subscriber_role(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(session("cap_ab12", ["wlanpi0"])),
        subscribed_event("cap_ab12"),
        *pcapng_chunks(BEACON_A),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    assert result["role"] == "subscriber"
    assert result["session_id"] == "cap_ab12"
    assert result["owner"] == "did:test:webui"
    assert result["namespace"] == "capture-ns"
    assert result["config"] == RUNNING_CONFIG  # a subscriber is never blind
    assert result["ap_count"] == 1
    assert "already captured" in result["subscribed_because"]
    # Never configure, start or stop a capture we do not own.
    assert ws.commands == ["auth", "list_sessions", "subscribe"]


async def test_session_on_another_interface_does_not_block_owning(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(session("cap_other", ["wlanpi1"])),
        CONFIG_APPLIED,
        started_event(),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    assert result["role"] == "owner"


async def test_interface_in_use_race_falls_back_to_subscribing(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),  # free at pre-flight time
        CONFIG_APPLIED,
        event(
            "INTERFACE_IN_USE",
            {"message": "Capture interface already in use: wlanpi0"},
            "error",
        ),
        sessions_event(session("cap_raced", ["wlanpi0"])),
        subscribed_event("cap_raced"),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    assert result["role"] == "subscriber"
    assert result["session_id"] == "cap_raced"
    assert "stop" not in ws.commands


async def test_interface_in_use_with_no_session_to_join_is_an_error(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(),
        CONFIG_APPLIED,
        event("INTERFACE_IN_USE", {"message": "already in use: wlanpi0"}, "error"),
        sessions_event(),
    ]
    tools, _ = _register()
    result = await tools["capture_scan"].fn(
        interface="wlanpi0", channels=[6], duration_s=1
    )

    assert "INTERFACE_IN_USE" in result["error"]


# ── capture_observe ──────────────────────────────────────────────────────────


async def test_observe_with_an_explicit_session_id_skips_discovery(ws):
    ws.script = [
        AUTH_OK,
        subscribed_event("cap_ab12"),
        *pcapng_chunks(BEACON_A),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_observe"].fn(session_id="cap_ab12", duration_s=1)

    assert result["role"] == "subscriber"
    assert result["session_id"] == "cap_ab12"
    assert result["config"] == RUNNING_CONFIG
    assert result["interfaces"] == ["wlanpi0"]
    assert result["ap_count"] == 1
    assert ws.commands == ["auth", "subscribe"]  # never stops someone else's capture


async def test_observe_resolves_the_session_by_interface(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(
            session("cap_one", ["wlanpi1"]), session("cap_two", ["wlanpi0"])
        ),
        subscribed_event("cap_two"),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_observe"].fn(interface="wlanpi0", duration_s=1)

    assert result["session_id"] == "cap_two"
    assert ws.payload("subscribe")["session_id"] == "cap_two"


async def test_observe_defaults_to_the_only_running_session(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(session("cap_sole", ["wlanpi3"])),
        subscribed_event("cap_sole"),
        CAPTURE_ENDED,
    ]
    tools, _ = _register()
    result = await tools["capture_observe"].fn(duration_s=1)

    assert result["session_id"] == "cap_sole"


async def test_observe_errors_when_nothing_is_running(ws):
    ws.script = [AUTH_OK, sessions_event()]
    tools, _ = _register()
    result = await tools["capture_observe"].fn(duration_s=1)

    assert "no capture is running" in result["error"]
    assert "subscribe" not in ws.commands


async def test_observe_errors_when_ambiguous(ws):
    ws.script = [
        AUTH_OK,
        sessions_event(session("cap_a", ["wlanpi0"]), session("cap_b", ["wlanpi1"])),
    ]
    tools, _ = _register()
    result = await tools["capture_observe"].fn(duration_s=1)

    assert "cap_a" in result["error"] and "cap_b" in result["error"]
    assert "subscribe" not in ws.commands


async def test_observe_errors_when_the_interface_has_no_capture(ws):
    ws.script = [AUTH_OK, sessions_event(session("cap_a", ["wlanpi1"]))]
    tools, _ = _register()
    result = await tools["capture_observe"].fn(interface="wlanpi0", duration_s=1)

    assert "no capture running on 'wlanpi0'" in result["error"]
    assert "wlanpi1" in result["error"]


async def test_observe_reports_session_not_found(ws):
    ws.script = [
        AUTH_OK,
        event(
            "SESSION_NOT_FOUND",
            {"message": "No running capture session: cap_x"},
            "error",
        ),
    ]
    tools, _ = _register()
    result = await tools["capture_observe"].fn(session_id="cap_x", duration_s=1)

    assert "SESSION_NOT_FOUND" in result["error"]


# ── list_capture_sessions / get_capture_channels ─────────────────────────────


async def test_list_capture_sessions_returns_sessions_verbatim(ws):
    running = session("cap_ab12", ["wlanpi0"])
    ws.script = [AUTH_OK, sessions_event(running)]
    tools, _ = _register()
    result = await tools["list_capture_sessions"].fn()

    assert result == {"sessions": [running], "count": 1}
    assert ws.commands == ["auth", "list_sessions"]
    assert ws.closed is True


async def test_list_capture_sessions_when_none_are_running(ws):
    ws.script = [AUTH_OK, sessions_event()]
    tools, _ = _register()
    assert await tools["list_capture_sessions"].fn() == {"sessions": [], "count": 0}


async def test_get_capture_channels_annotates_channel_numbers(ws):
    ws.script = [
        AUTH_OK,
        event(
            "SUPPORTED_FREQUENCIES",
            {"wlanpi0": [2412, 2437, 5180], "wlanpi1": [], "wlanpi2": [5955]},
        ),
    ]
    tools, _ = _register()
    result = await tools["get_capture_channels"].fn()

    assert result["adapters"]["wlanpi0"]["count"] == 3
    assert result["adapters"]["wlanpi0"]["channels"] == [
        {"freq": 2412, "channel": 1},
        {"freq": 2437, "channel": 6},
        {"freq": 5180, "channel": 36},
    ]
    assert result["adapters"]["wlanpi1"] == {"count": 0, "channels": []}
    assert result["adapters"]["wlanpi2"]["channels"] == [{"freq": 5955, "channel": 1}]


async def test_get_capture_channels_reports_a_fetch_failure(ws):
    ws.script = [
        AUTH_OK,
        event("FREQ_FETCH_FAILED", {"message": "Failed to fetch: boom"}, "error"),
    ]
    tools, _ = _register()
    result = await tools["get_capture_channels"].fn()

    assert "FREQ_FETCH_FAILED" in result["error"]


# ── URL derivation ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "base,expected",
    [
        ("http://localhost:31415", "ws://localhost:31415/api/v1/streaming/capture"),
        (
            "https://wlanpi.local:31416",
            "wss://wlanpi.local:31416/api/v1/streaming/capture",
        ),
        ("http://10.0.0.5:31415/", "ws://10.0.0.5:31415/api/v1/streaming/capture"),
    ],
)
def test_capture_ws_url_derivation(base, expected):
    from wlanpi_mcp.capture.ws_client import capture_ws_url

    assert capture_ws_url(Settings(WLANPI_CORE_URL=base, _env_file=None)) == expected


def test_capture_ws_url_never_carries_the_token():
    from wlanpi_mcp.capture.ws_client import capture_ws_url

    url = capture_ws_url(
        Settings(WLANPI_CORE_URL="http://localhost:31415", _env_file=None)
    )
    assert "token" not in url and "?" not in url


def test_connect_capture_ssl_matches_url_scheme(monkeypatch):
    from wlanpi_mcp.capture import ws_client

    captured: dict[str, object] = {}

    async def fake_connect(url, **_kwargs):
        captured["ssl"] = _kwargs.get("ssl")
        raise OSError("stop")

    monkeypatch.setattr("websockets.connect", fake_connect)

    for base, expect_ssl in (
        ("https://localhost:31415", True),
        ("http://localhost:31415", False),
    ):
        with pytest.raises(ws_client.CaptureError):
            asyncio.run(
                ws_client.connect_capture(
                    Settings(WLANPI_CORE_URL=base, _env_file=None)
                )
            )
        if expect_ssl:
            assert isinstance(captured["ssl"], ssl.SSLContext)
        else:
            assert captured["ssl"] is None
