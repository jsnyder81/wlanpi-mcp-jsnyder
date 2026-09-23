"""
Wi-Fi packet-capture tools backed by the wlanpi-core capture WebSocket.

wlanpi-core exposes capture only over `/api/v1/streaming/capture`, so these
tools open that socket, authenticate with the same wlanpi-core JWT used for
every REST call, run a bounded capture, and return a dissected summary. A
capture lives with its socket: the owner flow always stops the capture and
closes the socket before returning, so no ownerless capture is left running.
"""

import logging
from typing import Any

from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.capture import storage
from wlanpi_mcp.capture.dot11 import (
    DEFAULT_MAX_FRAMES,
    FrameLog,
    ScanTable,
    channel_to_freq,
    freq_to_channel,
)
from wlanpi_mcp.capture.pcapng import PcapngReader
from wlanpi_mcp.capture.ws_client import (
    CaptureError,
    CaptureSocket,
    connect_capture,
    sessions_on_interface,
)
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import get_settings

log = logging.getLogger(__name__)

DEFAULT_DURATION_S = 10
MAX_DURATION_S = 60
#: Extra margin, beyond the capture window, an owner keeps the socket open after
#: sending 'stop' — stopping flushes dumpcap's final buffered frames and yields
#: a CAPTURE_STOPPED confirmation, so closing the instant the window ends would
#: truncate the tail. The drain returns as soon as the capture confirms it
#: ended, so this is an upper bound, not a fixed wait.
STOP_DRAIN_S = 5
VALID_WIDTHS = (20, 40, 80, 160)
MIN_DWELL_MS = 50
MAX_DWELL_MS = 60000

#: Anything at or above this is treated as an explicit frequency in MHz rather
#: than a channel number (6 GHz channels have no unambiguous number mapping).
FREQ_THRESHOLD_MHZ = 1000

SINGLE_RADIO_HINT = (
    "Channel changes failed during this capture. When the capture interface "
    "shares its radio with a managed interface (such as wlan0), retuning fails "
    "with 'Device or resource busy' while that interface scans, so the listed "
    "channels were not all visited — this result is partial. Take the managed "
    "interface down or use a second adapter for reliable multi-channel capture."
)


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _collect_freqs(node: Any) -> list[int]:
    """Pull frequencies in MHz out of a supported-frequency payload."""
    out: list[int] = []

    def walk(item: Any) -> None:
        if isinstance(item, bool):
            return
        if isinstance(item, int):
            if 2000 <= item <= 7300:
                out.append(item)
            return
        if isinstance(item, dict):
            for key in ("freq", "frequency", "center_freq", "freq_mhz"):
                value = item.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    out.append(value)
                    return
            for value in item.values():
                walk(value)
            return
        if isinstance(item, (list, tuple)):
            for value in item:
                walk(value)

    walk(node)
    seen = set()
    unique = []
    for freq in out:
        if freq not in seen:
            seen.add(freq)
            unique.append(freq)
    return unique


def _freqs_by_adapter(data: Any) -> dict[str, list[int]]:
    """
    Normalise SUPPORTED_FREQUENCIES data to {interface: [freq, ...]}.

    Core sends the interface map directly; wrappers are tolerated.
    """
    if not isinstance(data, dict):
        return {}
    for key in ("frequencies", "interfaces", "adapters", "supported_frequencies"):
        inner = data.get(key)
        if isinstance(inner, dict):
            data = inner
            break
    return {
        name: _collect_freqs(value)
        for name, value in data.items()
        if isinstance(name, str)
    }


def _resolve_adapter(
    by_adapter: dict[str, list[int]], interface: str | None
) -> tuple[str, list[int]] | dict[str, Any]:
    """
    Pick the capture interface and its frequencies from core's adapter list.

    With no interface given, the device's only usable adapter is chosen; with
    several, the caller gets a 'needsSelection' result to return instead. An
    explicit interface must be one core reports, never swapped for another.
    Returns (interface, freqs), or a result dict to hand back as-is.
    """
    usable = {name: freqs for name, freqs in by_adapter.items() if freqs}
    if interface is None:
        if len(usable) == 1:
            return next(iter(usable.items()))
        if not usable:
            return {"error": "no capture interfaces reported by this device"}
        return {
            "needsSelection": True,
            "candidates": [
                {"interface": name, "channel_count": len(freqs)}
                for name, freqs in sorted(usable.items())
            ],
            "message": (
                "this device has several capture interfaces; call again with "
                "one of the candidates as 'interface' (get_capture_channels "
                "shows each one's channels)"
            ),
        }
    freqs = usable.get(interface)
    if not freqs:
        return {
            "error": (
                f"no supported frequencies reported for '{interface}'. "
                f"Capture interfaces on this device: {sorted(usable) or 'none'}"
            )
        }
    return interface, freqs


def _channels_to_freqs(channels: list[int]) -> list[int]:
    """Map channel numbers (or explicit MHz values) to frequencies."""
    freqs = []
    for channel in channels:
        value = int(channel)
        freqs.append(value if value >= FREQ_THRESHOLD_MHZ else channel_to_freq(value))
    return freqs


def _annotate(freqs: list[int]) -> list[dict[str, Any]]:
    return [{"freq": f, "channel": freq_to_channel(f)} for f in freqs]


async def _run_window(
    sock: CaptureSocket,
    duration_s: int,
    frame_log: FrameLog,
    *,
    owner: bool = False,
    raw_sink: Any = None,
) -> tuple[ScanTable, dict[str, Any]]:
    table = ScanTable()
    reader = PcapngReader()
    events = await sock.consume(reader, table, duration_s, frame_log, raw_sink)
    if owner and not events.get("capture_ended"):
        # The capture window is over. Ask core to stop, then keep dissecting
        # for a bounded margin: 'stop' flushes dumpcap's final frames and emits
        # CAPTURE_STOPPED, and closing the socket the instant the window ended
        # would cut those off. The same reader is reused so pcapng blocks that
        # span the window boundary still parse. Drains early on CAPTURE_STOPPED.
        window_ended = events.get("capture_ended", False)
        window_closed = events.get("stream_closed", False)
        await sock.stop()
        events = await sock.consume(reader, table, STOP_DRAIN_S, frame_log, raw_sink)
        # The drain always ends via our own stop (CAPTURE_STOPPED), so its
        # end flags describe the stop, not the capture. Keep the window's own
        # signal so 'capture_ended_early' means the capture died on its own,
        # not that we stopped it normally. Counts stay cumulative.
        events["capture_ended"] = window_ended
        events["stream_closed"] = window_closed
    return table, events


async def _run_and_save(
    sock: CaptureSocket,
    duration_s: int,
    frame_log: FrameLog,
    capture_id: str,
    *,
    owner: bool,
) -> tuple[ScanTable, dict[str, Any], dict[str, Any]]:
    """
    Run a capture window while teeing the raw pcapng to a file.

    The file lets the dissected summary be verified against the frames.
    Writing is best-effort — a storage problem never breaks the capture — and
    the file is always closed. Returns ``(table, events, pcap_extra)`` where
    pcap_extra carries ``pcap_path``/``pcap_bytes`` when the file was written.
    """
    path, fileobj = storage.try_open_capture_file(capture_id)
    sink = fileobj.write if fileobj is not None else None
    try:
        table, events = await _run_window(
            sock, duration_s, frame_log, owner=owner, raw_sink=sink
        )
    finally:
        if fileobj is not None:
            try:
                fileobj.close()
            except OSError as exc:
                log.debug("closing capture file failed: %r", exc)
    extra = {"pcap_path": path, "pcap_bytes": storage.file_size(path)} if path else {}
    return table, events, extra


def _summary(
    role: str,
    table: ScanTable,
    events: dict[str, Any],
    frame_log: FrameLog,
    **extra: Any,
) -> dict[str, Any]:
    aps = table.to_result()
    result = {
        "role": role,
        **extra,
        "ap_count": len(aps),
        "aps": aps,
        "other_frames": events.get("other_frames", 0),
        "channel_issues": events.get("channel_issues", []),
        "capture_ended_early": bool(
            events.get("capture_ended") or events.get("stream_closed")
        ),
        **frame_log.to_result(),
    }
    if result["channel_issues"]:
        result["note"] = SINGLE_RADIO_HINT
    return result


def register(mcp: FastMCP, client: CoreClient) -> None:
    """Register the streaming capture tools."""

    @mcp.tool()
    async def capture_scan(
        interface: str | None = None,
        channels: list[int] | None = None,
        width: int = 20,
        dwell_ms: int = 250,
        duration_s: int = DEFAULT_DURATION_S,
        pcap_filter: str = "",
        max_frames: int = DEFAULT_MAX_FRAMES,
    ) -> dict[str, Any]:
        """
        Run a live streaming Wi-Fi packet capture and return what was on the air.

        This is a streaming capture: it captures real 802.11 frames off the air
        (unlike scan_wlan, which asks the driver for a scan), so it reports what
        is actually being transmitted. The call blocks for duration_s seconds
        and returns a dissected summary. The raw pcapng is also saved on the
        device and its path returned in 'pcap_path' (fetch it with
        fetch_pcap_file to verify the summary against the frames). For a capture
        longer than the 60 s window, use the non-streaming file-capture tools
        (start_pcap_file/fetch_pcap_file) instead.

        The result has two parts:
        - 'aps': one row per BSSID from beacons/probe-responses, with SSID,
          channel, signal, 802.11 amendments, advertised TX power, full
          security detail — the compact 'security' label plus 'akm' (the AKM
          suite list), 'pairwise_ciphers', 'group_cipher' and 'pmf' — and,
          when the AP advertises a QBSS/BSS Load element, 'stations' (the
          associated client count) and 'channel_utilization' (percent).
        - 'frames' / 'frame_types': every frame's named type/subtype counted
          exactly in 'frame_types', plus up to max_frames per-frame records in
          'frames'. Each record has the source/destination addresses
          (addr1..addr4), a full radiotap decode, and — for the frames that
          carry one — a decoded 'result': authentication algorithm+status,
          association status+AID, deauth/disassoc reason, or probe/assoc SSID.

        The capture is owned by this call and is stopped before it returns.
        If another application is already capturing on the interface, this
        tool subscribes to that capture read-only instead of failing; the
        result always says whether the role was 'owner' or 'subscriber' and
        reports the running config.

        Single-radio caveat: where the capture interface shares a radio with
        a managed interface (such as wlan0), channel changes fail while that
        interface scans. Any such failures come back in 'channel_issues' —
        treat those results as partial rather than complete.

        Args:
            interface: A capture interface as listed by get_capture_channels
                (the device's monitor-mode interfaces, not the managed wlanN
                ones). Omit it to use the device's only capture interface; if
                there are several, the call returns 'needsSelection' with the
                candidates instead of capturing. Do not infer the name from
                wlan0/wlan1 numbering — take it from that list.
            channels: Channel numbers to hop (e.g. [1, 6, 11, 36]); 6 GHz can
                be given as explicit frequencies in MHz. Omit to hop every
                channel the adapter supports.
            width: Channel width in MHz: 20, 40, 80 or 160.
            dwell_ms: Milliseconds to dwell on each channel (50-60000).
            duration_s: How long to capture, 1-60 seconds. The tool call
                blocks for this whole window.
            pcap_filter: Optional BPF/pcap filter, e.g. 'type mgt subtype beacon'.
            max_frames: Cap on per-frame records returned in 'frames';
                per-kind counts in 'frame_types' are always exact. Set 0 to
                skip the per-frame records and get only the AP table and
                counts, or a negative value for no cap (every frame — a busy
                capture can then return tens of thousands of records, so use
                the file-capture tools for a full pcap instead). Beacons
                dominate a busy capture, so a pcap_filter such as 'not type mgt
                subtype beacon' makes the record list focus on the
                control/data/auth exchanges.
        """
        if width not in VALID_WIDTHS:
            return {"error": f"width must be one of {list(VALID_WIDTHS)}, got {width}"}
        duration_s = _clamp(int(duration_s), 1, MAX_DURATION_S)
        dwell_ms = _clamp(int(dwell_ms), MIN_DWELL_MS, MAX_DWELL_MS)
        frame_log = FrameLog(int(max_frames))

        try:
            token = client.current_token()
        except RuntimeError as exc:
            return {"error": str(exc)}

        try:
            sock = await connect_capture(get_settings())
        except CaptureError as exc:
            return {"error": str(exc)}

        owns = False
        owner_stopped = False
        try:
            await sock.authenticate(token)

            by_adapter = None
            if interface is None:
                by_adapter = _freqs_by_adapter(await sock.get_supported_frequencies())
                picked = _resolve_adapter(by_adapter, None)
                if isinstance(picked, dict):
                    return picked
                interface = picked[0]

            # Own-vs-subscribe pre-flight: one owner per interface, so a
            # running session on this interface means start would fail with
            # INTERFACE_IN_USE.
            existing = sessions_on_interface(await sock.list_sessions(), interface)

            if not existing:
                if channels:
                    try:
                        freqs = _channels_to_freqs(channels)
                    except (TypeError, ValueError) as exc:
                        return {"error": str(exc)}
                else:
                    if by_adapter is None:
                        by_adapter = _freqs_by_adapter(
                            await sock.get_supported_frequencies()
                        )
                    picked = _resolve_adapter(by_adapter, interface)
                    if isinstance(picked, dict):
                        return picked
                    freqs = picked[1]

                config = {
                    interface: {
                        "channels": [{"freq": f, "width": width} for f in freqs],
                        "dwell_time": dwell_ms,
                    }
                }
                await sock.configure(config)
                try:
                    session_id = await sock.start([interface], pcap_filter)
                    owns = True
                except CaptureError as exc:
                    if exc.code != "INTERFACE_IN_USE":
                        raise
                    # Raced with another owner between list_sessions and start.
                    existing = sessions_on_interface(
                        await sock.list_sessions(), interface
                    )
                    if not existing:
                        raise

            if owns:
                table, events, pcap = await _run_and_save(
                    sock, duration_s, frame_log, session_id, owner=True
                )
                # _run_window already stopped the capture (or it ended on its
                # own), so the finally must not send a second stop.
                owner_stopped = True
                return _summary(
                    "owner",
                    table,
                    events,
                    frame_log,
                    session_id=session_id,
                    interface=interface,
                    duration_s=duration_s,
                    # Prefer core's snapshot of the running config over ours.
                    config=sock.session_config
                    or {"interfaces": config, "pcap_filter": pcap_filter or ""},
                    **pcap,
                )

            info = await sock.subscribe(existing[0]["session_id"])
            table, events, pcap = await _run_and_save(
                sock, duration_s, frame_log, info["session_id"], owner=False
            )
            return _summary(
                "subscriber",
                table,
                events,
                frame_log,
                session_id=info["session_id"],
                interface=interface,
                duration_s=duration_s,
                owner=info["owner"],
                namespace=info["namespace"],
                config=info["config"],
                subscribed_because=(
                    f"'{interface}' is already captured by session "
                    f"{info['session_id']}; joined it read-only instead of "
                    "taking it over"
                ),
                **pcap,
            )
        except CaptureError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            log.exception("capture_scan failed")
            return {"error": f"capture failed: {type(exc).__name__}: {exc}"}
        finally:
            # Exception path: if we owned a capture but did not reach the
            # graceful stop, stop it now so no ownerless capture is left.
            if owns and not owner_stopped:
                await sock.stop()
            await sock.close()

    @mcp.tool()
    async def capture_observe(
        interface: str | None = None,
        session_id: str | None = None,
        duration_s: int = DEFAULT_DURATION_S,
        max_frames: int = DEFAULT_MAX_FRAMES,
    ) -> dict[str, Any]:
        """
        Watch a streaming capture another application is already running, read-only.

        Use this streaming subscriber to see what a capture started elsewhere
        (the WebUI, a lab controller, another agent) is receiving, without
        taking control of it. This never starts, reconfigures or stops a
        capture; the role in the result is always 'subscriber'. The result
        includes the owner's running config (channels, width, dwell, filter),
        so it is clear what the summary does and does not cover.

        Returns the same dissected summary as capture_scan (an 'aps' table with
        full security detail, plus per-frame 'frames'/'frame_types' with
        addresses, radiotap and decoded results). The raw pcapng is also saved
        on the device and its path returned in 'pcap_path' (fetch it with
        fetch_pcap_file). Use list_capture_sessions first if you want to see
        what is running.

        Single-radio caveat: the owner's channel hopping can fail on devices
        where the capture interface shares a radio with a managed interface, so
        an observed capture may cover fewer channels than its config lists.

        Args:
            session_id: Session to attach to (from list_capture_sessions).
            interface: Instead of a session id, the monitor-mode capture
                interface whose capture to watch (see list_capture_sessions).
            duration_s: How long to listen, 1-60 seconds. The tool call blocks
                for this whole window.
            max_frames: Cap on per-frame records in 'frames'; the
                'frame_types' counts are always exact. Set 0 for AP table and
                counts only, or a negative value for no cap (every frame).
        """
        duration_s = _clamp(int(duration_s), 1, MAX_DURATION_S)
        frame_log = FrameLog(int(max_frames))

        try:
            token = client.current_token()
        except RuntimeError as exc:
            return {"error": str(exc)}

        try:
            sock = await connect_capture(get_settings())
        except CaptureError as exc:
            return {"error": str(exc)}

        try:
            await sock.authenticate(token)

            target = session_id
            if not target:
                sessions = await sock.list_sessions()
                if not sessions:
                    return {
                        "error": (
                            "no capture is running on this device. Start one "
                            "with capture_scan, or check list_capture_sessions."
                        )
                    }
                if interface:
                    matches = sessions_on_interface(sessions, interface)
                    if not matches:
                        running = sorted(
                            {i for s in sessions for i in (s.get("interfaces") or [])}
                        )
                        return {
                            "error": (
                                f"no capture running on '{interface}'. "
                                f"Captures are running on: {running}"
                            )
                        }
                    target = matches[0]["session_id"]
                elif len(sessions) == 1:
                    target = sessions[0]["session_id"]
                else:
                    return {
                        "error": (
                            f"{len(sessions)} captures are running; pass "
                            "session_id or interface to pick one: "
                            f"{[s.get('session_id') for s in sessions]}"
                        )
                    }

            info = await sock.subscribe(target)
            table, events, pcap = await _run_and_save(
                sock, duration_s, frame_log, info["session_id"], owner=False
            )
            return _summary(
                "subscriber",
                table,
                events,
                frame_log,
                session_id=info["session_id"],
                duration_s=duration_s,
                owner=info["owner"],
                namespace=info["namespace"],
                interfaces=info["interfaces"],
                config=info["config"],
                **pcap,
            )
        except CaptureError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            log.exception("capture_observe failed")
            return {"error": f"capture failed: {type(exc).__name__}: {exc}"}
        finally:
            await sock.close()

    @mcp.tool()
    async def list_capture_sessions() -> dict[str, Any]:
        """
        List the packet captures currently running on this WLAN Pi.

        Each session reports its session_id, the owning principal, the
        monitor-mode capture interfaces it holds, its network namespace,
        and the running config (channels, width, dwell, pcap filter). A
        session's interface cannot be captured on by anyone else — use
        capture_observe to watch it read-only.
        """
        try:
            token = client.current_token()
        except RuntimeError as exc:
            return {"error": str(exc)}

        try:
            sock = await connect_capture(get_settings())
        except CaptureError as exc:
            return {"error": str(exc)}

        try:
            await sock.authenticate(token)
            sessions = await sock.list_sessions()
            return {"sessions": sessions, "count": len(sessions)}
        except CaptureError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            log.exception("list_capture_sessions failed")
            return {"error": f"capture failed: {type(exc).__name__}: {exc}"}
        finally:
            await sock.close()

    @mcp.tool()
    async def get_capture_channels() -> dict[str, Any]:
        """
        List the channels each capture adapter on this WLAN Pi can tune to.

        This is the device's list of capture interfaces: only the names it
        returns can be passed to capture_scan or start_pcap_file. The
        answer is namespace-aware and comes from the adapter's own radio, so
        it reflects the regulatory domain in force. Use it to pick the
        'interface' and 'channels' arguments for capture_scan.

        Each entry gives the frequency in MHz plus its channel number (6 GHz
        frequencies may have no channel number, in which case pass the
        frequency to capture_scan directly).
        """
        try:
            token = client.current_token()
        except RuntimeError as exc:
            return {"error": str(exc)}

        try:
            sock = await connect_capture(get_settings())
        except CaptureError as exc:
            return {"error": str(exc)}

        try:
            await sock.authenticate(token)
            by_adapter = _freqs_by_adapter(await sock.get_supported_frequencies())
            return {
                "adapters": {
                    name: {
                        "count": len(freqs),
                        "channels": _annotate(freqs),
                    }
                    for name, freqs in by_adapter.items()
                }
            }
        except CaptureError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            log.exception("get_capture_channels failed")
            return {"error": f"capture failed: {type(exc).__name__}: {exc}"}
        finally:
            await sock.close()
