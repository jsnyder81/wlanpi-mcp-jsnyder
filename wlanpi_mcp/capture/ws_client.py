"""
Async driver for the wlanpi-core capture WebSocket.

Protocol (wlanpi-core `/api/v1/streaming/capture`):

* every client -> server message is JSON text; the **first** one must be
  ``{"command": "auth", "token": "<core JWT>"}``. The server answers with the
  ``AUTH_OK`` event or closes with code 4401 (bad token, 10 s timeout, or a
  token in the query string — which is why the token never goes in the URL).
* later commands: ``get_supported_frequencies``, ``configure``, ``start``,
  ``stop``, ``subscribe``, ``unsubscribe``, ``list_sessions``.
* server -> client: binary frames are raw pcapng bytes in unaligned chunks;
  text frames are ``{"type","event","code","data"}`` events.

A capture lives with the socket that owns it: closing the socket stops the
capture. Owner flows must therefore ``stop()`` and close in a ``finally`` —
this server never leaves an ownerless capture running on the device.

The flows here are adapted from wlanpi-core
`tools/capture_harness/capture_harness.py`.
"""

import asyncio
import json
import logging
import re
import time
from collections.abc import Sequence
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

from wlanpi_mcp.capture.dot11 import (
    FrameLog,
    ScanTable,
    freq_to_channel,
    parse_beacon,
    parse_frame,
)
from wlanpi_mcp.capture.pcapng import PcapngReader
from wlanpi_mcp.client.tls import core_ssl_context

log = logging.getLogger(__name__)

__all__ = [
    "CAPTURE_WS_PATH",
    "CaptureError",
    "CaptureSocket",
    "capture_ws_url",
    "connect_capture",
]

CAPTURE_WS_PATH = "/api/v1/streaming/capture"

#: Core allows 10 s for the auth handshake; use the same budget for the short
#: request/response commands so a wedged server surfaces as a tool error.
COMMAND_TIMEOUT = 10.0

#: Error events that describe a degraded capture rather than a failed command.
#: Channel hopping fails routinely on single-radio devices while the managed
#: interface holds the phy, so these are collected and reported, not raised.
NON_FATAL_ERROR_CODES = frozenset({"CHANNEL_SET_FAILED", "CHANNEL_HOP_ERROR"})

#: Events meaning "the capture is over; stop consuming".
END_CODES = frozenset({"CAPTURE_ENDED", "CAPTURE_STOPPED"})

_FREQ_IN_MESSAGE = re.compile(r"(\d{4})\s*MHz")


class CaptureError(Exception):
    """A capture WebSocket command failed. ``code`` is the core event code."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def capture_ws_url(settings: Any) -> str:
    """Derive the capture WebSocket URL from ``Settings.WLANPI_CORE_URL``."""
    parts = urlsplit(settings.WLANPI_CORE_URL)
    scheme = {"https": "wss", "wss": "wss"}.get(parts.scheme, "ws")
    netloc = parts.netloc or parts.path
    return urlunsplit((scheme, netloc, CAPTURE_WS_PATH, "", ""))


async def connect_capture(settings: Any) -> "CaptureSocket":
    """Open the capture WebSocket. The single seam tests monkeypatch."""
    import websockets

    url = capture_ws_url(settings)
    ssl_ctx = core_ssl_context(settings) if url.startswith("wss://") else None
    try:
        # ping_interval=None: this is a bounded streaming consumer with its own
        # deadline, and a continuous binary pcapng stream can delay pong replies
        # enough to trip the default 20 s keepalive timeout and tear a long
        # capture down mid-stream. We rely on our own duration bound instead.
        ws = await websockets.connect(
            url, max_size=None, ping_interval=None, ssl=ssl_ctx
        )
    except Exception as exc:
        raise CaptureError(
            f"could not connect to the capture WebSocket at {url}: {exc}"
        ) from exc
    return CaptureSocket(ws, url=url)


def _closed_reason(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if code is None:
        code = getattr(getattr(exc, "rcvd", None), "code", None)
    if code == 4401:
        return (
            "the server rejected authentication and closed the connection "
            "(4401) — the wlanpi-core token is missing, expired or invalid"
        )
    if code:
        return f"connection closed with code {code}"
    return f"connection closed ({type(exc).__name__}: {exc})"


class CaptureSocket:
    """
    Command/event wrapper around an open capture WebSocket.

    Takes any object exposing async ``send(str)`` / ``recv()`` (and optionally
    ``close()``), so tests can drive it with a scripted stub.
    """

    def __init__(self, ws: Any, url: str = "") -> None:
        self._ws = ws
        self.url = url
        self.did: str | None = None
        self.session_id: str | None = None
        #: The running config core snapshots for the session we own or joined.
        self.session_config: dict[str, Any] | None = None
        #: pcapng chunks that arrived while awaiting an event, replayed by
        #: consume() so no captured bytes are dropped.
        self._pending_binary: list[bytes] = []
        #: CHANNEL_SET_FAILED / CHANNEL_HOP_ERROR seen on this socket.
        self.channel_issues: list[dict[str, Any]] = []
        self.channel_sets = 0
        self._ended = False

    # -- plumbing ---------------------------------------------------------

    async def _send(self, payload: dict[str, Any]) -> None:
        try:
            await self._ws.send(json.dumps(payload))
        except Exception as exc:
            raise CaptureError(
                f"could not send '{payload.get('command')}' to the capture "
                f"WebSocket: {_closed_reason(exc)}"
            ) from exc

    def _record_event(self, event: dict[str, Any]) -> None:
        code = event.get("code")
        data = event.get("data") or {}
        if code == "CHANNEL_SET":
            self.channel_sets += 1
            return
        if code in NON_FATAL_ERROR_CODES:
            message = data.get("message") or code
            match = _FREQ_IN_MESSAGE.search(str(message))
            freq = int(match.group(1)) if match else None
            self.channel_issues.append(
                {
                    "code": code,
                    "message": message,
                    "freq": freq,
                    "channel": freq_to_channel(freq) if freq else None,
                }
            )
        elif code in END_CODES:
            self._ended = True

    async def _next_event(self, timeout: float) -> dict[str, Any]:
        """Return the next text event, buffering any binary frames."""
        while True:
            msg = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
            if isinstance(msg, (bytes, bytearray, memoryview)):
                self._pending_binary.append(bytes(msg))
                continue
            try:
                event = json.loads(msg)
            except (TypeError, ValueError):
                log.debug("Ignoring non-JSON capture text frame: %r", msg)
                continue
            if isinstance(event, dict):
                return event

    async def _await_code(
        self,
        codes: Sequence[str],
        what: str,
        timeout: float = COMMAND_TIMEOUT,
    ) -> dict[str, Any]:
        """
        Wait for one of ``codes`` and return its ``data``.

        Informational events (channel hops, config acks) are recorded and
        skipped; a fatal ``event: "error"`` becomes a CaptureError carrying the
        core error code so callers can branch on e.g. INTERFACE_IN_USE.
        """
        wanted = set(codes)
        try:
            while True:
                event = await self._next_event(timeout)
                code = event.get("code")
                data = event.get("data") or {}
                self._record_event(event)
                if code in wanted:
                    return data
                if event.get("event") == "error" and code not in NON_FATAL_ERROR_CODES:
                    message = data.get("message") or json.dumps(data)
                    raise CaptureError(f"{code}: {message}", code=code)
        except CaptureError:
            raise
        except TimeoutError as exc:
            raise CaptureError(
                f"timed out after {timeout:g}s waiting for {what} from the "
                "capture WebSocket"
            ) from exc
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise CaptureError(
                f"capture WebSocket failed while waiting for {what}: "
                f"{_closed_reason(exc)}"
            ) from exc

    # -- commands ---------------------------------------------------------

    async def authenticate(self, token: str) -> str | None:
        """Send the mandatory first auth message; returns the principal did."""
        await self._send({"command": "auth", "token": token})
        data = await self._await_code(["AUTH_OK"], "authentication")
        self.did = data.get("did")
        return self.did

    async def list_sessions(self) -> list[dict[str, Any]]:
        """Return the running capture sessions reported by core."""
        await self._send({"command": "list_sessions"})
        data = await self._await_code(["SESSIONS"], "the session list")
        sessions = data.get("sessions")
        return sessions if isinstance(sessions, list) else []

    async def get_supported_frequencies(self) -> dict[str, Any]:
        """Return the frequencies each capture interface supports."""
        await self._send({"command": "get_supported_frequencies"})
        return await self._await_code(
            ["SUPPORTED_FREQUENCIES"], "the supported frequency list"
        )

    async def configure(self, interfaces_cfg: dict[str, Any]) -> dict[str, Any]:
        """Apply the channel configuration to core and return the applied config."""
        await self._send({"command": "configure", "interfaces": interfaces_cfg})
        return await self._await_code(["CONFIG_APPLIED"], "the capture configuration")

    async def start(self, interfaces: Sequence[str], pcap_filter: str = "") -> str:
        """Start a capture on the given interfaces and return its session id."""
        await self._send(
            {
                "command": "start",
                "interfaces": list(interfaces),
                "pcap_filter": pcap_filter or "",
            }
        )
        data = await self._await_code(["CAPTURE_STARTED"], "the capture to start")
        self.session_id = data.get("session_id")
        self.session_config = data.get("config")
        return self.session_id or ""

    async def subscribe(self, session_id: str) -> dict[str, Any]:
        """Subscribe to a running capture and return its owner, namespace, and config."""
        await self._send({"command": "subscribe", "session_id": session_id})
        data = await self._await_code(["SUBSCRIBED"], "the subscription")
        self.session_id = data.get("session_id") or session_id
        self.session_config = data.get("config")
        return {
            "session_id": self.session_id,
            "owner": data.get("owner"),
            "namespace": data.get("namespace"),
            "interfaces": data.get("interfaces") or [],
            "config": data.get("config"),
        }

    async def stop(self) -> None:
        """Best-effort stop; owner flows call this from a ``finally``."""
        try:
            await self._ws.send(json.dumps({"command": "stop"}))
        except Exception as exc:  # noqa: BLE001
            log.debug("Best-effort capture stop failed: %r", exc)

    async def close(self) -> None:
        """Close the WebSocket, awaiting any coroutine close method."""
        closer = getattr(self._ws, "close", None)
        if closer is None:
            return
        try:
            result = closer()
            if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
                await result
        except Exception as exc:  # noqa: BLE001
            log.debug("Closing the capture WebSocket failed: %r", exc)

    # -- streaming --------------------------------------------------------

    async def consume(
        self,
        reader: PcapngReader,
        table: ScanTable,
        duration_s: float,
        frame_log: FrameLog | None = None,
        raw_sink: Any | None = None,
    ) -> dict[str, Any]:
        """
        Read the stream for ``duration_s``, dissecting frames.

        Beacons/probe-responses are merged into ``table``; when ``frame_log``
        is given, every frame is dissected into it as a per-frame record. When
        ``raw_sink`` is given, each raw pcapng chunk is also written to it
        verbatim (a callable taking ``bytes``, e.g. a file's ``write``) so the
        dissected summary can be verified against the pcapng on disk. Returns a
        summary of the text events seen. Returns early when the capture ends
        (owner stopped, or dumpcap exited).
        """
        deadline = time.monotonic() + duration_s

        for chunk in self._pending_binary:
            if raw_sink is not None:
                raw_sink(chunk)
            self._absorb(chunk, reader, table, frame_log)
        self._pending_binary.clear()

        stream_closed = False
        while not self._ended:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                msg = await asyncio.wait_for(self._ws.recv(), timeout=remaining)
            except TimeoutError:
                break
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                # The stream ending is normal (the owner stopped, the socket
                # closed); return what was captured rather than failing.
                log.debug("Capture stream ended: %r", exc)
                stream_closed = True
                break
            if isinstance(msg, (bytes, bytearray, memoryview)):
                data = bytes(msg)
                if raw_sink is not None:
                    raw_sink(data)
                self._absorb(data, reader, table, frame_log)
            elif isinstance(msg, str):
                try:
                    event = json.loads(msg)
                except (TypeError, ValueError):
                    continue
                if isinstance(event, dict):
                    self._record_event(event)

        return {
            "channel_issues": list(self.channel_issues),
            "channel_sets": self.channel_sets,
            "other_frames": table.other,
            "capture_ended": self._ended,
            "stream_closed": stream_closed,
        }

    async def consume_raw(
        self,
        sink: Any,
        duration_s: float,
        stop_event: Optional["asyncio.Event"] = None,
    ) -> dict[str, Any]:
        """
        Stream raw pcapng bytes to ``sink`` for up to ``duration_s`` seconds.

        Unlike :meth:`consume`, this does not dissect: every binary chunk is
        written verbatim, so the accumulated bytes are a valid pcapng file.
        ``sink`` is any callable taking ``bytes`` (e.g. a binary file's
        ``write``). Returns early when the capture ends (owner stopped, dumpcap
        exited) or ``stop_event`` is set. Text events are still recorded, so
        ``channel_issues`` stays populated. The loop wakes at least once a
        second so an early stop is honoured even when no frames are arriving.
        """
        deadline = time.monotonic() + duration_s
        bytes_written = 0

        for chunk in self._pending_binary:
            sink(chunk)
            bytes_written += len(chunk)
        self._pending_binary.clear()

        stream_closed = False
        while not self._ended:
            if stop_event is not None and stop_event.is_set():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                msg = await asyncio.wait_for(
                    self._ws.recv(), timeout=min(remaining, 1.0)
                )
            except TimeoutError:
                # Wake to re-check the deadline and stop_event; not the end.
                continue
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                # The stream ending is normal (owner stopped, socket closed);
                # return what was written rather than failing.
                log.debug("Capture stream ended: %r", exc)
                stream_closed = True
                break
            if isinstance(msg, (bytes, bytearray, memoryview)):
                data = bytes(msg)
                sink(data)
                bytes_written += len(data)
            elif isinstance(msg, str):
                try:
                    event = json.loads(msg)
                except (TypeError, ValueError):
                    continue
                if isinstance(event, dict):
                    self._record_event(event)

        return {
            "channel_issues": list(self.channel_issues),
            "channel_sets": self.channel_sets,
            "bytes_written": bytes_written,
            "capture_ended": self._ended,
            "stream_closed": stream_closed,
        }

    @staticmethod
    def _absorb(
        chunk: bytes,
        reader: PcapngReader,
        table: ScanTable,
        frame_log: FrameLog | None = None,
    ) -> None:
        for _linktype, ts, pkt in reader.feed(chunk):
            ap = parse_beacon(pkt)
            if ap:
                table.update(ap)
            else:
                table.other += 1
            if frame_log is not None:
                record = parse_frame(pkt)
                if record is not None:
                    frame_log.add(record, ts)


def sessions_on_interface(
    sessions: Sequence[dict[str, Any]], interface: str
) -> list[dict[str, Any]]:
    """List sessions capturing on ``interface`` (one owner per interface)."""
    return [s for s in sessions if interface in (s.get("interfaces") or [])]
