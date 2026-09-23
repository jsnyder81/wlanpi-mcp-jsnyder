"""
Non-streaming, file-backed Wi-Fi capture tools.

Where the streaming tools capture_scan/capture_observe run a bounded window and
return a dissected summary, these run a capture in the *background* — holding
the wlanpi-core
capture WebSocket open past the tool call — and write the raw pcapng byte
stream to a file in a managed directory on the device. That lifts the 60 s
window cap (a returned summary must stay small; a file need not) so a capture
can run for minutes, and a later fetch hands the file back to the client as a
pcapng blob for analysis in Wireshark/tshark.

This deliberately relaxes two capture invariants (see CLAUDE.md): the result is
raw pcapng, not a dissected summary, and it writes and then reads a local file.
Both are scoped tightly — every file lives under PCAP_CAPTURE_DIR, and the
fetch tool refuses any path outside it — and the bytes still come only from the
core capture WebSocket: no local subprocess, no other transport, same JWT.
"""

import asyncio
import base64
import glob
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from mcp.types import BlobResourceContents, EmbeddedResource
from pydantic import AnyUrl

from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.capture import storage
from wlanpi_mcp.capture.ws_client import (
    CaptureError,
    CaptureSocket,
    connect_capture,
    sessions_on_interface,
)
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import get_settings
from wlanpi_mcp.tools.capture import (
    MAX_DWELL_MS,
    MIN_DWELL_MS,
    VALID_WIDTHS,
    _channels_to_freqs,
    _clamp,
    _freqs_by_adapter,
    _resolve_adapter,
)

log = logging.getLogger(__name__)

PCAP_MIME = "application/vnd.tcpdump.pcapng"


@dataclass
class FileCapture:
    """A background file-backed capture and its running state."""

    session_id: str
    interface: str
    path: str
    duration_s: int
    started_at: float
    stop_event: asyncio.Event
    config: dict[str, Any] | None = None
    task: asyncio.Task[Any] | None = None
    status: str = "running"  # running | completed | stopped | error | cancelled
    bytes_written: int = 0
    error: str | None = None
    ended_at: float | None = None
    channel_issues: list[dict[str, Any]] = field(default_factory=list)

    def to_result(self) -> dict[str, Any]:
        """Return the capture's public state as a JSON-safe result dict."""
        out = {
            # capture_id is the handle callers pass back to fetch/stop. It is
            # core's session id, but not named 'session_id' on purpose: that
            # name collided with the legacy MCP SSE transport's reserved
            # routing query param and some clients dropped a tool arg sharing
            # it. Streamable HTTP carries its session in a header, but the
            # name and the alias stay for existing callers.
            "capture_id": self.session_id,
            "session_id": self.session_id,
            "interface": self.interface,
            "path": self.path,
            "status": self.status,
            "duration_s": self.duration_s,
            "started_at": self.started_at,
            "size_bytes": _safe_size(self.path),
            "bytes_written": self.bytes_written,
        }
        if self.config is not None:
            out["config"] = self.config
        if self.channel_issues:
            out["channel_issues"] = self.channel_issues
        if self.ended_at is not None:
            out["ended_at"] = self.ended_at
        if self.error:
            out["error"] = self.error
        return out


#: Live file captures, keyed by core session_id. Persists across tool calls for
#: the life of the server process (the whole point: the capture outlives the
#: start call).
_CAPTURES: dict[str, FileCapture] = {}


def _safe_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


# The capture directory, filename scheme and path-confinement check live in
# wlanpi_mcp.capture.storage, shared with the streaming tools.
_capture_dir = storage.capture_dir
_within_capture_dir = storage.within_capture_dir


def _resolve_session_path(session_id: str) -> str | None:
    """
    Return the file path for a capture id.

    Looks in the registry first, then on disk, so a fetch by capture id still
    works when the registry has forgotten it.
    """
    entry = _CAPTURES.get(session_id)
    if entry is not None:
        return entry.path
    safe = storage.safe_component(session_id)
    matches = sorted(
        glob.glob(os.path.join(storage.capture_dir(), f"capture-*-{safe}.pcapng"))
    )
    return matches[-1] if matches else None


def _disk_captures() -> list[dict[str, Any]]:
    """Capture files present on disk but not (any longer) in the registry."""
    known = {os.path.realpath(e.path) for e in _CAPTURES.values()}
    try:
        files = glob.glob(os.path.join(storage.capture_dir(), "capture-*.pcapng"))
    except OSError:
        files = []
    out = []
    for path in sorted(files):
        resolved = os.path.realpath(path)
        if resolved in known:
            continue
        cid = storage.session_from_filename(os.path.basename(resolved))
        out.append(
            {
                "capture_id": cid,
                "session_id": cid,
                "path": resolved,
                "status": "on_disk",
                "size_bytes": _safe_size(resolved),
            }
        )
    return out


async def _run_file_capture(
    entry: FileCapture,
    sock: CaptureSocket,
    fileobj: Any,
) -> None:
    """Own the socket and file for the capture's life, then always clean up."""

    def sink(data: bytes) -> None:
        # Count as we write so bytes_written tracks progress live, not only at
        # completion (the file is unbuffered, so size_bytes advances too).
        entry.bytes_written += len(data)
        fileobj.write(data)

    try:
        events = await sock.consume_raw(sink, entry.duration_s, entry.stop_event)
        entry.channel_issues = events.get("channel_issues", [])
        # stop_event set means we were asked to stop early.
        entry.status = "stopped" if entry.stop_event.is_set() else "completed"
    except asyncio.CancelledError:
        entry.status = "cancelled"
        raise
    except Exception as exc:
        entry.status = "error"
        entry.error = f"{type(exc).__name__}: {exc}"
        log.exception("file capture %s failed", entry.session_id)
    finally:
        try:
            fileobj.close()
        except Exception as exc:  # noqa: BLE001
            log.debug("closing capture file failed: %r", exc)
        entry.bytes_written = entry.bytes_written or _safe_size(entry.path)
        # Never leave an ownerless capture: stop it and drop the socket.
        try:
            await sock.stop()
        except Exception as exc:  # noqa: BLE001
            log.debug("best-effort stop failed: %r", exc)
        await sock.close()
        entry.ended_at = time.time()


def register(mcp: FastMCP, client: CoreClient) -> None:
    """Register the non-streaming, file-backed capture tools."""

    @mcp.tool()
    async def start_pcap_file(
        interface: str | None = None,
        channels: list[int] | None = None,
        width: int = 20,
        dwell_ms: int = 250,
        duration_s: int = 60,
        pcap_filter: str = "",
    ) -> dict[str, Any]:
        """
        Start a background, non-streaming packet capture to a pcapng file.

        This is the non-streaming counterpart to capture_scan: unlike that
        streaming tool, it does not block and does not return a dissected
        summary. It starts a capture, keeps the core WebSocket open in the
        background, and writes the raw pcapng bytes to a file under a managed
        directory on the device. Because nothing is held in memory or returned
        inline, the capture can run far longer than the 60 s capture_scan
        window — up to the server's configured maximum. The call returns
        immediately with the capture_id and file path; the capture then runs on
        its own until duration_s elapses or you call stop_pcap_file. Retrieve
        the file with fetch_pcap_file(capture_id=...) (a pcapng blob) once it
        has stopped.

        This tool always owns the interface. If a capture is already running on
        it, this returns an error rather than taking it over — watch that one
        with capture_observe instead.

        Args:
            interface: A capture interface as listed by get_capture_channels
                (the device's monitor-mode interfaces, not the managed wlanN
                ones). Omit it to use the device's only capture interface; if
                there are several, the call returns 'needsSelection' with the
                candidates instead of starting.
            channels: Channel numbers to hop (e.g. [1, 6, 11, 36]); 6 GHz can be
                given as explicit frequencies in MHz. Omit to hop every channel
                the adapter supports.
            width: Channel width in MHz: 20, 40, 80 or 160.
            dwell_ms: Milliseconds to dwell on each channel (50-60000).
            duration_s: How long the background capture runs, in seconds, from 1
                up to the server maximum (default max 3600). The call itself
                returns immediately.
            pcap_filter: Optional BPF/pcap filter, e.g. 'type mgt subtype beacon'.
        """
        settings = get_settings()
        if width not in VALID_WIDTHS:
            return {"error": f"width must be one of {list(VALID_WIDTHS)}, got {width}"}
        duration_s = _clamp(int(duration_s), 1, settings.PCAP_MAX_DURATION_S)
        dwell_ms = _clamp(int(dwell_ms), MIN_DWELL_MS, MAX_DWELL_MS)

        try:
            token = client.current_token()
        except RuntimeError as exc:
            return {"error": str(exc)}

        try:
            sock = await connect_capture(settings)
        except CaptureError as exc:
            return {"error": str(exc)}

        owns = False
        spawned = False
        try:
            await sock.authenticate(token)

            by_adapter = None
            if interface is None:
                by_adapter = _freqs_by_adapter(await sock.get_supported_frequencies())
                picked = _resolve_adapter(by_adapter, None)
                if isinstance(picked, dict):
                    return picked
                interface = picked[0]

            existing = sessions_on_interface(await sock.list_sessions(), interface)
            if existing:
                return {
                    "error": (
                        f"'{interface}' is already captured by session "
                        f"{existing[0].get('session_id')}. Stop it first, or "
                        "watch it read-only with capture_observe."
                    )
                }

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
            session_id = await sock.start([interface], pcap_filter)

            owns = True

            # Unbuffered write so a fetch mid-capture sees current bytes.
            path, fileobj = storage.open_capture_file(session_id)

            entry = FileCapture(
                session_id=session_id,
                interface=interface,
                path=path,
                duration_s=duration_s,
                started_at=time.time(),
                stop_event=asyncio.Event(),
                config=sock.session_config
                or {"interfaces": config, "pcap_filter": pcap_filter or ""},
            )
            entry.task = asyncio.create_task(_run_file_capture(entry, sock, fileobj))
            _CAPTURES[session_id] = entry
            spawned = True

            result = entry.to_result()
            result["message"] = (
                f"capturing to {path} for up to {duration_s}s; fetch it with "
                f"fetch_pcap_file(capture_id='{session_id}') once stopped"
            )
            return result
        except CaptureError as exc:
            if exc.code == "INTERFACE_IN_USE":
                return {
                    "error": (
                        f"'{interface}' is already in use. Watch it read-only "
                        "with capture_observe, or stop the other capture."
                    )
                }
            return {"error": str(exc)}
        except Exception as exc:
            log.exception("start_pcap_file failed")
            return {"error": f"capture failed: {type(exc).__name__}: {exc}"}
        finally:
            # If the background task never took ownership, tear the socket down
            # here so no ownerless capture is left running.
            if not spawned:
                if owns:
                    await sock.stop()
                await sock.close()

    @mcp.tool()
    async def stop_pcap_file(
        capture_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Stop a running non-streaming file capture before its duration elapses.

        Signals the background capture to stop, waits for it to flush and close
        its file, and returns the final path, status and size. A capture that
        has already ended on its own is returned as-is. Fetch the file with
        fetch_pcap_file.

        Args:
            capture_id: The capture_id returned by start_pcap_file (also shown
                by list_pcap_files).
            session_id: Deprecated alias for capture_id.
        """
        cid = capture_id or session_id
        if not cid:
            return {"error": "pass capture_id"}
        entry = _CAPTURES.get(cid)
        if entry is None:
            if _resolve_session_path(cid) is not None:
                return {
                    "error": (
                        f"capture '{cid}' is not a live capture in this server "
                        "(it likely ended when the server restarted). Its file "
                        "is still available via fetch_pcap_file."
                    )
                }
            return {
                "error": (
                    f"no file capture with capture_id '{cid}'. See "
                    "list_pcap_files for the ones this server knows."
                )
            }
        if entry.status == "running":
            entry.stop_event.set()
            if entry.task is not None:
                try:
                    await entry.task
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - status carries the error
                    log.debug("awaiting stopped capture task: %r", exc)
        return entry.to_result()

    @mcp.tool()
    async def list_pcap_files() -> dict[str, Any]:
        """
        List the non-streaming, file-backed captures this server has started.

        Includes captures that are running or done. Each entry gives the
        capture_id, interface, on-device pcapng path, status
        (running/completed/stopped/error), current size and configured
        duration. Use stop_pcap_file to end a running one and fetch_pcap_file
        to retrieve the file. Files left on disk from an earlier server run are
        also listed, with status 'on_disk' — they can still be fetched.
        """
        captures = [entry.to_result() for entry in _CAPTURES.values()]
        captures.extend(_disk_captures())
        return {"captures": captures, "count": len(captures)}

    @mcp.tool()
    async def fetch_pcap_file(
        capture_id: str | None = None,
        path: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any] | EmbeddedResource:
        """
        Fetch a non-streaming capture's pcapng file as a binary blob.

        Returns the raw pcapng file (mime application/vnd.tcpdump.pcapng) for
        the capture named by capture_id (preferred) or by an explicit
        on-device path. Open it in Wireshark/tshark for analysis. Fetch after
        the capture has stopped for a complete file; fetching a still-running
        capture returns only the bytes written so far.

        For safety this reads only files under the server's managed capture
        directory; any other path is refused.

        Args:
            capture_id: The capture_id from start_pcap_file/list_pcap_files.
            path: Alternatively, the on-device file path (must be inside the
                managed capture directory).
            session_id: Deprecated alias for capture_id.
        """
        cid = capture_id or session_id
        if cid:
            resolved_path = _resolve_session_path(cid)
            if resolved_path is None:
                return {
                    "error": (
                        f"no capture file for capture_id '{cid}'. See list_pcap_files."
                    )
                }
            path = resolved_path
        elif not path:
            log.info(
                "fetch_pcap_file called without an identifier "
                "(capture_id=%r session_id=%r path=%r)",
                capture_id,
                session_id,
                path,
            )
            return {"error": "pass capture_id or path"}

        if not _within_capture_dir(path):
            return {
                "error": (
                    "refusing to read a path outside the managed capture "
                    f"directory ({_capture_dir()})"
                )
            }

        resolved = os.path.realpath(path)
        if not os.path.isfile(resolved):
            return {"error": f"no such capture file: {path}"}

        try:
            with open(resolved, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            return {"error": f"could not read capture file: {exc}"}

        blob = base64.b64encode(data).decode("ascii")
        return EmbeddedResource(
            type="resource",
            resource=BlobResourceContents(
                uri=AnyUrl(f"file://{resolved}"),
                mimeType=PCAP_MIME,
                blob=blob,
            ),
        )
