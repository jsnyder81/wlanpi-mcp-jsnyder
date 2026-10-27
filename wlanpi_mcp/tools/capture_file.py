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
import contextlib
import functools
import glob
import hashlib
import logging
import os
import secrets
import shlex
import time
from dataclasses import dataclass, field
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import BlobResourceContents, EmbeddedResource
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response

from wlanpi_mcp import download_links, tasks
from wlanpi_mcp.capture import storage
from wlanpi_mcp.capture.ws_client import (
    CaptureError,
    CaptureSocket,
    connect_capture,
    sessions_on_interface,
)
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import get_settings
from wlanpi_mcp.tools import hints
from wlanpi_mcp.tools.capture import (
    DEFAULT_INTERFACE,
    MAX_DWELL_MS,
    MIN_DWELL_MS,
    VALID_WIDTHS,
    _channels_to_freqs,
    _clamp,
    _freqs_by_adapter,
)

log = logging.getLogger(__name__)

PCAP_MIME = "application/vnd.tcpdump.pcapng"

#: URL prefix of the one-time pcap download route. BearerTokenMiddleware lets
#: requests under it through without a JWT: the route itself admits only a
#: ticket minted by get_pcap_download_url, an authenticated tool call.
DOWNLOAD_PREFIX = "/pcap/"

#: How long a download ticket stays valid, in seconds. Single use either way.
DOWNLOAD_TTL_S = download_links.DOWNLOAD_TTL_S

#: One-time download tickets: ticket -> (resolved file path, expiry epoch).
#: In memory only; a daemon restart drops them, which is fine for a link that
#: is meant to be used straight away.
_TICKETS: dict[str, tuple[str, float]] = {}


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
    # Set when the capture was started as an MCP task (issue #90); the run
    # path publishes the outcome there instead of only into _CAPTURES.
    task_record: tasks.TaskRecord | None = None

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
        _publish_task_outcome(entry)


def _publish_task_outcome(entry: FileCapture) -> None:
    """Hand a finished capture to its task record, if it was started as one."""
    record = entry.task_record
    if record is None:
        return
    result = entry.to_result()
    if record.cancel_requested or entry.status == "cancelled":
        tasks.TASKS.cancelled(record, result)
    elif entry.status == "error":
        tasks.TASKS.fail(record, result)
    else:
        tasks.TASKS.complete(record, result)


def _progress_message(entry: FileCapture) -> str:
    """Live statusMessage for a task-backed capture: bytes written so far."""
    return f"{entry.bytes_written} bytes written to {os.path.basename(entry.path)}"


async def _stop_for_cancel(entry: FileCapture) -> None:
    """Stop a capture through its normal end path so the ownership rule holds.

    Awaiting the run task means the store's cancel returns only once the
    finally block above has stopped the core session and published the
    outcome.
    """
    entry.stop_event.set()
    if entry.task is not None:
        # A capture task cancelled by loop shutdown is already ending: the
        # tasks/cancel request must not fail on top of it.
        with contextlib.suppress(asyncio.CancelledError):
            await entry.task


def _prune_tickets(now: float) -> None:
    """Drop expired download tickets."""
    for ticket in [t for t, (_, exp) in _TICKETS.items() if exp <= now]:
        _TICKETS.pop(ticket, None)


def _sha256(path: str) -> str:
    """Return the hex SHA-256 of a file, read in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _capture_for_path(resolved: str) -> FileCapture | None:
    """Return the registry entry writing this file, if any."""
    for entry in _CAPTURES.values():
        if os.path.realpath(entry.path) == resolved:
            return entry
    return None


def register(mcp: MCPServer, client: CoreClient) -> None:
    """Register the non-streaming, file-backed capture tools."""

    @mcp.tool(annotations=hints.ADDITIVE)
    async def start_pcap_file(
        interface: str = DEFAULT_INTERFACE,
        channels: list[int] | None = None,
        width: int = 20,
        dwell_ms: int = 250,
        duration_s: int = 60,
        pcap_filter: str = "",
        ctx: Context[Any, Any] | None = None,
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

        When your client supports MCP Tasks this call instead returns a task
        handle right away: the capture runs until duration_s elapses or you
        cancel the task, tasks/get reports the bytes written so far and, once
        terminal, the final capture report (capture_id, path, size_bytes,
        status). Without task support everything above is exactly as before.

        This tool always owns the interface. If a capture is already running on
        it, this returns an error rather than taking it over — watch that one
        with capture_observe instead.

        Args:
            interface: Monitor-mode capture interface, always 'wlanpiN' (e.g.
                'wlanpi0'), not 'wlan0'. See get_capture_channels.
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
                by_adapter = _freqs_by_adapter(await sock.get_supported_frequencies())
                freqs = by_adapter.get(interface) or []
                if not freqs and len(by_adapter) == 1:
                    freqs = next(iter(by_adapter.values()))
                if not freqs:
                    known = sorted(k for k, v in by_adapter.items() if v)
                    return {
                        "error": (
                            f"no supported frequencies reported for '{interface}'. "
                            f"Capture interfaces on this device: {known or 'none'}"
                        )
                    }

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
            if tasks.tasks_supported(ctx):
                entry.task_record = tasks.TASKS.create(
                    progress=functools.partial(_progress_message, entry),
                    cancel=functools.partial(_stop_for_cancel, entry),
                )
            entry.task = asyncio.create_task(_run_file_capture(entry, sock, fileobj))
            _CAPTURES[session_id] = entry
            spawned = True

            result = entry.to_result()
            if entry.task_record is not None:
                return tasks.task_call_result(
                    entry.task_record,
                    message=(
                        f"capturing to {path} for up to {duration_s}s as task "
                        f"'{entry.task_record.task_id}'; poll tasks/get with that "
                        "taskId for progress and the final capture report, or "
                        "tasks/cancel to stop it early"
                    ),
                    payload=result,
                )
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

    @mcp.tool(annotations=hints.ADDITIVE)
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

    @mcp.tool(annotations=hints.READ_ONLY)
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

    # structured_output=False: with structured output on, MCPServer serialises the
    # returned EmbeddedResource into structuredContent as well as content, so
    # the base64 pcap goes over the wire twice (issue #50). Errors are raised as
    # ToolError (isError: true) rather than returned as dicts, so the result is
    # only ever the blob.
    @mcp.tool(annotations=hints.READ_ONLY, structured_output=False)
    async def fetch_pcap_file(
        capture_id: str | None = None,
        path: str | None = None,
        session_id: str | None = None,
    ) -> EmbeddedResource:
        """
        Fetch a non-streaming capture's pcapng file as a binary blob.

        Returns the raw pcapng file (mime application/vnd.tcpdump.pcapng) for
        the capture named by capture_id (preferred) or by an explicit
        on-device path. Open it in Wireshark/tshark for analysis. Fetch after
        the capture has stopped for a complete file; fetching a still-running
        capture returns only the bytes written so far. The blob is base64, about
        1.33x the file size (see size_bytes in list_pcap_files) - check the size
        before fetching a long capture.

        For safety this reads only files under the server's managed capture
        directory; any other path is refused.

        Fails as a tool error when no identifier is given, the capture_id or
        path has no file, or the path is outside the capture directory.

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
                raise ToolError(
                    f"no capture file for capture_id '{cid}'. See list_pcap_files."
                )
            path = resolved_path
        elif not path:
            log.info(
                "fetch_pcap_file called without an identifier "
                "(capture_id=%r session_id=%r path=%r)",
                capture_id,
                session_id,
                path,
            )
            raise ToolError("pass capture_id or path")

        if not _within_capture_dir(path):
            raise ToolError(
                "refusing to read a path outside the managed capture "
                f"directory ({_capture_dir()})"
            )

        resolved = os.path.realpath(path)
        if not os.path.isfile(resolved):
            raise ToolError(f"no such capture file: {path}")

        try:
            with open(resolved, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise ToolError(f"could not read capture file: {exc}") from exc

        blob = base64.b64encode(data).decode("ascii")
        return EmbeddedResource(
            type="resource",
            resource=BlobResourceContents(
                uri=f"file://{resolved}",
                mime_type=PCAP_MIME,
                blob=blob,
            ),
        )

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_pcap_download_url(
        capture_id: str | None = None,
        path: str | None = None,
    ) -> dict[str, Any]:
        """
        Get a one-time HTTPS link to download a capture's pcapng file straight to disk.

        Prefer this to fetch_pcap_file whenever you can run a shell command:
        fetch_pcap_file returns the whole file as base64 inside the tool
        result (about 1.33x the file size, all of it in your context), while
        this returns a short link and a ready-made 'curl' command that saves
        the file locally without passing it through the conversation. Run the
        'curl' command as given, then check the file's size (or 'sha256';
        the hash is of the file when the link was made, so it only matches a
        capture that had already stopped).

        The link works once and expires after 'expires_in_s' seconds; ask for
        a new one if it lapses. It is served on the same host and port as this
        MCP server, with the device's self-signed certificate (hence curl -k).
        Fetch after the capture has stopped ('status' is not 'running') for a
        complete file. Only files in the managed capture directory are served.

        Args:
            capture_id: The capture_id from start_pcap_file/list_pcap_files
                (also the capture_scan/capture_observe tee files).
            path: Alternatively, the on-device file path (must be inside the
                managed capture directory).
        """
        if capture_id:
            file_path = _resolve_session_path(capture_id)
            if file_path is None:
                return {
                    "error": (
                        f"no capture file for capture_id '{capture_id}'. "
                        "See list_pcap_files."
                    )
                }
        elif path:
            file_path = path
        else:
            return {"error": "pass capture_id or path"}

        if not _within_capture_dir(file_path):
            return {
                "error": (
                    "refusing to serve a path outside the managed capture "
                    f"directory ({_capture_dir()})"
                )
            }
        resolved = os.path.realpath(file_path)
        if not os.path.isfile(resolved):
            return {"error": f"no such capture file: {file_path}"}

        # The link itself carries no JWT, so check this caller's token with
        # wlanpi-core before minting one.
        if (token_error := await download_links.check_token(client)) is not None:
            return {"error": token_error}

        now = time.time()
        _prune_tickets(now)
        ticket = secrets.token_urlsafe(24)
        _TICKETS[ticket] = (resolved, now + DOWNLOAD_TTL_S)

        filename = os.path.basename(resolved)
        route = f"{DOWNLOAD_PREFIX}{ticket}"
        base = download_links.request_base_url()
        entry = _capture_for_path(resolved)
        result: dict[str, Any] = {
            "capture_id": capture_id or storage.session_from_filename(filename),
            "filename": filename,
            "size_bytes": _safe_size(resolved),
            # Off the event loop: a long capture is a lot to hash on a Pi.
            "sha256": await asyncio.to_thread(_sha256, resolved),
            "expires_in_s": DOWNLOAD_TTL_S,
            "single_use": True,
        }
        if entry is not None:
            result["status"] = entry.status
            if entry.status == "running":
                result["warning"] = (
                    "capture still running: the file is partial. Wait for it "
                    "to finish (or stop_pcap_file), then ask for a new link."
                )
        if base:
            url = f"{base}{route}"
            result["download_url"] = url
            result["curl"] = (
                f"curl -gsSfk -o {shlex.quote(filename)} {shlex.quote(url)}"
            )
        else:
            result["download_path"] = route
            result["note"] = (
                "no HTTP request context (stdio): prefix download_path with "
                "this server's https://host:port"
            )
        return result

    @mcp.custom_route(DOWNLOAD_PREFIX + "{ticket}", methods=["GET"])
    async def download_pcap(request: Request) -> Response:
        """Serve one capture file for a valid, unused, unexpired ticket."""
        now = time.time()
        _prune_tickets(now)
        entry = _TICKETS.pop(request.path_params.get("ticket", ""), None)
        if entry is None:
            return JSONResponse(
                {"detail": "unknown, used or expired download link"},
                status_code=404,
            )
        file_path, _expires = entry
        if not _within_capture_dir(file_path) or not os.path.isfile(file_path):
            return JSONResponse({"detail": "capture file is gone"}, status_code=404)
        return FileResponse(
            file_path, media_type=PCAP_MIME, filename=os.path.basename(file_path)
        )
