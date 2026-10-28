"""
get_profiler_reports: the per-client results wlanpi-profiler writes.

Read through wlanpi-core (2.4.8+), which serves the profiler's data directory:

    GET /api/v1/profiler/files          manifest of clients and reports
    GET /api/v1/profiler/files/{path}   one file's bytes

    clients/<mac>/<mac>_<band>.json   capability profile (schema v2)
    clients/<mac>/<mac>_<band>.txt    human-readable report
    clients/<mac>/<mac>_<band>.pcap   the association request frame
    reports/profiler-<date>.csv       one row per profiled client, per day

Core confines reads to clients/ and reports/ and refuses symlinks, and every
call carries the caller's JWT, so core validates it like any other tool.

Files can come back three ways: parsed JSON profiles inline, one single-use
link per file, or one single-use link to a zip of them all. The links reuse
the get_pcap_download_url pattern (download_links.py) but hold a snapshot of
the bytes in memory, so a ticket never names a path.
"""

import asyncio
import hashlib
import io
import json
import logging
import posixpath
import re
import secrets
import shlex
import time
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from wlanpi_mcp import download_links
from wlanpi_mcp.client.core_client import CoreAPIError, CoreClient
from wlanpi_mcp.tools import hints

log = logging.getLogger(__name__)

#: URL prefix of the one-time profiler report download route. Listed in
#: BearerTokenMiddleware's TICKET_PATH_PREFIXES: the route admits only a
#: ticket minted by an authenticated get_profiler_reports call.
REPORT_PREFIX = "/profiler-report/"

#: Most bytes one call may snapshot into memory for links or a zip. Profiles
#: are a few KB each, so this is thousands of clients; past it, filter.
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024

#: Core's profiler file endpoints, added in wlanpi-core 2.4.8.
FILES_PATH = "/api/v1/profiler/files"

#: Most file downloads from core in flight at once.
_FETCH_CONCURRENCY = 8

#: The profiler names a client directory after its MAC, lowercase with dashes.
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?:-[0-9a-f]{2}){5}$")


@dataclass(frozen=True)
class _Download:
    """A snapshot of one file (or zip) behind a single-use ticket."""

    data: bytes
    filename: str
    media_type: str
    expires: float


#: One-time download tickets. In memory only; a daemon restart drops them.
_TICKETS: dict[str, _Download] = {}


def _prune_tickets(now: float) -> None:
    """Drop expired download tickets."""
    for ticket in [t for t, d in _TICKETS.items() if d.expires <= now]:
        _TICKETS.pop(ticket, None)


def _mint(data: bytes, filename: str, media_type: str, now: float) -> str:
    """Store a snapshot behind a fresh ticket and return its route."""
    ticket = secrets.token_urlsafe(24)
    _TICKETS[ticket] = _Download(
        data, filename, media_type, now + download_links.DOWNLOAD_TTL_S
    )
    return f"{REPORT_PREFIX}{ticket}"


def _normalize_mac(mac: str) -> str | None:
    """Return the profiler's directory name for a MAC, or None if not a MAC."""
    digits = re.sub(r"[^0-9a-f]", "", mac.strip().lower())
    if len(digits) != 12 or re.search(r"[^0-9a-fA-F:.\-\s]", mac):
        return None
    return "-".join(digits[i : i + 2] for i in range(0, 12, 2))


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds")


def _file_info(entry: dict[str, Any]) -> dict[str, Any]:
    """Turn one of core's manifest files into this tool's file record."""
    mtime = datetime.fromisoformat(entry["modified"]).timestamp()
    return {
        "name": posixpath.basename(entry["path"]),
        "path": entry["path"],
        "size_bytes": entry["size"],
        "modified": _iso(mtime),
        "_mtime": mtime,
    }


def _from_manifest(
    manifest: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Return (clients newest first, session reports newest first).

    Each client is {"mac", "modified", "files": [...]}; private _mtime keys
    are stripped before anything is returned.
    """
    clients = []
    for entry in manifest.get("clients", []):
        # Core reports the MAC with colons; callers know it by the profiler's
        # directory name.
        mac = entry["mac"].lower().replace(":", "-")
        files = [_file_info(f) for f in entry.get("files", [])]
        if not _MAC_RE.match(mac) or not files:
            continue
        newest = max(f["_mtime"] for f in files)
        clients.append(
            {"mac": mac, "modified": _iso(newest), "_mtime": newest, "files": files}
        )
    clients.sort(key=lambda c: c["_mtime"], reverse=True)

    reports = [
        _file_info(f) for f in manifest.get("reports", []) if f["path"].endswith(".csv")
    ]
    reports.sort(key=lambda r: r["_mtime"], reverse=True)
    return clients, reports


async def _fetch_all(
    client: CoreClient, files: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], bytes | CoreAPIError, str]]:
    """
    Download each file from core, in order, a few at a time.

    A 404 (the file was purged or rewritten since the manifest) comes back in
    place of its bytes; any other core error propagates.
    """
    gate = asyncio.Semaphore(_FETCH_CONCURRENCY)

    async def fetch(
        f: dict[str, Any],
    ) -> tuple[dict[str, Any], bytes | CoreAPIError, str]:
        async with gate:
            try:
                data, media = await client.get_bytes(f"{FILES_PATH}/{quote(f['path'])}")
            except CoreAPIError as exc:
                if exc.status_code != 404:
                    raise
                return f, exc, ""
            return f, data, media

    return list(await asyncio.gather(*(fetch(f) for f in files)))


def _public(info: dict[str, Any]) -> dict[str, Any]:
    """Drop the private scan keys from a file or client record."""
    return {k: v for k, v in info.items() if not k.startswith("_")}


def _band(name: str, mac: str) -> str | None:
    """'aa-..-ff_5GHz.json' -> '5GHz'; None when the profiler wrote no band."""
    stem = posixpath.splitext(name)[0]
    return stem.removeprefix(mac).removeprefix("_") or None


def _parse_profiles(
    client: dict[str, Any],
    fetched: dict[str, bytes | CoreAPIError],
    include_frame: bool,
) -> dict[str, Any]:
    """Parse one client's JSON profiles (one per band it was seen on)."""
    profiles = []
    for f in client["files"]:
        if not f["name"].endswith(".json"):
            continue
        data = fetched[f["path"]]
        if isinstance(data, CoreAPIError):
            profiles.append({"file": f["path"], "error": f"unreadable: {data}"})
            continue
        try:
            profile = json.loads(data)
        except ValueError as exc:
            profiles.append({"file": f["path"], "error": f"unreadable: {exc}"})
            continue
        if not isinstance(profile, dict):
            profiles.append({"file": f["path"], "error": "not a JSON object"})
            continue
        if not include_frame:
            profile.pop("pcapng", None)
        profiles.append(
            {
                "file": f["path"],
                "band": _band(f["name"], client["mac"]),
                "modified": f["modified"],
                **profile,
            }
        )
    return {"mac": client["mac"], "modified": client["modified"], "profiles": profiles}


def _zip(blobs: list[tuple[dict[str, Any], bytes, str]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f, data, _ in blobs:
            # Keep each file's own mtime (when the client was profiled), not
            # the time the zip was built. Zip times are local, 2 s, >= 1980.
            stamp = time.localtime(max(f["_mtime"], 315532800))[:6]
            info = zipfile.ZipInfo(f"profiler/{f['path']}", date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _curl(pairs: list[tuple[str, str]]) -> str:
    """One curl command saving each (local path, url) pair."""
    parts = ["curl -gsSfk --create-dirs"]
    for path, url in pairs:
        parts.append(f"-o {shlex.quote(path)} {shlex.quote(url)}")
    return " ".join(parts)


async def build_reports(
    client: CoreClient,
    *,
    mac: str | None = None,
    output: str = "json",
    max_clients: int = 25,
    include_frame: bool = False,
    include_session_csv: bool = True,
) -> dict[str, Any]:
    """Build get_profiler_reports' result."""
    if output not in ("json", "links", "zip"):
        return {"error": "output must be 'json', 'links' or 'zip'"}
    wanted = None
    if mac:
        wanted = _normalize_mac(mac)
        if wanted is None:
            return {"error": f"not a MAC address: {mac!r}"}

    try:
        manifest = await client.get(
            FILES_PATH, params={"mac": wanted} if wanted else None
        )
    except CoreAPIError as exc:
        # The listing route has no 404 of its own: core predates it.
        if exc.status_code == 404:
            return {
                "error": (
                    "this wlanpi-core has no profiler files endpoint "
                    f"({FILES_PATH}); upgrade wlanpi-core to 2.4.8 or later"
                )
            }
        raise
    clients, reports = _from_manifest(manifest)
    total = len(clients)
    if max_clients > 0:
        clients = clients[:max_clients]
    result: dict[str, Any] = {
        "total_clients": total,
        "returned_clients": len(clients),
        "truncated": len(clients) < total,
    }
    if wanted and not clients:
        result["note"] = f"no profile for {wanted}"
    elif total == 0:
        result["note"] = (
            "no client profiles: the profiler has not profiled a client "
            "since its data was last purged"
        )

    if output == "json":
        wanted_files = [
            f for c in clients for f in c["files"] if f["name"].endswith(".json")
        ]
        fetched = {
            f["path"]: data for f, data, _ in await _fetch_all(client, wanted_files)
        }
        result["clients"] = [
            _parse_profiles(c, fetched, include_frame) for c in clients
        ]
        result["session_reports"] = [_public(r) for r in reports]
        return result

    files = [f for c in clients for f in c["files"]]
    if include_session_csv:
        files += reports
    size = sum(f["size_bytes"] for f in files)
    if size > MAX_DOWNLOAD_BYTES:
        return {
            "error": (
                f"{len(files)} files, {size} bytes: over the "
                f"{MAX_DOWNLOAD_BYTES} byte limit for one call. Narrow "
                "it with mac or max_clients, or include_session_csv=false."
            )
        }
    blobs = []
    for f, data, media in await _fetch_all(client, files):
        if isinstance(data, CoreAPIError):
            log.warning("profiler report %s gone: %s", f["path"], data)
        else:
            blobs.append((f, data, media))

    now = time.time()
    _prune_tickets(now)
    base = download_links.request_base_url()
    result["expires_in_s"] = download_links.DOWNLOAD_TTL_S
    result["single_use"] = True
    result["clients"] = [{"mac": c["mac"], "modified": c["modified"]} for c in clients]

    def link(route: str) -> dict[str, str]:
        if base:
            return {"download_url": f"{base}{route}"}
        return {"download_path": route}

    if output == "zip":
        data = await asyncio.to_thread(_zip, blobs)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        filename = f"profiler-reports-{stamp}.zip"
        route = _mint(data, filename, "application/zip", now)
        result.update(
            {
                "filename": filename,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "files": [f["path"] for f, _, _ in blobs],
                **link(route),
            }
        )
        if base:
            result["curl"] = _curl([(filename, f"{base}{route}")])
    else:
        entries = []
        pairs = []
        for f, data, media in blobs:
            route = _mint(data, f["name"], media, now)
            entries.append({"path": f["path"], "size_bytes": len(data), **link(route)})
            if base:
                pairs.append((f"profiler/{f['path']}", f"{base}{route}"))
        result["files"] = entries
        if pairs:
            result["curl"] = _curl(pairs)

    if not base:
        result["note"] = (
            "no HTTP request context (stdio): prefix download_path with "
            "this server's https://host:port"
        )
    return result


def register(mcp: MCPServer, client: CoreClient) -> None:
    """Register get_profiler_reports and its download route."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_profiler_reports(
        mac: str | None = None,
        output: Literal["json", "links", "zip"] = "json",
        max_clients: int = 25,
        include_frame: bool = False,
        include_session_csv: bool = True,
    ) -> dict[str, Any]:
        """
        Get the client capability profiles the wlanpi-profiler has captured.

        Each client the profiler saw associate gets a profile per band:
        manufacturer (manuf, chipset), whether its MAC is randomized
        (is_laa), what it associated to (capture_ssid/bssid/band/channel),
        and 'features' - its 802.11 capabilities (dot11k/r/v/w, n/ac/ax/be
        support and spatial streams, MCS ranges, channel widths, beamforming,
        TWT, MLO/EMLSR, supported_channels, min/max power, and the RSN
        akm/pairwise_cipher/group_cipher suite numbers). In 'features', 1
        means supported, 0 not supported, -1 not advertised/not applicable.

        Results accumulate across profiler runs until purge_profiler_data, so
        clients are listed newest first; use 'mac' to pick one, or compare
        'modified' against when the run started. Reading is safe while the
        profiler runs; a client that has not finished associating may not be
        written yet.

        Args:
            mac: Only this client (any common MAC format).
            output: How to return the results.
                'json' (default) - the parsed profiles inline, one entry per
                    client with a profile per band. Best for answering
                    questions about clients.
                'links' - a single-use HTTPS link per file (each client's
                    .json, .txt report and .pcap association frame, plus the
                    daily session CSVs) and one 'curl' command that saves them
                    all under ./profiler/. Use when the user wants the files.
                'zip' - one single-use link to a zip of the same files, with
                    a 'curl' command. Use for many clients or to hand the
                    whole set over in one file.
                Links work once, expire after 'expires_in_s' seconds, and use
                the device's self-signed certificate (hence curl -k). Without
                an HTTP request (stdio) you get 'download_path' to prefix
                with this server's https://host:port instead.
            max_clients: Most clients to return, newest first (default 25);
                0 or less returns every client. 'truncated' says if any
                were left out.
            include_frame: json only - keep each profile's 'pcapng' field,
                the base64 association request frame (off by default: large
                and rarely needed inline; the .pcap comes with links/zip).
            include_session_csv: links/zip only - include the daily
                reports/profiler-<date>.csv summaries (default true). Not
                filtered by mac or max_clients.

        Returns {"clients": [...], "total_clients", "returned_clients",
        "truncated", "session_reports": [...]}, plus the link fields for
        'links'/'zip'. No clients means the profiler has not profiled
        anything since the data was last purged.

        Reads through wlanpi-core's profiler file endpoints (wlanpi-core
        2.4.8 or later). A 401 from core means it refused this token: get a
        fresh one and reconnect.
        """
        return await build_reports(
            client,
            mac=mac,
            output=output,
            max_clients=max_clients,
            include_frame=include_frame,
            include_session_csv=include_session_csv,
        )

    @mcp.custom_route(REPORT_PREFIX + "{ticket}", methods=["GET"])
    async def download_profiler_report(request: Request) -> Response:
        """Serve one snapshot for a valid, unused, unexpired ticket."""
        _prune_tickets(time.time())
        entry = _TICKETS.pop(request.path_params.get("ticket", ""), None)
        if entry is None:
            return JSONResponse(
                {"detail": "unknown, used or expired download link"},
                status_code=404,
            )
        return Response(
            entry.data,
            media_type=entry.media_type,
            headers={"Content-Disposition": f'attachment; filename="{entry.filename}"'},
        )
