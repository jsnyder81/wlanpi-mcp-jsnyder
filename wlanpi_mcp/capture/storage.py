"""
Shared on-device storage for captured pcapng files.

Both the streaming tools (capture_scan/capture_observe, which tee their raw
bytes to a file for verification) and the non-streaming file tools
(start_pcap_file et al.) write pcapng files into one managed directory
(``Settings.PCAP_CAPTURE_DIR``) using one naming convention, so a file written
by either family is discoverable and fetchable by the same helpers. This module
is the single home for that directory, the filename scheme, and the
path-confinement check — kept here (not in a tools module) so both tool modules
can import it without a circular dependency.
"""

import glob
import os
import re
import time
from typing import Any

from wlanpi_mcp.config import get_settings

#: Filenames are ``capture-<stamp>-<safe capture id>.pcapng``. The stamp carries
#: no '-', so the capture id is the whole third '-'-delimited field and can be
#: recovered from the name after the in-memory registry is gone.
_SAFE_RE = re.compile(r"[^A-Za-z0-9_]+")


def file_size(path: str) -> int:
    """Return the size of the file at path in bytes, or 0 if unreadable."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def capture_dir() -> str:
    """Return the resolved managed capture directory path."""
    return os.path.realpath(get_settings().PCAP_CAPTURE_DIR)


def within_capture_dir(path: str) -> bool:
    """Return True if the given path resolves inside the managed capture directory."""
    base = capture_dir()
    resolved = os.path.realpath(path)
    return resolved == base or resolved.startswith(base + os.sep)


def safe_component(value: str) -> str:
    """Render a capture id filesystem-safely for use in a filename."""
    return _SAFE_RE.sub("_", value) or "capture"


def capture_filename(capture_id: str) -> str:
    """Return a timestamped, capture-id-keyed pcapng filename."""
    stamp = time.strftime("%Y%m%dT%H%M%S")
    return f"capture-{stamp}-{safe_component(capture_id)}.pcapng"


def session_from_filename(name: str) -> str:
    """Recover the capture id from a ``capture-<stamp>-<id>.pcapng`` filename."""
    base = name[: -len(".pcapng")] if name.endswith(".pcapng") else name
    parts = base.split("-", 2)  # "capture", stamp, safe-capture-id
    return parts[2] if len(parts) == 3 else base


def latest_path(capture_id: str) -> str | None:
    """Return the newest pcapng file written for capture_id, or None if absent."""
    safe = safe_component(capture_id)
    try:
        matches = sorted(
            glob.glob(os.path.join(capture_dir(), f"capture-*-{safe}.pcapng"))
        )
    except OSError:
        return None
    return matches[-1] if matches else None


def open_capture_file(capture_id: str) -> tuple[str, Any]:
    """
    Create the capture dir and open a new unbuffered pcapng file for writing.

    Unbuffered so a fetch mid-capture sees the bytes written so far. Returns
    ``(path, fileobj)``.
    """
    directory = get_settings().PCAP_CAPTURE_DIR
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, capture_filename(capture_id))
    return path, open(path, "wb", buffering=0)


def try_open_capture_file(capture_id: str) -> tuple[str | None, Any]:
    """
    Best-effort :func:`open_capture_file`: never raises.

    Returns ``(path, fileobj)`` on success, ``(None, None)`` if the file could
    not be opened, so a storage problem never breaks a live capture.
    """
    try:
        return open_capture_file(capture_id)
    except OSError:
        return None, None
