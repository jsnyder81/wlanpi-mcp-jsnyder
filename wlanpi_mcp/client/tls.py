"""TLS trust for connections to wlanpi-core, shared by REST and the capture WebSocket."""

import logging
import ssl
from pathlib import Path

from wlanpi_mcp.config import Settings

log = logging.getLogger(__name__)


def core_ssl_context(settings: Settings) -> ssl.SSLContext:
    """
    Return the SSL context that verifies wlanpi-core's TLS listener.

    Core serves a self-signed device certificate, so trust is explicit: the
    certificate at ``WLANPI_CORE_CA`` is the trust anchor. Verification is
    never disabled. An empty ``WLANPI_CORE_CA`` means "use the system trust
    store" (a core behind a publicly signed certificate). A configured path
    that does not exist also falls back to the system store, but is logged,
    because a self-signed core will then fail the handshake.
    """
    ca = settings.WLANPI_CORE_CA
    if not ca:
        return ssl.create_default_context()
    if not Path(ca).is_file():
        log.warning(
            "WLANPI_CORE_CA %s not found; verifying wlanpi-core against the "
            "system trust store, which will reject a self-signed device "
            "certificate",
            ca,
        )
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=ca)
