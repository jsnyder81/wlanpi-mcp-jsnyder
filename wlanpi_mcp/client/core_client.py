"""Async HTTP client for the wlanpi-core API, forwarding the client's JWT."""

import logging
from typing import Any, Optional

import httpx

from wlanpi_mcp.auth.token_context import get_token
from wlanpi_mcp.client.tls import core_ssl_context
from wlanpi_mcp.config import Settings

log = logging.getLogger(__name__)

_client: Optional["CoreClient"] = None


def get_client() -> "CoreClient":
    """Return the initialized CoreClient, raising if not yet initialized."""
    if _client is None:
        raise RuntimeError("CoreClient not initialized — call init_client() first")
    return _client


def init_client(settings: Settings) -> "CoreClient":
    """Initialize and return the module-global CoreClient for the given settings."""
    global _client
    _client = CoreClient(settings)
    return _client


class CoreClient:
    """
    Async client for the wlanpi-core API.

    Auth is pure passthrough: the wlanpi-core JWT presented by the MCP client
    (captured by BearerTokenMiddleware, or WLANPI_CORE_TOKEN for stdio mode)
    is forwarded as the Bearer token on every request. wlanpi-core validates
    it — this server never mints or verifies tokens itself. Core selects its
    auth scheme from the credential presented, so a Bearer token takes the JWT
    path even over loopback; no routing hint header is needed.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._http = httpx.AsyncClient(
            base_url=settings.WLANPI_CORE_URL,
            verify=core_ssl_context(settings),
            timeout=30.0,
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    async def get(self, path: str, **kwargs: Any) -> Any:
        """Send a GET request to the given wlanpi-core path."""
        return await self._request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:
        """Send a POST request to the given wlanpi-core path."""
        return await self._request("POST", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> Any:
        """Send a PATCH request to the given wlanpi-core path."""
        return await self._request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> Any:
        """Send a DELETE request to the given wlanpi-core path."""
        return await self._request("DELETE", path, **kwargs)

    def current_token(self) -> str:
        """
        Return the wlanpi-core token for this request, by the same rule as REST calls.

        Public so non-HTTP core transports (the capture WebSocket, which sends
        the token in its first message) reuse this resolution instead of
        duplicating it. Raises RuntimeError when no token is available.
        """
        return self._current_token()

    def _current_token(self) -> str:
        token = get_token() or self._settings.WLANPI_CORE_TOKEN
        if not token:
            raise RuntimeError(
                "No wlanpi-core token available. Connect with "
                "'Authorization: Bearer <token>' (HTTP) or set WLANPI_CORE_TOKEN "
                "(stdio). Tokens are issued by wlanpi-core at /api/v1/auth/token."
            )
        return token

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = {
            **kwargs.get("headers", {}),
            "Authorization": f"Bearer {self._current_token()}",
        }
        response = await self._http.request(
            method, path, **{**kwargs, "headers": headers}
        )
        response.raise_for_status()
        return response.json()
