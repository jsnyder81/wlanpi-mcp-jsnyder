"""MCP tools for advanced system control: mode, regulatory domain, and battery."""

import re
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp_types import InputRequiredResult

from wlanpi_mcp import elicit
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import hints

VALID_MODES = {"classic", "wconsole", "hotspot", "wiperf", "server", "bridge"}


def register(mcp: MCPServer, client: CoreClient) -> None:
    """Register the advanced system control tools."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_device_mode() -> dict[str, Any]:
        """Get the current WLAN Pi operating mode (classic, wconsole, hotspot, wiperf, server, bridge)."""
        info = await client.get("/api/v1/system/device/info")
        mode = info.get("mode", "")
        return {"mode": mode, "valid": mode in VALID_MODES}

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_regulatory_domain() -> dict[str, Any]:
        """
        Get the current Wi-Fi regulatory domain.

        Returns 'country' as an ISO 3166-1 alpha-2 code.
        """
        return await client.get("/api/v1/system/reg-domain")

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def set_regulatory_domain(
        country_code: str, ctx: Context
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Set the Wi-Fi regulatory domain (country code) on the WLAN Pi.

        This controls which channels and transmit power levels are permitted.
        Use a valid ISO 3166-1 alpha-2 country code (e.g. 'US', 'GB', 'DE').
        When the client supports elicitation, the user is asked to confirm
        directly; a 'not_performed' status means they declined - do not
        retry.

        Args:
            country_code: Two-letter ISO 3166-1 alpha-2 country code
        """
        if not re.match(r"^[A-Z]{2}$", country_code.upper()):
            return {
                "error": "country_code must be a two-letter ISO 3166-1 alpha-2 code (e.g. 'US')"
            }

        country = country_code.upper()

        async def message() -> str:
            name = await elicit.device_name(client)
            return (
                f"Set the Wi-Fi regulatory domain on {name} to {country}? "
                "This changes which channels and transmit powers its radios "
                "may use."
            )

        stop = await elicit.confirm(
            ctx, "reg_domain", message, f"set the regulatory domain to {country}"
        )
        if stop is not None:
            return stop
        return await client.post(
            "/api/v1/system/reg-domain/set", json={"country": country}
        )

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_battery_status() -> dict[str, Any]:
        """
        Get battery status on WLAN Pi models with a battery (e.g. WLAN Pi Pro).

        Returns 'present': false on hardware without a battery, otherwise
        capacity percentage and charging status.
        """
        return await client.get("/api/v1/system/battery")
