"""MCP tools for WLAN Pi system management: device, services, timezone, and power."""

from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp_types import InputRequiredResult

from wlanpi_mcp import elicit
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import get_settings
from wlanpi_mcp.tools import hints


def register(mcp: MCPServer, client: CoreClient) -> None:
    """Register the system management tools."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_device_info() -> dict[str, Any]:
        """Get WLAN Pi device identity: model, hostname, software version, and current operating mode."""
        return await client.get("/api/v1/system/device/info")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_device_stats() -> dict[str, Any]:
        """Get WLAN Pi live system metrics: IP address, CPU usage, RAM usage, disk usage, CPU temperature, and uptime."""
        return await client.get("/api/v1/system/device/stats")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def list_allowed_services() -> dict[str, Any]:
        """
        List the services this WLAN Pi lets you query, start, stop, or restart.

        The list is wlanpi-core's own allowlist, the same one it checks on every
        service call, so only these names work with get_service_status,
        start_service, stop_service and restart_service. A listed service may
        still not be installed on this image; get_service_status says so.
        """
        return await client.get("/api/v1/system/services")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_service_status(name: str) -> dict[str, Any]:
        """
        Get the running status of a WLAN Pi service.

        Args:
            name: Service name (use list_allowed_services to see valid names).
                wlanpi-core answers 400 for a name outside its allowlist
                or a service that is not installed.
        """
        return await client.get("/api/v1/system/service/status", params={"name": name})

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def start_service(name: str) -> dict[str, Any]:
        """
        Start a WLAN Pi service.

        Args:
            name: Service name (use list_allowed_services to see valid names).
                wlanpi-core answers 400 for a name outside its allowlist
                or a service that is not installed.
        """
        return await client.post("/api/v1/system/service/start", params={"name": name})

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def stop_service(name: str) -> dict[str, Any]:
        """
        Stop a WLAN Pi service.

        Args:
            name: Service name (use list_allowed_services to see valid names).
                wlanpi-core answers 400 for a name outside its allowlist
                or a service that is not installed.
        """
        return await client.post("/api/v1/system/service/stop", params={"name": name})

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def restart_service(name: str) -> dict[str, Any]:
        """
        Restart a WLAN Pi service.

        Args:
            name: Service name (use list_allowed_services to see valid names).
                wlanpi-core answers 400 for a name outside its allowlist
                or a service that is not installed.
        """
        return await client.post(
            "/api/v1/system/service/restart", params={"name": name}
        )

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_device_model() -> dict[str, Any]:
        """Get the WLAN Pi hardware model (e.g. WLAN Pi Pro, R4, M4)."""
        return await client.get("/api/v1/system/device/model")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_datetime() -> dict[str, Any]:
        """Get the WLAN Pi's current local date, time, and timezone."""
        return await client.get("/api/v1/system/datetime")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_timezone() -> dict[str, Any]:
        """Get the WLAN Pi's current system timezone."""
        return await client.get("/api/v1/system/timezone")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def list_timezones() -> dict[str, Any]:
        """List all timezones available on the WLAN Pi (for use with set_timezone)."""
        return await client.get("/api/v1/system/timezone/list")

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def set_timezone(timezone: str) -> dict[str, Any]:
        """
        Set the WLAN Pi system timezone.

        Args:
            timezone: Timezone name, e.g. 'America/Denver' (use list_timezones for valid values)
        """
        return await client.post(
            "/api/v1/system/timezone/set", json={"timezone": timezone}
        )

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def enable_auto_timezone() -> dict[str, Any]:
        """Enable NTP automatic time synchronization on the WLAN Pi."""
        return await client.post("/api/v1/system/timezone/auto")

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def reboot_device(ctx: Context) -> dict[str, Any] | InputRequiredResult:
        """
        Reboot the WLAN Pi immediately.

        Active sessions and captures will be interrupted. Can be disabled via
        ALLOW_POWER_CONTROL=false in the server config. When the client
        supports elicitation, the user is asked to confirm directly; a
        'not_performed' status means they declined - do not retry.
        """
        if not get_settings().ALLOW_POWER_CONTROL:
            return {
                "error": "Power control is disabled. Set ALLOW_POWER_CONTROL=true "
                "in /etc/wlanpi-mcp/config.env to allow reboot/shutdown."
            }

        async def message() -> str:
            name = await elicit.device_name(client)
            return (
                f"Reboot {name} now? Active captures, the profiler and every "
                "connection to it will be interrupted until it is back up."
            )

        stop = await elicit.confirm(ctx, "reboot", message, "reboot the device")
        if stop is not None:
            return stop
        return await client.post("/api/v1/system/reboot")

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def shutdown_device(ctx: Context) -> dict[str, Any] | InputRequiredResult:
        """
        Shut down the WLAN Pi immediately.

        The device must be powered back on manually. Can be disabled via
        ALLOW_POWER_CONTROL=false in the server config. When the client
        supports elicitation, the user is asked to confirm directly; a
        'not_performed' status means they declined - do not retry.
        """
        if not get_settings().ALLOW_POWER_CONTROL:
            return {
                "error": "Power control is disabled. Set ALLOW_POWER_CONTROL=true "
                "in /etc/wlanpi-mcp/config.env to allow reboot/shutdown."
            }

        async def message() -> str:
            name = await elicit.device_name(client)
            return (
                f"Shut down {name} now? It stays off until someone powers it "
                "back on by hand, and every connection to it is lost."
            )

        stop = await elicit.confirm(ctx, "shutdown", message, "shut down the device")
        if stop is not None:
            return stop
        return await client.post("/api/v1/system/shutdown")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_hotspot_clients(iface: str | None = None) -> dict[str, Any]:
        """
        Get the connected client count in hotspot mode.

        Returns an error if the device is not in hotspot mode.

        Args:
            iface: Optional AP interface name; auto-detected if omitted.
        """
        params = {"iface": iface} if iface else None
        return await client.get("/api/v1/system/hotspot/clients", params=params)

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_hotspot_ssid_passphrase() -> dict[str, Any]:
        """
        Get the hotspot SSID and WPA passphrase.

        Read from the hostapd configuration. Returns an error if the device is
        not in hotspot mode.
        """
        return await client.get("/api/v1/system/hotspot/ssid-passphrase")
