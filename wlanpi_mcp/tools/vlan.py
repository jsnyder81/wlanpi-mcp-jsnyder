"""MCP tools for managing VLANs on ethernet interfaces."""

from typing import Any

from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import hints


def register(mcp: FastMCP, client: CoreClient) -> None:
    """Register the VLAN management tools."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_vlans(
        interface: str | None = None,
        vlan_id: int | None = None,
    ) -> dict[str, Any]:
        """
        Get VLAN interfaces on the WLAN Pi.

        Args:
            interface: Ethernet interface to filter by (e.g. 'eth0'). If omitted, returns all interfaces.
            vlan_id: VLAN ID to filter by. If omitted, returns all VLANs.
        """
        iface = interface or "all"
        if vlan_id is not None:
            path = f"/api/v1/network/ethernet/{iface}/vlan/{vlan_id}"
        else:
            path = f"/api/v1/network/ethernet/{iface}/vlan"
        return await client.get(path)

    @mcp.tool(annotations=hints.ADDITIVE)
    async def create_vlan(
        interface: str,
        vlan_id: int,
        addresses: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Create (or replace) a VLAN on an ethernet interface.

        Args:
            interface: Ethernet interface (e.g. 'eth0'). Cannot be 'all'.
            vlan_id: VLAN ID (1-4094)
            addresses: Optional list of IP addresses to assign. Each is a dict
                       with 'family' ('inet' or 'inet6', required), 'local'
                       (IP string) and 'prefixlen' (int); optional 'dynamic'
                       (true = run DHCP on the VLAN instead of a static
                       address), 'broadcast', 'anycast', 'scope' (default
                       'global'), 'label', 'valid_life_time' and
                       'preferred_life_time' (seconds).
                       Example: [{"family": "inet", "local": "192.168.10.1", "prefixlen": 24}]
        """
        body = addresses or []
        return await client.post(
            f"/api/v1/network/ethernet/{interface}/vlan/{vlan_id}",
            json=body,
        )

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def delete_vlan(
        interface: str,
        vlan_id: int,
        allow_missing: bool = False,
    ) -> dict[str, Any]:
        """
        Delete a VLAN from an ethernet interface.

        Args:
            interface: Ethernet interface (e.g. 'eth0'). Cannot be 'all'.
            vlan_id: VLAN ID to delete
            allow_missing: If True, don't error if the VLAN doesn't exist
        """
        return await client.delete(
            f"/api/v1/network/ethernet/{interface}/vlan/{vlan_id}",
            params={"allow_missing": allow_missing},
        )
