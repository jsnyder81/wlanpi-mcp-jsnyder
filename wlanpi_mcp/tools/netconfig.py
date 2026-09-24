"""MCP tools for managing saved network configuration profiles."""

from typing import Any

from wlanpi_mcp._compat import FastMCP
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import hints


def register(mcp: FastMCP, client: CoreClient) -> None:
    """Register the network configuration management tools."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_network_config_status() -> dict[str, Any]:
        """Get the status of all saved network configurations, showing which is active."""
        return await client.get("/api/v1/network/config/status")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def list_network_configs() -> dict[str, Any]:
        """
        List all saved network configuration profiles.

        Returns a dict mapping config ID to active state (True/False).
        """
        return await client.get("/api/v1/network/config/")

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_network_config(id: str) -> dict[str, Any]:
        """
        Get a saved network configuration by ID.

        Secrets are never returned: security shows psk_set/password_set instead
        of psk/password. 422 means the stored profile breaks the naming rules;
        the user must fix or recreate it.

        Args:
            id: Configuration profile ID (use list_network_configs to see available IDs)
        """
        return await client.get(f"/api/v1/network/config/{id}")

    @mcp.tool(annotations=hints.ADDITIVE)
    async def create_network_config(config: dict[str, Any]) -> dict[str, Any]:
        """
        Create a saved network configuration profile.

        config: {id, namespaces?: [...], roots?: [...]}. id may not be default,
        root, status, leftovers or reset in any case (400).
        Each entry: mode ('managed'|'monitor', default managed),
        iface_display_name, phy (e.g. 'phy0'; advisory), interface (e.g.
        'wlan0'), namespace (namespaces only), and optional default_route
        (bool, default false), mlo (bool, default false: enable Wi-Fi 7
        multi-link operation; needs an MLO-capable adapter and AP),
        autostart_app (name defined in core's apps file) and security {ssid,
        security: WPA2-PSK|WPA3-PSK|OPEN|OWE, psk?}. The security block also
        accepts sae_pwe, pmf, identity, password, client_cert, private_key
        and ca_cert, but core does not apply them today: PMF is fixed by the
        security type and there is no EAP security type - don't set them.
        Rejected with 422: WPA2-PSK psk not 8-63 printable ASCII or 64 hex;
        WPA3-PSK psk not a passphrase (no 64-hex); two entries with the same
        interface; a display name equal to another entry's interface; a
        display name repeated within one namespace.

        Args:
            config: Network configuration dict matching the NetConfig schema
        """
        return await client.post("/api/v1/network/config/", json=config)

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def update_network_config(
        id: str, config_update: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Update a profile's namespaces and/or roots (replaces those lists).

        An entry that omits psk/password (or sends null) keeps the stored one,
        matched by (namespace, interface), so an entry from get_network_config
        can be sent back as is. If you change an entry's interface or
        namespace, the secret is not carried over: ask the user for it.
        Entries take the same fields as create_network_config (including
        mlo) and the same validation (422).

        Args:
            id: Configuration profile ID to update
            config_update: {namespaces?: [...], roots?: [...]}
        """
        return await client.patch(f"/api/v1/network/config/{id}", json=config_update)

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def activate_network_config(
        id: str, override_active: bool = False
    ) -> dict[str, Any]:
        """
        Activate a saved profile.

        Always call with override_active=false first. Never set it true on
        your own: if another profile is active, ask the user whether to replace
        it, even if they already asked to activate this one.
        Success does NOT mean every entry was applied: tell the user each
        outcomes[] entry's interface, status and detail.
        connected/provisioned: applied (provisioned with detail "does not
        exist, skipping" means the radio is absent).
        in_use: another tool (e.g. profiler, kismet, tcpdump) holds that radio;
        Core left it alone and there is no override. The user must stop that
        tool, then activate again.
        skipped: activating 'default' only; the interface was not created by Core.
        Errors: 422/500 mean the activation was rolled back and 'default' is
        active (the error lists outcomes or the adapter error). 404: no such
        profile. 409: another change is running (nothing changed; retry
        shortly), WLAN_MANAGEMENT=manual (Core is not managing Wi-Fi; tell the
        user), or a profile is already active (ask the user before retrying
        with override_active=true).

        Args:
            id: Configuration profile ID to activate
            override_active: Tear down the active profile first; only after the user confirms
        """
        return await client.post(
            f"/api/v1/network/config/activate/{id}",
            params={"override_active": override_active},
        )

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def deactivate_network_config(
        id: str, override_active: bool = False
    ) -> dict[str, Any]:
        """
        Deactivate the active profile; 'default' becomes current.

        Only what Core set up is reverted. left_alone lists namespaces still
        holding radios that Core did not remove: show them to the user, and
        offer reset_network_namespaces only if the user asks to clear them.
        Errors: 404 no such profile; 409 busy (retry), not the active profile,
        or WLAN_MANAGEMENT=manual.

        Args:
            id: Configuration profile ID to deactivate
            override_active: Deactivate even if this profile is not the active one
        """
        return await client.post(
            f"/api/v1/network/config/deactivate/{id}",
            params={"override_active": override_active},
        )

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def delete_network_config(id: str, force: bool = False) -> dict[str, Any]:
        """
        Delete a saved profile.

        Deleting the active profile is 409 unless force is set, which
        deactivates it first. 409 also means another change is running (retry).

        Args:
            id: Configuration profile ID to delete
            force: Deactivate and delete the profile even if it is active
        """
        return await client.delete(
            f"/api/v1/network/config/{id}",
            params={"force": force},
        )

    @mcp.tool(annotations=hints.READ_ONLY)
    async def list_network_leftovers() -> dict[str, Any]:
        """
        List namespaces holding radios that Core left alone (read-only).

        Each left_alone entry has namespace, interfaces, phys, core_created and
        reason. Namespaces of the active profile are not listed.
        """
        return await client.get("/api/v1/network/config/leftovers")

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def reset_network_namespaces(namespaces: list[str]) -> dict[str, Any]:
        """
        DESTRUCTIVE: clear the named namespaces, including other tools' ones.

        Returns every radio in them to root and deletes each once empty.
        Always confirm with the user first: list the exact namespaces (from
        left_alone or list_network_leftovers) and call only after they approve
        those names in this conversation. Never pick names yourself or reuse
        an earlier approval. Refusals are
        per-entry in results[].detail (e.g. in use by the active profile:
        deactivate it first). It does not free a radio another tool holds in
        root (e.g. profiler on wlan0): the user must stop that tool.
        Errors: 422 invalid or empty name list; 409 busy (retry) or
        WLAN_MANAGEMENT=manual.

        Args:
            namespaces: Namespace names the user confirmed for reset
        """
        return await client.post(
            "/api/v1/network/config/reset", json={"namespaces": namespaces}
        )
