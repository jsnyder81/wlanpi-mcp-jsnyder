"""MCP tools for managing saved network configuration profiles."""

from typing import Any, NotRequired, TypedDict

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import confirms, hints


# Top-level shape of wlanpi-core's NetConfig / NetConfigUpdate. Typed so the
# tool's input schema shows namespaces and roots as arrays; with a bare dict a
# model has to guess, and a guess like "roots": "" fails at core with 422. The
# entries stay free-form objects: their fields are core's, described in the
# create_network_config docstring, and validated by core.
class NetConfig(TypedDict):
    """A network configuration profile as create_network_config sends it."""

    id: str
    namespaces: NotRequired[list[dict[str, Any]] | None]
    roots: NotRequired[list[dict[str, Any]] | None]


class NetConfigUpdate(TypedDict, total=False):
    """The lists update_network_config replaces; omit a list to keep it."""

    namespaces: list[dict[str, Any]] | None
    roots: list[dict[str, Any]] | None


def register(mcp: MCPServer, client: CoreClient) -> None:
    """Register the network configuration management tools."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def get_network_config_status() -> dict[str, Any]:
        """
        Get the status of all saved network configurations, showing which is active.

        Not an association check: 'channel' is null for a Wi-Fi 7 MLO client
        even when it is connected. Use get_wlan_link for that.
        """
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
    async def create_network_config(config: NetConfig) -> dict[str, Any]:
        """
        Create a saved network configuration profile.

        config: {id, namespaces?: [...], roots?: [...]}. id may not be default,
        root, status, leftovers or reset in any case (400).
        Each entry: mode ('managed'|'monitor', default managed),
        iface_display_name, phy (e.g. 'phy0'; advisory), interface (e.g.
        'wlan0'), namespace (namespaces only), and optional default_route
        (bool, default false), autostart_app (name defined in core's apps
        file) and security {ssid, security: WPA2-PSK|WPA3-PSK|OPEN|OWE,
        psk?}. The security block also accepts sae_pwe, pmf, identity,
        password, client_cert, private_key and ca_cert, but core does not
        apply them today: PMF is fixed by the security type and there is no
        EAP security type - don't set them.
        Rejected with 422: WPA2-PSK psk not 8-63 printable ASCII or 64 hex;
        WPA3-PSK psk not a passphrase (no 64-hex); two entries with the same
        interface; a display name equal to another entry's interface; a
        display name repeated within one namespace.

        Args:
            config: {id, namespaces?, roots?}; namespaces and roots are lists of entries
        """
        return await client.post("/api/v1/network/config/", json=config)

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def update_network_config(
        id: str, config_update: NetConfigUpdate
    ) -> dict[str, Any]:
        """
        Update a profile's namespaces and/or roots (replaces those lists).

        An entry that omits psk/password (or sends null) keeps the stored one,
        matched by (namespace, interface), so an entry from get_network_config
        can be sent back as is. If you change an entry's interface or
        namespace, the secret is not carried over: ask the user for it.
        Entries take the same fields as create_network_config and the same
        validation (422). Send only the list you are changing: an omitted
        list keeps the stored one, and [] clears it. Core refuses to edit the
        active profile (409); deactivate it first.

        Args:
            id: Configuration profile ID to update
            config_update: {namespaces?, roots?}; each a list of entries
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
        exist, skipping" means the radio is absent). Applied is not
        associated: to confirm a Wi-Fi client joined its network (including a
        Wi-Fi 7 MLO client), call get_wlan_link on that interface.
        in_use: another tool (e.g. profiler, kismet, tcpdump) holds that radio;
        Core left it alone and there is no override. The user must stop that
        tool, then activate again.
        skipped: activating 'default' only; the interface was not created by Core.
        Errors: 422 means the profile is invalid (outcomes or message say why)
        and nothing changed: a previously active profile keeps running (except
        when re-activating the active profile itself with override_active and
        outcomes are listed: it is torn down and 'default' is active). 500
        with outcomes or an adapter error means the activation was rolled back
        and 'default' is active; any other 500: check get_network_config_status.
        404: no such profile.
        409: another change is running (nothing changed; retry
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
    async def delete_network_config(
        id: str,
        ctx: Context[Any, Any],
        force: bool = False,
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Delete a saved profile.

        Deleting the active profile is 409 unless force is set, which
        deactivates it first. When force is set, the server asks the user to
        confirm over the MCP channel first, so do not ask "are you sure"
        yourself. 409 also means another change is running (retry).

        Args:
            id: Configuration profile ID to delete
            force: Deactivate and delete the profile even if it is active
        """
        if force:
            gate = confirms.confirm_gate(
                ctx,
                f"Delete network config '{id}' now? If it is active, it is "
                "deactivated first, taking down its interfaces.",
            )
            if gate is not None:
                return gate
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
    async def reset_network_namespaces(
        namespaces: list[str],
        ctx: Context[Any, Any],
    ) -> dict[str, Any] | InputRequiredResult:
        """
        DESTRUCTIVE: clear the named namespaces, including other tools' ones.

        The server asks the user to confirm over the MCP channel before
        clearing, so do not ask "are you sure" yourself. Still pass only
        namespaces the user named (from left_alone or
        list_network_leftovers): never pick names yourself or reuse an
        earlier approval.
        Returns every radio in them to root and deletes each once empty.
        Refusals are
        per-entry in results[].detail (e.g. in use by the active profile:
        deactivate it first). It does not free a radio another tool holds in
        root (e.g. profiler on wlan0): the user must stop that tool.
        Errors: 422 invalid or empty name list; 409 busy (retry) or
        WLAN_MANAGEMENT=manual.

        Args:
            namespaces: Namespace names the user confirmed for reset
        """
        # Quote each name and cap the list so a hostile or mistaken
        # namespaces value cannot stuff the confirm prompt.
        shown = ", ".join(f"'{name}'" for name in namespaces[:5])
        if len(namespaces) > 5:
            shown += f", and {len(namespaces) - 5} more"
        gate = confirms.confirm_gate(
            ctx,
            f"Reset namespaces {shown} now? Every radio in them returns to "
            "root and each namespace is deleted once empty.",
        )
        if gate is not None:
            return gate
        return await client.post(
            "/api/v1/network/config/reset", json={"namespaces": namespaces}
        )
