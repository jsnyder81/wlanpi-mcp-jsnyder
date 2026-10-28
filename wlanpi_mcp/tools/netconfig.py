"""MCP tools for managing saved network configuration profiles."""

import re
from typing import Any, NotRequired, TypedDict

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import InputRequiredResult

from wlanpi_mcp import download_links, elicit
from wlanpi_mcp.client.core_client import CoreAPIError, CoreClient
from wlanpi_mcp.tools import hints, netconfig_secrets

# Core's 409 details (wlanpi_core/utils/network_config.py ConfigActiveError)
# for the cases override_active resolves. The other 409s (a change is
# running, WLAN_MANAGEMENT=manual) are not the user's call to override.
_ANOTHER_ACTIVE = re.compile(r"^Another configuration is currently active: (.+)\.$")
_ALREADY_ACTIVE = re.compile(r"^Configuration .+ is already active\.$")
_NOT_ACTIVE = re.compile(r"^Configuration .+ is not active\.$")


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
    netconfig_secrets.register_routes(mcp)

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
    async def create_network_config(
        config: NetConfig, ctx: Context
    ) -> dict[str, Any] | InputRequiredResult:
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
        Passphrases: when the client supports URL elicitation, leave psk out
        of a WPA2-PSK/WPA3-PSK entry and don't ask for it in the chat: the
        server asks the user to type it into a page on the WLAN Pi, so it
        never passes through the conversation, then creates the profile. A
        'not_performed' status means they declined. Otherwise a PSK entry
        needs psk set; without one core saves the profile but it cannot
        connect when activated.
        Rejected with 422: WPA2-PSK psk not 8-63 printable ASCII or 64 hex;
        WPA3-PSK psk not a passphrase (no 64-hex); two entries with the same
        interface; a display name equal to another entry's interface; a
        display name repeated within one namespace.

        Args:
            config: {id, namespaces?, roots?}; namespaces and roots are lists of entries
        """
        slots = netconfig_secrets.slots_needing_secret(dict(config))
        route = elicit.state(ctx).get("secret_route")
        if route is None:
            base = download_links.request_base_url()
            if not slots or not elicit.can_url(ctx) or base is None:
                # As before: core stores a PSK entry without one, and it
                # fails only when activated.
                return await client.post("/api/v1/network/config/", json=config)
            refused = await download_links.check_token(client)
            if refused:
                return {"error": refused}
            route = netconfig_secrets.mint(config["id"], slots)
            networks = ", ".join(f"'{s.ssid}'" for s in slots)
            return elicit.ask(
                ctx,
                "secret_page",
                elicit.url_request(
                    f"Network profile '{config['id']}' needs the Wi-Fi "
                    f"passphrase for {networks}. Open the WLAN Pi's page to "
                    "type it there, so it never goes through the AI "
                    "conversation. The page uses the WLAN Pi's own "
                    "certificate, so your browser may warn about it first.",
                    f"{base}{route}",
                ),
                secret_route=route,
            )

        declined = [
            reply
            for key in ("secret_page", "secret_done")
            if (reply := elicit.answer(ctx, key)) is not None and not reply.accepted
        ]
        if declined:
            netconfig_secrets.discard(route)
            return elicit.not_performed(
                f"enter the Wi-Fi passphrase, so profile '{config['id']}' was not created"
            )
        try:
            filled = netconfig_secrets.take(route)
        except netconfig_secrets.TicketGone:
            return {
                "error": (
                    "the passphrase page expired or was already used; call "
                    "create_network_config again to get a new one"
                )
            }
        if filled is None:
            # The client usually retries as soon as the page opens, before
            # the user has typed anything: wait for them to say they're done.
            return elicit.ask(
                ctx,
                "secret_done",
                elicit.form_request(
                    "Enter the passphrase on the WLAN Pi page and press Save, "
                    f"then accept here to create profile '{config['id']}'."
                ),
            )
        try:
            return await client.post(
                "/api/v1/network/config/",
                json=netconfig_secrets.apply(dict(config), filled),
            )
        except CoreAPIError as exc:
            # Core's 422 echoes the request body, passphrases included: keep
            # them out of the error the model (and the log) sees.
            raise ToolError(
                netconfig_secrets.redact(str(exc), filled)
                + " The passphrase was not saved; fix the profile and call "
                "create_network_config again."
            ) from None

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
        id: str, ctx: Context, override_active: bool = False
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Activate a saved profile.

        Always call with override_active=false first. Never set it true on
        your own: if another profile is active, or this one already is, ask
        the user whether to replace or re-apply it, even if they already asked
        to activate this one. When the client supports elicitation the server
        asks the user that question itself (and ignores an override_active you
        set) and you get either the activation or the 409 back: do not ask
        again, and if the error says the user declined, do not retry with
        override_active.
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
        user), or a profile, possibly this one, is already active (ask the
        user before retrying with override_active=true).

        Args:
            id: Configuration profile ID to activate
            override_active: Tear down the active profile first; only after the user confirms
        """
        reply = elicit.answer(ctx, "replace_active")
        if reply is not None:
            carried = elicit.state(ctx)
            if not reply.accepted:
                active = carried.get("active")
                what = (
                    f"re-apply '{id}', which is already active"
                    if active == id
                    else f"replace the active profile '{active}'"
                )
                raise ToolError(
                    f"{carried.get('core_error', '')} The user declined to "
                    f"{what}; nothing changed. Do not retry with override_active."
                )
            override_active = True
        elif elicit.can_form(ctx):
            # The user answers this one, not the model: an override_active the
            # model set itself must not skip the question. Core refuses only
            # without the override, so drop it and let the 409 ask.
            override_active = False
        try:
            return await client.post(
                f"/api/v1/network/config/activate/{id}",
                params={"override_active": override_active},
            )
        except CoreAPIError as exc:
            if exc.status_code != 409 or not elicit.can_form(ctx):
                raise
            detail = str(exc.detail)
            if match := _ANOTHER_ACTIVE.match(detail):
                active = match.group(1)
                message = (
                    f"Replace it with '{id}'? '{active}' is torn down first, "
                    "so its connections drop."
                )
            elif _ALREADY_ACTIVE.match(detail):
                active = id
                message = (
                    f"Re-apply it? '{id}' is torn down and set up again, so its "
                    "connections drop briefly."
                )
            else:
                raise
            name = await elicit.device_name(client)
            return elicit.ask(
                ctx,
                "replace_active",
                elicit.form_request(
                    f"'{active}' is the active network profile on {name}. {message}"
                ),
                active=active,
                core_error=str(exc),
            )

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def deactivate_network_config(
        id: str, ctx: Context, override_active: bool = False
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Deactivate the active profile; 'default' becomes current.

        Only what Core set up is reverted. left_alone lists namespaces still
        holding radios that Core did not remove: show them to the user, and
        offer reset_network_namespaces only if the user asks to clear them.
        Errors: 404 no such profile; 409 busy (retry), not the active profile,
        or WLAN_MANAGEMENT=manual. For 'not the active profile', override_active
        tears down that profile's entries anyway and returns every radio to
        root, which also disrupts whatever profile is active: ask the user
        first. When the client supports elicitation the server asks itself
        (and ignores an override_active you set); if the error says the user
        declined, do not retry.

        Args:
            id: Configuration profile ID to deactivate
            override_active: Deactivate even if this profile is not the active one
        """
        reply = elicit.answer(ctx, "deactivate_inactive")
        if reply is not None:
            if not reply.accepted:
                raise ToolError(
                    f"{elicit.state(ctx).get('core_error', '')} The user declined "
                    f"to deactivate '{id}' while it is not the active profile; "
                    "nothing changed. Do not retry with override_active."
                )
            override_active = True
        elif elicit.can_form(ctx):
            # As in activate_network_config: the user answers, not the model.
            override_active = False
        try:
            return await client.post(
                f"/api/v1/network/config/deactivate/{id}",
                params={"override_active": override_active},
            )
        except CoreAPIError as exc:
            if (
                exc.status_code != 409
                or not _NOT_ACTIVE.match(str(exc.detail))
                or not elicit.can_form(ctx)
            ):
                raise
            name = await elicit.device_name(client)
            return elicit.ask(
                ctx,
                "deactivate_inactive",
                elicit.form_request(
                    f"'{id}' is not the active network profile on {name}. "
                    "Deactivate it anyway? Its entries are torn down and every "
                    "radio returns to the root namespace, which also disrupts "
                    "the profile that is active now."
                ),
                core_error=str(exc),
            )

    @mcp.tool(annotations=hints.DESTRUCTIVE)
    async def delete_network_config(
        id: str, ctx: Context, force: bool = False
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Delete a saved profile.

        Deleting the active profile is 409 unless force is set, which
        deactivates it first. 409 also means another change is running (retry).
        With force, the user is asked to confirm directly when the client
        supports elicitation; a 'not_performed' status means they declined -
        do not retry.

        Args:
            id: Configuration profile ID to delete
            force: Deactivate and delete the profile even if it is active
        """
        if force:

            async def message() -> str:
                name = await elicit.device_name(client)
                return (
                    f"Delete network profile '{id}' on {name}, deactivating it "
                    "first if it is active? Its connections drop and the saved "
                    "profile, including its passphrases, is gone."
                )

            stop = await elicit.confirm(
                ctx, "force_delete", message, f"delete network profile '{id}'"
            )
            if stop is not None:
                return stop
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
        namespaces: list[str], ctx: Context
    ) -> dict[str, Any] | InputRequiredResult:
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

        When the client supports elicitation, the server also asks the user
        to confirm the exact names; a 'not_performed' status means they
        declined - do not retry.

        Args:
            namespaces: Namespace names the user confirmed for reset
        """
        listed = ", ".join(f"'{n}'" for n in namespaces) or "(none)"

        async def message() -> str:
            name = await elicit.device_name(client)
            return (
                f"Clear the network namespaces {listed} on {name}? Every radio "
                "in them returns to root, including ones other tools are using."
            )

        stop = await elicit.confirm(
            ctx, "reset_namespaces", message, f"reset namespaces {listed}"
        )
        if stop is not None:
            return stop
        return await client.post(
            "/api/v1/network/config/reset", json={"namespaces": namespaces}
        )
