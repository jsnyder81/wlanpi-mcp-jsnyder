"""MCP tools for WLAN scanning."""

from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import confirms, hints


def _adapter_choices(candidates: Any) -> list[tuple[str, str, dict[str, Any]]]:
    """Turn each scan candidate into a pick option.

    Core's candidates carry iface, namespace, label and mode; no driver or
    band, so the label (e.g. 'wlanpi0 (monitor, lab)') is all the detail
    the pick can show. The option value keys interface and namespace
    together, so the same interface name in two namespaces stays two
    distinct options, and the resume entry carries both to core.
    """
    options: list[tuple[str, str, dict[str, Any]]] = []
    if not isinstance(candidates, list):
        return options
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        iface = candidate.get("iface")
        if not isinstance(iface, str) or not iface:
            continue
        namespace = candidate.get("namespace")
        if not isinstance(namespace, str) or not namespace:
            namespace = "root"
        label = candidate.get("label")
        if not isinstance(label, str) or not label:
            label = f"{iface} ({namespace})"
        entry = {"iface": iface, "namespace": namespace}
        options.append((f"{iface} ({namespace})", label, entry))
    return options


def register(mcp: MCPServer, client: CoreClient) -> None:
    """Register the WLAN scan tool."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def scan_wlan(
        ctx: Context[Any, Any],
        interface: str | None = None,
        namespace: str | None = None,
        include_hidden: bool = True,
        detail: Literal["short", "full"] = "short",
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Scan for Wi-Fi networks.

        Namespace-aware, with automatic monitor adapter selection. When
        multiple monitor adapters exist and no interface is given, the
        server asks the user to pick one over the MCP channel on clients
        that support elicitation, so do not choose or ask yourself. A
        client that cannot answer gets 'needsSelection' with candidates
        instead of a scan: ask the user, then call again with one of the
        candidate interfaces.

        Errors: 409 with error SCAN_IN_PROGRESS (that adapter is already
        scanning; retry shortly) or MONITOR_IN_USE (a capture holds a monitor
        on the same Intel radio; the capture must stop first). 422 with
        NO_SCAN_ADAPTER: no suitable adapter. 503: scan command unavailable.

        Each network's 'key_mgmt' is one of: 'wpa-psk' (WPA/WPA2-Personal),
        'sae' (WPA3-Personal), 'wpa-eap' (Enterprise), 'owe' (Enhanced Open),
        'wep', 'open' or 'unknown' (null if not reported). A WPA2/WPA3
        transition network reports 'wpa-psk', since a WPA2 client can join it;
        read 'flags' for the full AKM list (e.g. SAE alongside PSK).

        To connect to a network found by this scan, create and activate a network
        configuration (create_network_config / activate_network_config).

        Args:
            interface: WLAN interface to scan with (e.g. 'wlan0'); auto-selected if omitted
            namespace: Optional network namespace the interface lives in
            include_hidden: Include hidden SSIDs in results
            detail: 'short' for list-friendly fields plus RF extensions; 'full'
                also adds each BSS's raw 'iw scan' dump (much larger)
        """
        params: dict[str, Any] = {"hidden": include_hidden, "detail": detail}
        if interface:
            params["iface"] = interface
        if namespace:
            params["namespace"] = namespace

        resume = confirms.resume_choice(ctx)
        if resume is not None:
            choice, state = resume
            if choice is None:
                return state["result"]
            entry = state["candidates"][choice]
            chosen: dict[str, Any] = dict(state["params"])
            chosen["iface"] = entry["iface"]
            chosen["namespace"] = entry["namespace"]
            return await client.get("/api/v1/utils/wlan/scan", params=chosen)

        result = await client.get("/api/v1/utils/wlan/scan", params=params)
        if isinstance(result, dict) and result.get("needsSelection"):
            ask = confirms.choose_from(
                ctx,
                "Multiple monitor adapters are available. Which should this scan use?",
                _adapter_choices(result.get("candidates")),
                {
                    "params": {
                        k: v
                        for k, v in params.items()
                        if k not in ("iface", "namespace")
                    },
                    "result": result,
                },
            )
            if ask is not None:
                return ask
        return result
