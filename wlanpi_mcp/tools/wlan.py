"""MCP tools for WLAN scanning."""

from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp_types import InputRequiredResult

from wlanpi_mcp import elicit
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools import hints


def _adapter_option(candidate: dict[str, Any]) -> tuple[str, str]:
    """(value, label) for one of core's needsSelection candidates."""
    iface = str(candidate.get("iface", ""))
    namespace = str(candidate.get("namespace") or "root")
    label = str(candidate.get("label") or iface)
    where = (
        f"{iface} in {namespace}"
        if label == iface
        else f"{label} ({iface} in {namespace})"
    )
    mode = candidate.get("mode")
    return f"{namespace}/{iface}", f"{where}, {mode}" if mode else where


def register(mcp: MCPServer, client: CoreClient) -> None:
    """Register the WLAN scan tool."""

    @mcp.tool(annotations=hints.READ_ONLY)
    async def scan_wlan(
        ctx: Context,
        interface: str | None = None,
        namespace: str | None = None,
        include_hidden: bool = True,
        detail: Literal["short", "full"] = "short",
    ) -> dict[str, Any] | InputRequiredResult:
        """
        Scan for Wi-Fi networks.

        Namespace-aware, with automatic monitor adapter selection. If multiple
        monitor adapters exist and no interface is given, the user is asked to
        pick one directly when the client supports elicitation, and the scan
        runs on their choice. Otherwise (or if they decline) this returns
        'needsSelection' with candidates instead of scanning: ask the user
        which one, then call again with that interface and its namespace.

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

        async def scan(iface: str | None, ns: str | None) -> dict[str, Any]:
            params: dict[str, Any] = {"hidden": include_hidden, "detail": detail}
            if iface:
                params["iface"] = iface
            if ns:
                params["namespace"] = ns
            return await client.get("/api/v1/utils/wlan/scan", params=params)

        result = await scan(interface, namespace)
        candidates = result.get("candidates") or []
        if interface or not result.get("needsSelection") or not candidates:
            return result
        # Asking returns before anything is scanned; the retry re-reads the
        # candidates, so the choice is checked against the current adapters.
        choice = elicit.choose(
            ctx,
            "adapter",
            "Several monitor adapters can scan. Which one should scan for Wi-Fi networks?",
            [_adapter_option(c) for c in candidates],
            field="adapter",
        )
        if not isinstance(choice, str):
            return choice if choice is not None else result
        ns, _, iface = choice.partition("/")
        return await scan(iface, None if ns == "root" else ns)
