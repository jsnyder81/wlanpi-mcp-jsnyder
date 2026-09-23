"""Server configuration via pydantic settings loaded from the config file."""

import logging
from typing import Any, Literal

from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

log = logging.getLogger(__name__)

ALLOWED_SERVICES = [
    "wlanpi-profiler",
    "wlanpi-fpms",
    "wlanpi-chat-bot",
    "bt-agent",
    "bt-network",
    "iperf",
    "iperf3",
    "tftpd-hpa",
    "hostapd",
    "wpa_supplicant",
    "wpa_supplicant@wlan0",
    "kismet",
    "grafana-server",
    "cockpit",
    "wlanpi-grafana-scanner-wlan0",
    "wlanpi-grafana-scanner-wlan1",
    "wlanpi-grafana-scanner-wlan2",
    "wlanpi-grafana-health",
    "wlanpi-grafana-internet",
    "wlanpi-grafana-wispy-24",
    "wlanpi-grafana-wispy-5",
    "wlanpi-grafana-wipry-lp-24",
    "wlanpi-grafana-wipry-lp-5",
    "wlanpi-grafana-wipry-lp-6",
    "wlanpi-grafana-wipry-lp-stop",
]

# The tools exposed under TOOL_PROFILE=classroom: reads, scans and captures.
# Anything that restarts services, power-cycles the device, reconfigures the
# network or radios, or reveals a stored credential is left out, so a leaked
# student token is read-mostly. An allowlist rather than a denylist so a new
# tool stays out of the classroom until someone decides it belongs there.
CLASSROOM_TOOLS = frozenset(
    {
        # system
        "get_device_info",
        "get_device_stats",
        "get_device_model",
        "list_allowed_services",
        "get_service_status",
        "get_datetime",
        "get_timezone",
        "list_timezones",
        "get_hotspot_clients",
        # network
        "get_network_interfaces",
        "get_network_info",
        "get_public_ipv6",
        "get_ethernet_interface",
        "get_routing_table",
        "get_tcp_connections",
        "get_udp_connections",
        "get_dhcp_leases",
        "get_interface_link_stats",
        # utils
        "get_wlan_usb_drivers",
        "get_wlan_pci_drivers",
        "get_reachability",
        "get_usb_interfaces",
        "get_ufw_status",
        "run_speedtest",
        "get_blinker_status",
        # wlan, vlan, bluetooth, network configs (read side only)
        "scan_wlan",
        "get_vlans",
        "get_bluetooth_status",
        "get_network_config_status",
        "list_network_configs",
        # profiler: a capture, owns its interface only while running
        "get_profiler_status",
        "start_profiler",
        "stop_profiler",
        # wifi and advanced
        "get_wifi_capabilities",
        "get_wifi_regulatory",
        "get_hotspot_stations",
        "get_hotspot_link_stats",
        "get_device_mode",
        "get_regulatory_domain",
        "get_battery_status",
        # packet capture, streaming and file-backed
        "capture_scan",
        "capture_observe",
        "list_capture_sessions",
        "get_capture_channels",
        "start_pcap_file",
        "stop_pcap_file",
        "list_pcap_files",
        "fetch_pcap_file",
    }
)

#: Settings that must come from the process environment, never a config file.
ENV_ONLY_SETTINGS = frozenset({"WLANPI_CORE_TOKEN"})


class _WithoutEnvOnly(PydanticBaseSettingsSource):
    """Wrap the config-file source so it cannot supply an env-only setting."""

    def __init__(
        self, settings_cls: type[BaseSettings], source: PydanticBaseSettingsSource
    ) -> None:
        super().__init__(settings_cls)
        self._source = source

    def get_field_value(
        self, field: FieldInfo, field_name: str
    ) -> tuple[Any, str, bool]:
        return self._source.get_field_value(field, field_name)

    def __call__(self) -> dict[str, Any]:
        values = self._source()
        for name in ENV_ONLY_SETTINGS & values.keys():
            log.warning(
                "Ignoring %s from the config file: a token must be supplied "
                "through the environment, never a file on disk",
                name,
            )
            del values[name]
        return values


class Settings(BaseSettings):
    """Pydantic settings for the WLAN Pi MCP server."""

    WLANPI_CORE_URL: str = "https://localhost:31415"
    WLANPI_CORE_CA: str = "/etc/nginx/ssl/self-signed-wlanpi.cert"
    # Fallback wlanpi-core JWT for stdio transport, where there is no HTTP
    # Authorization header to pass through. Leave empty in HTTP/daemon mode.
    # Read from the process environment only (inject it from a keychain or a
    # 0600 env file at launch); a value in config.env is ignored.
    WLANPI_CORE_TOKEN: str = ""
    # Gate for the reboot_device/shutdown_device tools. Set false to prevent
    # MCP clients from power-cycling the device.
    ALLOW_POWER_CONTROL: bool = True
    # Loopback-only: nginx fronts the HTTP daemon on 8767 (TLS) and 8766
    # (plaintext fallback), so the JWT never crosses the LAN unauthenticated.
    WLANPI_MCP_HOST: str = "127.0.0.1"
    # 8768: loopback-only upstream for the nginx fronts on 8766/8767.
    # Avoids colliding with the wlanpi-fpms2 state service on 8765.
    WLANPI_MCP_PORT: int = 8768
    LOG_LEVEL: str = "INFO"
    # File-backed capture (start_pcap_file/fetch_pcap_file). Raw pcapng files
    # are written here and fetch refuses any path outside this directory.
    PCAP_CAPTURE_DIR: str = "/tmp/wlanpi-mcp/captures"
    # Ceiling on a single file capture's duration, in seconds.
    PCAP_MAX_DURATION_S: int = 3600
    # Which tools the server exposes. "full" registers everything;
    # "classroom" exposes only CLASSROOM_TOOLS (reads, scans, captures).
    TOOL_PROFILE: Literal["full", "classroom"] = "full"
    # Comma-separated tool names. When set, exactly these tools are exposed
    # and TOOL_PROFILE is ignored. Unknown names fail startup.
    TOOL_ALLOWLIST: str = ""

    model_config = SettingsConfigDict(
        env_file="/etc/wlanpi-mcp/config.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Load as pydantic-settings does, but keep tokens out of config.env."""
        return (
            init_settings,
            env_settings,
            _WithoutEnvOnly(settings_cls, dotenv_settings),
            file_secret_settings,
        )

    def enabled_tools(self) -> frozenset[str] | None:
        """Return the tool names to expose, or None to expose every tool."""
        explicit = {name.strip() for name in self.TOOL_ALLOWLIST.split(",")}
        explicit.discard("")
        if explicit:
            return frozenset(explicit)
        if self.TOOL_PROFILE == "classroom":
            return CLASSROOM_TOOLS
        return None


def get_settings() -> Settings:
    """Return the server settings from the config file."""
    return Settings()
