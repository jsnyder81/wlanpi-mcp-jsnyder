"""
Every tool carries an explicit MCP annotation class (wlanpi_mcp/tools/hints.py).

Clients may prompt or gate on these hints, and MCP treats an unannotated tool
as destructive, so a new tool must be classified here to pass.
"""

from unittest.mock import MagicMock

import pytest

from wlanpi_mcp.server import create_server
from wlanpi_mcp.tools import hints

# Removes or overwrites state, or interrupts something in use.
DESTRUCTIVE = {
    "set_regulatory_domain",
    "set_bluetooth_power",  # off drops Bluetooth links, including BT PAN access
    "renew_dhcp_lease",  # may change the address the client is using
    "start_profiler",  # takes an adapter over for its AP
    "stop_profiler",
    "purge_profiler_data",  # deletes saved profiles and reports
    "start_service",  # e.g. wlanpi-profiler takes a radio
    "stop_service",
    "restart_service",
    "set_timezone",
    "enable_auto_timezone",
    "reboot_device",
    "shutdown_device",
    "delete_vlan",
    "update_network_config",
    "activate_network_config",
    "deactivate_network_config",
    "delete_network_config",
    "reset_network_namespaces",
}

# Changes state without removing or interrupting anything: creates something,
# or starts/stops something only this server owns.
ADDITIVE = {
    "start_bluetooth_pairing",
    "capture_scan",  # captures are refused or subscribed if a radio is in use
    "capture_observe",
    "start_pcap_file",
    "stop_pcap_file",  # this server's own capture; the file is kept
    "start_blinker",
    "stop_blinker",
    "create_vlan",
    "create_network_config",
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in create_server(MagicMock())._tool_manager.list_tools()}


def test_classes_name_real_tools(tools):
    assert (DESTRUCTIVE | ADDITIVE) - set(tools) == set()


def test_every_tool_has_its_class(tools):
    expected = {
        name: (
            hints.DESTRUCTIVE
            if name in DESTRUCTIVE
            else hints.ADDITIVE
            if name in ADDITIVE
            else hints.READ_ONLY
        )
        for name in tools
    }
    wrong = {n: t.annotations for n, t in tools.items() if t.annotations != expected[n]}
    assert wrong == {}


def test_confirmed_tools_are_destructive(tools):
    # Only a destructive action earns a protocol-level confirm (#88); asking
    # before a read-only or additive one would just be noise.
    assert hints.CONFIRMED - DESTRUCTIVE == set()
    assert hints.CONFIRMED <= set(tools)
