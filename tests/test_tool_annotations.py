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
    "profile_clients",  # starts and stops the profiler as one task
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

# Tools the server gates with an elicitation confirm (#88). The Pi owns
# these confirms, so the browser extension must not double-confirm; every
# entry must also be DESTRUCTIVE, and a new destructive tool must be added
# here or justified by omission.
CONFIRMED = {
    "reboot_device",
    "shutdown_device",
    "purge_profiler_data",
    "profile_clients",  # takes a radio before the task even starts
    "delete_network_config",  # only when force=true
    "reset_network_namespaces",
    "set_regulatory_domain",
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


def test_confirmed_tools_are_destructive():
    assert CONFIRMED - DESTRUCTIVE == set()
