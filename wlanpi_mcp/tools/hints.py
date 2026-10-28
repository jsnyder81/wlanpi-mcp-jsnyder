"""
MCP tool annotations shared by every tool module.

Clients may gate or prompt on these hints. MCP treats a tool that is not
read-only as destructive by default, so every tool states one of these
classes; tests/test_tool_annotations.py pins which tool has which.
readOnlyHint defaults to false, so the two mutating classes leave it out.
"""

from mcp.types import ToolAnnotations

#: Only reads device or server state.
READ_ONLY = ToolAnnotations(readOnlyHint=True)

#: Changes state without removing, replacing or interrupting anything:
#: creates something new, or starts/stops something only this server owns.
ADDITIVE = ToolAnnotations(destructiveHint=False)

#: Removes or overwrites state, or interrupts something in use (a service,
#: a radio, a link, the device itself).
DESTRUCTIVE = ToolAnnotations(destructiveHint=True)

#: DESTRUCTIVE tools that ask the user to confirm through MCP elicitation
#: (wlanpi_mcp/elicit.py confirm()) when the client supports it, instead of
#: relying on the model to ask. The server owns these confirms, so a client
#: or extension should not add its own on top. Every name here must be
#: DESTRUCTIVE; tests/test_tool_annotations.py pins that.
CONFIRMED = frozenset(
    {
        "reboot_device",
        "shutdown_device",
        "purge_profiler_data",
        "delete_network_config",  # only with force=true
        "reset_network_namespaces",
        "set_regulatory_domain",
        "activate_network_config",  # only to replace another active profile
        "deactivate_network_config",  # only for a profile that is not active
    }
)
