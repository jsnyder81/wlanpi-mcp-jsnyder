"""
Elicitation confirms: pre-action (#88) and mid-flow override_active (#86).

A client that declares form elicitation gets a protocol-level confirm before
anything destructive runs; every other client sees the pre-#88 behavior
byte for byte. These tests cover the helpers in
wlanpi_mcp/tools/confirms.py and the round-trip through real registered
tools.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import (
    ClientCapabilities,
    ElicitationCapability,
    ElicitResult,
    FormElicitationCapability,
    InputRequiredResult,
    UrlElicitationCapability,
)

from wlanpi_mcp.client.core_client import CoreAPIError
from wlanpi_mcp.tools import netconfig, system
from wlanpi_mcp.tools.confirms import (
    _REQUEST_STATE,
    CONFIRM_KEY,
    confirm_gate,
    form_elicitations_supported,
    resume_with_state,
)

FORM_CAPS = ClientCapabilities(
    elicitation=ElicitationCapability(form=FormElicitationCapability())
)
URL_ONLY_CAPS = ClientCapabilities(
    elicitation=ElicitationCapability(url=UrlElicitationCapability())
)
BARE_CAPS = ClientCapabilities(elicitation=ElicitationCapability())

MODERN = "2026-07-28"


def _ctx(
    capabilities: ClientCapabilities | None,
    responses: dict[str, ElicitResult] | None = None,
    state: str | None = None,
    version: str | None = MODERN,
) -> Context[Any, Any]:
    """Build a Context fake exposing just the properties the helpers read."""
    ctx = MagicMock(spec=Context)
    ctx.client_capabilities = capabilities
    ctx.input_responses = responses
    ctx.request_state = state
    ctx.protocol_version = version
    return ctx


def _tools(module, client):
    mcp = MCPServer("test")
    module.register(mcp, client)
    return mcp._tool_manager._tools


def _accept(confirm=True):
    responses = {
        CONFIRM_KEY: ElicitResult(action="accept", content={"confirm": confirm})
    }
    return _ctx(FORM_CAPS, responses, state="asked")


# ── form_elicitations_supported ──────────────────────────────────────────────


def test_supported_with_form_capability():
    assert form_elicitations_supported(_ctx(FORM_CAPS)) is True


def test_supported_with_bare_elicitation():
    # A bare `elicitation: {}` predates modes and means form support.
    assert form_elicitations_supported(_ctx(BARE_CAPS)) is True


def test_not_supported_url_only():
    assert form_elicitations_supported(_ctx(URL_ONLY_CAPS)) is False


def test_not_supported_no_capabilities():
    assert form_elicitations_supported(_ctx(None)) is False


def test_not_supported_old_protocol():
    # input_required results do not exist before 2026-07-28, so a capable
    # client on an older revision must not be asked.
    assert form_elicitations_supported(_ctx(FORM_CAPS, version="2025-11-25")) is False


def test_not_supported_outside_a_request():
    # A bare Context() has no request: no version, no client to ask.
    assert form_elicitations_supported(Context()) is False


# ── confirm_gate ─────────────────────────────────────────────────────────────


def test_gate_noop_without_capability():
    assert confirm_gate(_ctx(None), "msg") is None


def test_gate_asks_on_first_round():
    gate = confirm_gate(_ctx(FORM_CAPS), "msg")
    assert isinstance(gate, InputRequiredResult)
    request = gate.input_requests[CONFIRM_KEY]
    assert request.params.message == "msg"
    schema = request.params.requested_schema
    assert schema["properties"]["confirm"]["type"] == "boolean"
    assert schema["required"] == ["confirm"]
    # The state is sealed by RequestStateBoundary to bind the retry.
    assert gate.request_state is not None


@pytest.mark.parametrize("action", ["decline", "cancel"])
def test_gate_reports_decline(action):
    responses = {CONFIRM_KEY: ElicitResult(action=action)}
    gate_ctx = _ctx(FORM_CAPS, responses, state="asked")
    assert confirm_gate(gate_ctx, "msg") == {
        "performed": False,
        "reason": "user declined or dismissed",
    }


def test_gate_proceeds_on_accepted_checkbox():
    assert confirm_gate(_accept(), "msg") is None


def test_gate_declines_unchecked_box():
    # An unchecked form still arrives as action "accept": content decides.
    assert confirm_gate(_accept(confirm=False), "msg") == {
        "performed": False,
        "reason": "user declined or dismissed",
    }


def test_gate_declines_accept_without_content():
    responses = {CONFIRM_KEY: ElicitResult(action="accept")}
    gate_ctx = _ctx(FORM_CAPS, responses, state="asked")
    assert confirm_gate(gate_ctx, "msg") == {
        "performed": False,
        "reason": "user declined or dismissed",
    }


def test_gate_reasks_on_answers_without_a_prior_ask():
    # input_responses alone is not a retry: the echoed requestState proves
    # the server asked first, so this cannot skip the confirm.
    responses = {CONFIRM_KEY: ElicitResult(action="accept", content={"confirm": True})}
    gate = confirm_gate(_ctx(FORM_CAPS, responses), "msg")
    assert isinstance(gate, InputRequiredResult)


def test_gate_reasks_on_retry_without_answers():
    assert isinstance(
        confirm_gate(_ctx(FORM_CAPS, None, state="asked"), "msg"), InputRequiredResult
    )


def test_gate_reasks_on_other_keys():
    other = {"elsewhere": ElicitResult(action="accept", content={"confirm": True})}
    gate = confirm_gate(_ctx(FORM_CAPS, other, state="asked"), "msg")
    assert isinstance(gate, InputRequiredResult)


# ── end to end through a registered tool ─────────────────────────────────────


@pytest.fixture
def power_client():
    client = MagicMock()
    client.post = AsyncMock(return_value={"success": True})
    return client


async def test_reboot_asks_then_proceeds_on_accept(power_client, monkeypatch):
    monkeypatch.setenv("ALLOW_POWER_CONTROL", "true")
    tool = _tools(system, power_client)["reboot_device"]

    first = await tool.run({}, _ctx(FORM_CAPS))
    assert isinstance(first, InputRequiredResult)
    assert "Reboot the WLAN Pi now?" in first.input_requests[CONFIRM_KEY].params.message
    power_client.post.assert_not_awaited()

    retry = _accept()
    retry.request_state = first.request_state
    assert await tool.run({}, retry) == {"success": True}
    power_client.post.assert_awaited_once_with("/api/v1/system/reboot")


async def test_reboot_unchecked_box_is_a_decline_not_an_error(
    power_client, monkeypatch
):
    monkeypatch.setenv("ALLOW_POWER_CONTROL", "true")
    tool = _tools(system, power_client)["reboot_device"]

    first = await tool.run({}, _ctx(FORM_CAPS))
    retry = _accept(confirm=False)
    retry.request_state = first.request_state
    result = await tool.run({}, retry)
    assert result == {"performed": False, "reason": "user declined or dismissed"}
    power_client.post.assert_not_awaited()


async def test_reboot_declined_is_not_an_error(power_client, monkeypatch):
    monkeypatch.setenv("ALLOW_POWER_CONTROL", "true")
    tool = _tools(system, power_client)["reboot_device"]

    responses = {CONFIRM_KEY: ElicitResult(action="decline")}
    result = await tool.run({}, _ctx(FORM_CAPS, responses, state="asked"))
    assert result == {"performed": False, "reason": "user declined or dismissed"}
    power_client.post.assert_not_awaited()


async def test_reboot_without_capability_is_unchanged(power_client, monkeypatch):
    monkeypatch.setenv("ALLOW_POWER_CONTROL", "true")
    tool = _tools(system, power_client)["reboot_device"]

    assert await tool.run({}, _ctx(None)) == {"success": True}
    power_client.post.assert_awaited_once_with("/api/v1/system/reboot")


async def test_power_control_gate_still_short_circuits_first(power_client, monkeypatch):
    # Disabled power control answers before any confirm is considered.
    monkeypatch.setenv("ALLOW_POWER_CONTROL", "false")
    tool = _tools(system, power_client)["reboot_device"]

    result = await tool.run({}, _ctx(FORM_CAPS))
    assert "error" in result
    power_client.post.assert_not_awaited()


async def test_delete_config_confirms_only_when_force():
    core = MagicMock()
    core.delete = AsyncMock(return_value={"success": True})
    tool = _tools(netconfig, core)["delete_network_config"]

    # force=false: no confirm, straight through (unchanged behavior).
    assert await tool.run({"id": "lab"}, _ctx(FORM_CAPS)) == {"success": True}
    core.delete.assert_awaited_once_with(
        "/api/v1/network/config/lab", params={"force": False}
    )

    # force=true: first round asks, naming the profile.
    first = await tool.run({"id": "lab", "force": True}, _ctx(FORM_CAPS))
    assert isinstance(first, InputRequiredResult)
    assert "'lab'" in first.input_requests[CONFIRM_KEY].params.message

    retry = _accept()
    retry.request_state = first.request_state
    assert await tool.run({"id": "lab", "force": True}, retry) == {"success": True}
    core.delete.assert_awaited_with(
        "/api/v1/network/config/lab", params={"force": True}
    )


async def test_reset_namespaces_message_quotes_and_caps_names():
    core = MagicMock()
    core.post = AsyncMock(return_value={"results": []})
    tool = _tools(netconfig, core)["reset_network_namespaces"]

    names = [f"ns{i}" for i in range(8)]
    first = await tool.run({"namespaces": names}, _ctx(FORM_CAPS))
    message = first.input_requests[CONFIRM_KEY].params.message
    assert "'ns0'" in message and "'ns4'" in message
    assert "'ns5'" not in message
    assert "and 3 more" in message


# ── mid-flow override_active confirms (#86) ──────────────────────────────────

# Core's ConfigActiveError strings, verified against wlanpi-core main.
ACTIVE_409 = "Another configuration is currently active: office."
NOT_ACTIVE_409 = "Configuration lab is not active."
BUSY_409 = "Another network configuration change is in progress; try again."
ALREADY_409 = "Configuration lab is already active."


def _409(detail):
    """Build a CoreAPIError as the activate/deactivate routes raise it: 409 JSON."""
    response = httpx.Response(
        409,
        json={"detail": detail},
        request=httpx.Request("POST", "https://localhost:31415/api/v1/network"),
    )
    return CoreAPIError(response)


def _refusing_core(refusal, success):
    """Return a fake core that refuses without the override and answers with it."""

    async def post(path, params=None, **kwargs):
        if params and params.get("override_active"):
            return success
        raise refusal

    core = MagicMock()
    core.post = AsyncMock(side_effect=post)
    core.get = AsyncMock(return_value={})
    return core


def _declined_ctx(first, action):
    return _ctx(
        FORM_CAPS, {CONFIRM_KEY: ElicitResult(action=action)}, state=first.request_state
    )


def test_resume_state_ignores_foreign_states():
    responses = {CONFIRM_KEY: ElicitResult(action="accept", content={"confirm": True})}
    # confirm_gate's constant, a marked-less JSON dict, junk, and no state
    # at all are not our retries.
    assert resume_with_state(_ctx(FORM_CAPS, responses, state=_REQUEST_STATE)) is None
    assert (
        resume_with_state(_ctx(FORM_CAPS, responses, state='{"op": "activate"}'))
        is None
    )
    assert resume_with_state(_ctx(FORM_CAPS, responses, state="{not json")) is None
    assert resume_with_state(_ctx(FORM_CAPS, responses)) is None


async def test_activate_409_without_capability_is_unchanged():
    core = _refusing_core(_409(ACTIVE_409), {})
    tool = _tools(netconfig, core)["activate_network_config"]

    with pytest.raises(ToolError) as err:
        await tool.run({"id": "lab"}, _ctx(None))
    assert "409" in str(err.value)
    core.post.assert_awaited_once_with(
        "/api/v1/network/config/activate/lab", params={"override_active": False}
    )


async def test_activate_success_with_capability_is_not_confirmed():
    # No refusal, no ask: a straight success passes through untouched.
    applied = {"id": "lab", "message": "Configuration activated successfully"}
    core = MagicMock()
    core.post = AsyncMock(return_value=applied)
    tool = _tools(netconfig, core)["activate_network_config"]

    assert await tool.run({"id": "lab"}, _ctx(FORM_CAPS)) == applied
    core.post.assert_awaited_once_with(
        "/api/v1/network/config/activate/lab", params={"override_active": False}
    )


async def test_activate_409_asks_naming_both_profiles():
    core = _refusing_core(_409(ACTIVE_409), {})
    tool = _tools(netconfig, core)["activate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    assert isinstance(first, InputRequiredResult)
    message = first.input_requests[CONFIRM_KEY].params.message
    assert "'office'" in message and "'lab'" in message
    core.post.assert_awaited_once()


async def test_activate_accept_retries_core_with_override():
    applied = {"id": "lab", "message": "Configuration activated successfully"}
    core = _refusing_core(_409(ACTIVE_409), applied)
    tool = _tools(netconfig, core)["activate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    retry = _accept()
    retry.request_state = first.request_state
    assert await tool.run({"id": "lab"}, retry) == applied
    assert core.post.await_args_list[1].kwargs["params"] == {"override_active": True}


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_activate_decline_returns_409_detail(action):
    core = _refusing_core(_409(ACTIVE_409), {})
    tool = _tools(netconfig, core)["activate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    assert await tool.run({"id": "lab"}, _declined_ctx(first, action)) == {
        "performed": False,
        "reason": "user declined or dismissed",
        "detail": ACTIVE_409,
    }
    core.post.assert_awaited_once()


async def test_activate_unchecked_box_is_a_decline():
    core = _refusing_core(_409(ACTIVE_409), {})
    tool = _tools(netconfig, core)["activate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    retry = _accept(confirm=False)
    retry.request_state = first.request_state
    result = await tool.run({"id": "lab"}, retry)
    assert result["performed"] is False
    core.post.assert_awaited_once()


async def test_activate_override_true_cannot_skip_the_confirm():
    # A model that sets override_active itself must not bypass the confirm:
    # for a capable client the server drops it and lets the 409 drive the
    # ask, then honors it on the accepted retry.
    applied = {"id": "lab", "message": "Configuration activated successfully"}
    core = _refusing_core(_409(ACTIVE_409), applied)
    tool = _tools(netconfig, core)["activate_network_config"]

    first = await tool.run({"id": "lab", "override_active": True}, _ctx(FORM_CAPS))
    assert isinstance(first, InputRequiredResult)
    assert core.post.await_args.kwargs["params"] == {"override_active": False}

    retry = _accept()
    retry.request_state = first.request_state
    assert await tool.run({"id": "lab", "override_active": True}, retry) == applied
    assert core.post.await_args_list[1].kwargs["params"] == {"override_active": True}


async def test_activate_other_409s_are_not_confirmed():
    # The busy refusal must surface as it does today.
    core = _refusing_core(_409(BUSY_409), {})
    tool = _tools(netconfig, core)["activate_network_config"]

    with pytest.raises(ToolError):
        await tool.run({"id": "lab"}, _ctx(FORM_CAPS))


async def test_activate_already_active_409_asks_to_reapply():
    # Re-activating the active profile is a teardown plus re-apply, so it
    # confirms too rather than dead-ending a downgraded override.
    applied = {"id": "lab", "message": "Configuration activated successfully"}
    core = _refusing_core(_409(ALREADY_409), applied)
    tool = _tools(netconfig, core)["activate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    assert isinstance(first, InputRequiredResult)
    message = first.input_requests[CONFIRM_KEY].params.message
    assert "already active" in message and "'lab'" in message

    retry = _accept()
    retry.request_state = first.request_state
    assert await tool.run({"id": "lab"}, retry) == applied
    assert core.post.await_args_list[1].kwargs["params"] == {"override_active": True}


async def test_activate_409_without_a_name_falls_back():
    # Core phrasing drift: still confirmable, but the message cannot name
    # the active profile.
    core = _refusing_core(_409("Another configuration is currently active."), {})
    tool = _tools(netconfig, core)["activate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    message = first.input_requests[CONFIRM_KEY].params.message
    assert "Another profile is currently active" in message


async def test_activate_answers_without_a_prior_ask_cannot_skip():
    core = _refusing_core(_409(ACTIVE_409), {})
    tool = _tools(netconfig, core)["activate_network_config"]

    responses = {CONFIRM_KEY: ElicitResult(action="accept", content={"confirm": True})}
    result = await tool.run({"id": "lab"}, _ctx(FORM_CAPS, responses))
    assert isinstance(result, InputRequiredResult)
    core.post.assert_awaited_once()


async def test_activate_retry_without_answer_reasks():
    core = _refusing_core(_409(ACTIVE_409), {})
    tool = _tools(netconfig, core)["activate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    second = await tool.run({"id": "lab"}, _ctx(FORM_CAPS, None, first.request_state))
    assert isinstance(second, InputRequiredResult)


async def test_deactivate_409_asks_naming_both_profiles():
    done = {"id": "lab", "message": "Configuration deactivated successfully"}
    core = _refusing_core(_409(NOT_ACTIVE_409), done)
    core.get = AsyncMock(return_value={"office": True, "lab": False})
    tool = _tools(netconfig, core)["deactivate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    assert isinstance(first, InputRequiredResult)
    message = first.input_requests[CONFIRM_KEY].params.message
    assert "'office'" in message and "'lab'" in message


async def test_deactivate_accept_retries_core_with_override():
    done = {"id": "lab", "message": "Configuration deactivated successfully"}
    core = _refusing_core(_409(NOT_ACTIVE_409), done)
    core.get = AsyncMock(return_value={"office": True, "lab": False})
    tool = _tools(netconfig, core)["deactivate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    retry = _accept()
    retry.request_state = first.request_state
    assert await tool.run({"id": "lab"}, retry) == done
    assert core.post.await_args_list[1].kwargs["params"] == {"override_active": True}


async def test_deactivate_override_true_cannot_skip_the_confirm():
    done = {"id": "lab", "message": "Configuration deactivated successfully"}
    core = _refusing_core(_409(NOT_ACTIVE_409), done)
    core.get = AsyncMock(return_value={"office": True, "lab": False})
    tool = _tools(netconfig, core)["deactivate_network_config"]

    first = await tool.run({"id": "lab", "override_active": True}, _ctx(FORM_CAPS))
    assert isinstance(first, InputRequiredResult)
    assert core.post.await_args.kwargs["params"] == {"override_active": False}
    core.get.assert_awaited_once()


async def test_activate_override_true_passes_through_without_capability():
    # Legacy behavior for clients that cannot answer: the model's override
    # reaches core untouched.
    applied = {"id": "lab", "message": "Configuration activated successfully"}
    core = _refusing_core(_409(ACTIVE_409), applied)
    tool = _tools(netconfig, core)["activate_network_config"]

    assert await tool.run({"id": "lab", "override_active": True}, _ctx(None)) == applied
    assert core.post.await_args.kwargs["params"] == {"override_active": True}


async def test_deactivate_override_true_passes_through_without_capability():
    # Legacy behavior for clients that cannot answer: the model's override
    # reaches core untouched.
    done = {"id": "lab", "message": "Configuration deactivated successfully"}
    core = _refusing_core(_409(NOT_ACTIVE_409), done)
    tool = _tools(netconfig, core)["deactivate_network_config"]

    assert await tool.run({"id": "lab", "override_active": True}, _ctx(None)) == done
    assert core.post.await_args.kwargs["params"] == {"override_active": True}
    core.get.assert_not_awaited()


async def test_deactivate_decline_returns_409_detail():
    core = _refusing_core(_409(NOT_ACTIVE_409), {})
    tool = _tools(netconfig, core)["deactivate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    assert await tool.run({"id": "lab"}, _declined_ctx(first, "decline")) == {
        "performed": False,
        "reason": "user declined or dismissed",
        "detail": NOT_ACTIVE_409,
    }
    core.post.assert_awaited_once()


async def test_deactivate_active_lookup_failure_falls_back():
    # The name lookup is cosmetic: its failure must not eat the confirm.
    core = _refusing_core(_409(NOT_ACTIVE_409), {})
    core.get = AsyncMock(side_effect=_409("nope"))
    tool = _tools(netconfig, core)["deactivate_network_config"]

    first = await tool.run({"id": "lab"}, _ctx(FORM_CAPS))
    assert isinstance(first, InputRequiredResult)
    message = first.input_requests[CONFIRM_KEY].params.message
    assert "'lab'" in message and "is not the active profile." in message


async def test_deactivate_409_without_capability_is_unchanged():
    core = _refusing_core(_409(NOT_ACTIVE_409), {})
    tool = _tools(netconfig, core)["deactivate_network_config"]

    with pytest.raises(ToolError):
        await tool.run({"id": "lab"}, _ctx(None))
    core.get.assert_not_awaited()
