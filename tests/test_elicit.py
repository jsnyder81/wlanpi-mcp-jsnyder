"""Elicitation confirms, picks and passphrase pages over the real /mcp dispatch.

Every flow here is multi-round-trip (2026-07-28): the tool answers with an
input_required result, and the client retries the same call with the user's
answer and the sealed requestState. Clients that cannot elicit must get the
tool's behaviour from before (#86-#89).
"""

import json
import re
from urllib.parse import urlencode

import httpx
import pytest
import respx

from tests import wire
from tests.test_server import _serve
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.server import create_server
from wlanpi_mcp.tools import netconfig_secrets

CORE = wire.CORE
DEVICE_INFO = f"{CORE}/api/v1/system/device/info"


@pytest.fixture
def mcp(settings):
    return create_server(CoreClient(settings))


@pytest.fixture(autouse=True)
def _device_info():
    with respx.mock(assert_all_called=False) as router:
        router.get(DEVICE_INFO).mock(
            return_value=httpx.Response(200, json={"hostname": "wlanpi-9be"})
        )
        yield router


@pytest.fixture(autouse=True)
def _clean_secret_tickets():
    netconfig_secrets._TICKETS.clear()
    yield
    netconfig_secrets._TICKETS.clear()


# ── #88: destructive confirms ────────────────────────────────────────────────

# (tool, arguments, core method, core path) for each confirmed action.
CONFIRMED_CALLS = [
    ("reboot_device", {}, "POST", "/api/v1/system/reboot"),
    ("shutdown_device", {}, "POST", "/api/v1/system/shutdown"),
    ("purge_profiler_data", {}, "POST", "/api/v1/profiler/purge"),
    (
        "delete_network_config",
        {"id": "lab", "force": True},
        "DELETE",
        "/api/v1/network/config/lab",
    ),
    (
        "reset_network_namespaces",
        {"namespaces": ["kismet"]},
        "POST",
        "/api/v1/network/config/reset",
    ),
    (
        "set_regulatory_domain",
        {"country_code": "gb"},
        "POST",
        "/api/v1/system/reg-domain/set",
    ),
]


@pytest.mark.parametrize(("tool", "args", "method", "path"), CONFIRMED_CALLS)
async def test_confirmed_tool_asks_then_acts_on_accept(
    mcp, _device_info, tool, args, method, path
):
    action = _device_info.route(method=method, url=f"{CORE}{path}").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    async with _serve(mcp) as http:
        first = await wire.call(http, tool, args, capabilities=wire.FORM)
        key, params, state = wire.question(first)
        assert params["mode"] == "form"
        assert params["requestedSchema"] == {"type": "object", "properties": {}}
        assert not action.called, "nothing may happen before the user answers"

        done = await wire.call(
            http,
            tool,
            args,
            capabilities=wire.FORM,
            answers={key: wire.accept()},
            state=state,
        )
    assert done["result"]["structuredContent"] == {"ok": True}, done
    assert action.call_count == 1


@pytest.mark.parametrize(("tool", "args", "method", "path"), CONFIRMED_CALLS)
async def test_confirmed_tool_declined_is_not_performed(
    mcp, _device_info, tool, args, method, path
):
    action = _device_info.route(method=method, url=f"{CORE}{path}").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    async with _serve(mcp) as http:
        key, _params, state = wire.question(
            await wire.call(http, tool, args, capabilities=wire.FORM)
        )
        done = await wire.call(
            http,
            tool,
            args,
            capabilities=wire.FORM,
            answers={key: wire.DECLINE},
            state=state,
        )
    result = done["result"]
    # A decline is an answer, not an error.
    assert result["isError"] is False
    assert result["structuredContent"]["status"] == "not_performed"
    assert not action.called


@pytest.mark.parametrize(("tool", "args", "method", "path"), CONFIRMED_CALLS)
async def test_confirmed_tool_acts_directly_without_elicitation(
    mcp, _device_info, tool, args, method, path
):
    # Claude Desktop, claude -p, a legacy request: today's behaviour.
    action = _device_info.route(method=method, url=f"{CORE}{path}").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    async with _serve(mcp) as http:
        done = await wire.call(http, tool, args, capabilities=wire.NONE)
    assert done["result"]["structuredContent"] == {"ok": True}
    assert action.call_count == 1


async def test_reboot_message_names_the_device(mcp):
    async with _serve(mcp) as http:
        _key, params, _state = wire.question(
            await wire.call(http, "reboot_device", capabilities=wire.FORM)
        )
    assert params["message"].startswith("Reboot wlanpi-9be now?")


async def test_delete_without_force_does_not_ask(mcp, _device_info):
    route = _device_info.delete(f"{CORE}/api/v1/network/config/lab").mock(
        return_value=httpx.Response(200, json={"deleted": "lab"})
    )
    async with _serve(mcp) as http:
        done = await wire.call(
            http, "delete_network_config", {"id": "lab"}, capabilities=wire.FORM
        )
    assert done["result"]["structuredContent"] == {"deleted": "lab"}
    assert route.called


async def test_an_answer_without_our_state_does_not_count(mcp, _device_info):
    # A client cannot pre-fill the confirm on the first round: only a question
    # our sealed state says we asked can be answered.
    reboot = _device_info.post(f"{CORE}/api/v1/system/reboot").mock(
        return_value=httpx.Response(200, json={})
    )
    async with _serve(mcp) as http:
        body = await wire.call(
            http,
            "reboot_device",
            capabilities=wire.FORM,
            answers={"reboot": wire.accept()},
        )
    wire.question(body)  # asked again
    assert not reboot.called


async def test_state_minted_for_one_token_is_refused_for_another(mcp, _device_info):
    reboot = _device_info.post(f"{CORE}/api/v1/system/reboot").mock(
        return_value=httpx.Response(200, json={})
    )
    async with _serve(mcp) as http:
        key, _params, state = wire.question(
            await wire.call(
                http, "reboot_device", capabilities=wire.FORM, token="alice"
            )
        )
        stolen = await wire.call(
            http,
            "reboot_device",
            capabilities=wire.FORM,
            token="mallory",
            answers={key: wire.accept()},
            state=state,
        )
    assert stolen["error"]["code"] == -32602
    assert not reboot.called


async def test_state_is_bound_to_the_arguments(mcp, _device_info):
    # A "yes" to GB must not set US.
    route = _device_info.post(f"{CORE}/api/v1/system/reg-domain/set").mock(
        return_value=httpx.Response(200, json={})
    )
    async with _serve(mcp) as http:
        key, _params, state = wire.question(
            await wire.call(
                http,
                "set_regulatory_domain",
                {"country_code": "GB"},
                capabilities=wire.FORM,
            )
        )
        swapped = await wire.call(
            http,
            "set_regulatory_domain",
            {"country_code": "US"},
            capabilities=wire.FORM,
            answers={key: wire.accept()},
            state=state,
        )
    assert swapped["error"]["code"] == -32602
    assert not route.called


async def test_url_only_client_is_not_sent_a_form(mcp, _device_info):
    _device_info.post(f"{CORE}/api/v1/system/reboot").mock(
        return_value=httpx.Response(200, json={"rebooting": True})
    )
    async with _serve(mcp) as http:
        done = await wire.call(
            http, "reboot_device", capabilities={"elicitation": {"url": {}}}
        )
    assert done["result"]["structuredContent"] == {"rebooting": True}


# ── #86: replacing the active network profile ───────────────────────────────

ACTIVATE = f"{CORE}/api/v1/network/config/activate/lab"
DEACTIVATE = f"{CORE}/api/v1/network/config/deactivate/lab"


def _another_active(request):
    if request.url.params.get("override_active") == "true":
        return httpx.Response(200, json={"id": "lab", "outcomes": []})
    return httpx.Response(
        409, json={"detail": "Another configuration is currently active: home."}
    )


async def test_activate_asks_to_replace_the_active_profile(mcp, _device_info):
    route = _device_info.post(url__startswith=ACTIVATE).mock(
        side_effect=_another_active
    )
    async with _serve(mcp) as http:
        first = await wire.call(
            http, "activate_network_config", {"id": "lab"}, capabilities=wire.FORM
        )
        key, params, state = wire.question(first)
        assert "'home' is the active network profile on wlanpi-9be" in params["message"]
        assert "Replace it with 'lab'?" in params["message"]

        done = await wire.call(
            http,
            "activate_network_config",
            {"id": "lab"},
            capabilities=wire.FORM,
            answers={key: wire.accept()},
            state=state,
        )
    assert done["result"]["structuredContent"]["id"] == "lab"
    assert [c.request.url.params["override_active"] for c in route.calls] == [
        "false",
        "true",
    ]


async def test_activate_declined_returns_cores_409_unchanged(mcp, _device_info):
    route = _device_info.post(url__startswith=ACTIVATE).mock(
        side_effect=_another_active
    )
    async with _serve(mcp) as http:
        key, _params, state = wire.question(
            await wire.call(
                http, "activate_network_config", {"id": "lab"}, capabilities=wire.FORM
            )
        )
        done = await wire.call(
            http,
            "activate_network_config",
            {"id": "lab"},
            capabilities=wire.FORM,
            answers={key: wire.DECLINE},
            state=state,
        )
    result = done["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert (
        "wlanpi-core returned 409: Another configuration is currently active: home."
        in text
    )
    assert "declined" in text
    assert route.call_count == 1  # no override was sent


async def test_activate_without_elicitation_keeps_the_409(mcp, _device_info):
    _device_info.post(url__startswith=ACTIVATE).mock(side_effect=_another_active)
    async with _serve(mcp) as http:
        done = await wire.call(
            http, "activate_network_config", {"id": "lab"}, capabilities=wire.NONE
        )
    assert done["result"]["isError"] is True
    assert "currently active: home" in done["result"]["content"][0]["text"]


@pytest.mark.parametrize(
    "detail",
    [
        "Another network configuration change is in progress",  # busy: retry
        "WLAN management is disabled (WLAN_MANAGEMENT=manual)",
        "Configuration lab is already active.",
    ],
)
async def test_other_409s_are_not_offered_an_override(mcp, _device_info, detail):
    _device_info.post(url__startswith=ACTIVATE).mock(
        return_value=httpx.Response(409, json={"detail": detail})
    )
    async with _serve(mcp) as http:
        done = await wire.call(
            http, "activate_network_config", {"id": "lab"}, capabilities=wire.FORM
        )
    assert done["result"]["isError"] is True
    assert detail in done["result"]["content"][0]["text"]


async def test_deactivate_asks_before_tearing_down_an_inactive_profile(
    mcp, _device_info
):
    def respond(request):
        if request.url.params.get("override_active") == "true":
            return httpx.Response(200, json={"id": "lab", "left_alone": []})
        return httpx.Response(409, json={"detail": "Configuration lab is not active."})

    route = _device_info.post(url__startswith=DEACTIVATE).mock(side_effect=respond)
    async with _serve(mcp) as http:
        key, params, state = wire.question(
            await wire.call(
                http, "deactivate_network_config", {"id": "lab"}, capabilities=wire.FORM
            )
        )
        assert "'lab' is not the active network profile" in params["message"]
        done = await wire.call(
            http,
            "deactivate_network_config",
            {"id": "lab"},
            capabilities=wire.FORM,
            answers={key: wire.accept()},
            state=state,
        )
    assert done["result"]["structuredContent"]["id"] == "lab"
    assert route.call_count == 2


# ── #87: picking the scan adapter ───────────────────────────────────────────

SCAN = f"{CORE}/api/v1/utils/wlan/scan"
CANDIDATES = [
    {"iface": "wlan1", "namespace": "root", "label": "wlan1", "mode": "monitor"},
    {"iface": "mon0", "namespace": "lab", "label": "Lab radio", "mode": "monitor"},
]


def _scan(request):
    if "iface" not in request.url.params:
        return httpx.Response(
            200,
            json={"needsSelection": True, "candidates": CANDIDATES, "networks": []},
        )
    return httpx.Response(
        200,
        json={
            "needsSelection": False,
            "selectedAdapter": dict(request.url.params),
            "networks": [{"ssid": "lab"}],
        },
    )


async def test_scan_asks_which_adapter_then_scans_with_it(mcp, _device_info):
    route = _device_info.get(url__startswith=SCAN).mock(side_effect=_scan)
    async with _serve(mcp) as http:
        key, params, state = wire.question(
            await wire.call(http, "scan_wlan", capabilities=wire.FORM)
        )
        options = params["requestedSchema"]["properties"]["adapter"]["oneOf"]
        assert options == [
            {"const": "root/wlan1", "title": "wlan1 in root, monitor"},
            {"const": "lab/mon0", "title": "Lab radio (mon0 in lab), monitor"},
        ]
        done = await wire.call(
            http,
            "scan_wlan",
            capabilities=wire.FORM,
            answers={key: wire.accept({"adapter": "lab/mon0"})},
            state=state,
        )
    result = done["result"]["structuredContent"]
    assert result["networks"] == [{"ssid": "lab"}]
    last = route.calls[-1].request.url.params
    assert (last["iface"], last["namespace"]) == ("mon0", "lab")


async def test_scan_root_choice_sends_no_namespace(mcp, _device_info):
    route = _device_info.get(url__startswith=SCAN).mock(side_effect=_scan)
    async with _serve(mcp) as http:
        key, _params, state = wire.question(
            await wire.call(http, "scan_wlan", capabilities=wire.FORM)
        )
        await wire.call(
            http,
            "scan_wlan",
            capabilities=wire.FORM,
            answers={key: wire.accept({"adapter": "root/wlan1"})},
            state=state,
        )
    last = route.calls[-1].request.url.params
    assert last["iface"] == "wlan1"
    assert "namespace" not in last


@pytest.mark.parametrize(
    "reply", [wire.DECLINE, wire.accept({"adapter": "root/not-a-candidate"})]
)
async def test_scan_without_a_valid_choice_returns_needs_selection(
    mcp, _device_info, reply
):
    _device_info.get(url__startswith=SCAN).mock(side_effect=_scan)
    async with _serve(mcp) as http:
        key, _params, state = wire.question(
            await wire.call(http, "scan_wlan", capabilities=wire.FORM)
        )
        done = await wire.call(
            http, "scan_wlan", capabilities=wire.FORM, answers={key: reply}, state=state
        )
    result = done["result"]["structuredContent"]
    assert result["needsSelection"] is True
    assert result["candidates"] == CANDIDATES


async def test_scan_without_elicitation_returns_needs_selection(mcp, _device_info):
    _device_info.get(url__startswith=SCAN).mock(side_effect=_scan)
    async with _serve(mcp) as http:
        done = await wire.call(http, "scan_wlan", capabilities=wire.NONE)
    assert done["result"]["structuredContent"]["needsSelection"] is True


# ── #89: passphrases through a page on the WLAN Pi ──────────────────────────

CREATE = f"{CORE}/api/v1/network/config/"
PROFILE = {
    "id": "lab",
    "namespaces": [
        {
            "interface": "wlan0",
            "namespace": "lab",
            "security": {"ssid": "Lab <5G>", "security": "WPA2-PSK"},
        }
    ],
}
PASSPHRASE = "correct horse battery"


async def _open_page(http, params) -> str:
    """Return the relative route of the passphrase page the elicitation opens."""
    url = params["url"]
    assert url.startswith("https://wlanpi-9be.local:8767/netconfig-secret/")
    return url.removeprefix("https://wlanpi-9be.local:8767")


@pytest.fixture
def lan_host(monkeypatch):
    # The page link is built from the Host header nginx forwards.
    from tests import test_server

    monkeypatch.setitem(test_server.MCP_HEADERS, "Host", "wlanpi-9be.local:8767")
    monkeypatch.setitem(test_server.MCP_HEADERS, "X-Forwarded-Proto", "https")


async def test_passphrase_goes_through_the_page_not_the_conversation(
    mcp, _device_info, lan_host
):
    create = _device_info.post(CREATE).mock(
        return_value=httpx.Response(200, json={"id": "lab"})
    )
    async with _serve(mcp) as http:
        first = await wire.call(
            http, "create_network_config", {"config": PROFILE}, capabilities=wire.URL
        )
        key, params, state = wire.question(first)
        assert key == "secret_page"
        assert params["mode"] == "url"
        route = await _open_page(http, params)

        # The browser has no JWT: the ticket is its credential.
        page = await http.get(route, headers={"Host": "wlanpi-9be.local:8767"})
        assert page.status_code == 200
        assert "Lab &lt;5G&gt;" in page.text  # escaped
        assert page.headers["cache-control"] == "no-store"
        assert "default-src 'none'" in page.headers["content-security-policy"]

        # The client retries as soon as the page opens: wait for the user.
        early = await wire.call(
            http,
            "create_network_config",
            {"config": PROFILE},
            capabilities=wire.URL,
            answers={key: wire.accept()},
            state=state,
        )
        done_key, done_params, state = wire.question(early)
        assert done_key == "secret_done"
        assert done_params["mode"] == "form"
        assert not create.called

        saved = await http.post(
            route,
            content=f"p0={PASSPHRASE.replace(' ', '+')}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert saved.status_code == 200 and "Saved" in saved.text

        done = await wire.call(
            http,
            "create_network_config",
            {"config": PROFILE},
            capabilities=wire.URL,
            answers={done_key: wire.accept()},
            state=state,
        )
        assert done["result"]["structuredContent"] == {"id": "lab"}

        # Spent: the page is gone and the passphrase is no longer held.
        assert (await http.get(route)).status_code == 404
    assert netconfig_secrets._TICKETS == {}
    sent = create.calls[0].request
    assert json.loads(sent.content)["namespaces"][0]["security"]["psk"] == PASSPHRASE
    for body in (first, early, done):
        assert PASSPHRASE not in json.dumps(body)


async def test_core_errors_never_echo_the_entered_passphrase(
    mcp, _device_info, lan_host
):
    # Core's 422 echoes the request body, psk included (seen on a real Pi).
    tricky = 'quote"back\\slash pass'

    def echo(request):
        body = json.loads(request.content)
        return httpx.Response(
            422,
            json={
                "detail": [
                    {
                        "type": "missing",
                        "loc": ["body", "roots", 0, "phy"],
                        "input": body["namespaces"][0],
                    }
                ]
            },
        )

    _device_info.post(CREATE).mock(side_effect=echo)
    async with _serve(mcp) as http:
        key, params, state = wire.question(
            await wire.call(
                http,
                "create_network_config",
                {"config": PROFILE},
                capabilities=wire.URL,
            )
        )
        await http.post(
            await _open_page(http, params),
            content=urlencode({"p0": tricky}),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        done = await wire.call(
            http,
            "create_network_config",
            {"config": PROFILE},
            capabilities=wire.URL,
            answers={key: wire.accept()},
            state=state,
        )
    result = done["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "422" in text and '"psk":"***"' in text
    assert "quote" not in json.dumps(done)


async def test_the_page_rejects_a_passphrase_core_would_refuse(mcp, lan_host):
    async with _serve(mcp) as http:
        _key, params, _state = wire.question(
            await wire.call(
                http,
                "create_network_config",
                {"config": PROFILE},
                capabilities=wire.URL,
            )
        )
        route = await _open_page(http, params)
        short = await http.post(
            route,
            content="p0=short",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert short.status_code == 422
    assert "8 to 63 printable ASCII" in short.text
    ((state,),) = [list(netconfig_secrets._TICKETS.values())]
    assert state.values is None  # nothing stored


async def test_declining_the_page_discards_the_request(mcp, _device_info, lan_host):
    create = _device_info.post(CREATE).mock(return_value=httpx.Response(200, json={}))
    async with _serve(mcp) as http:
        key, _params, state = wire.question(
            await wire.call(
                http,
                "create_network_config",
                {"config": PROFILE},
                capabilities=wire.URL,
            )
        )
        done = await wire.call(
            http,
            "create_network_config",
            {"config": PROFILE},
            capabilities=wire.URL,
            answers={key: wire.DECLINE},
            state=state,
        )
    assert done["result"]["structuredContent"]["status"] == "not_performed"
    assert netconfig_secrets._TICKETS == {}
    assert not create.called


async def test_passphrase_is_handed_only_to_the_token_that_asked(mcp, lan_host):
    async with _serve(mcp) as http:
        _key, params, _state = wire.question(
            await wire.call(
                http,
                "create_network_config",
                {"config": PROFILE},
                capabilities=wire.URL,
                token="alice",
            )
        )
        route = await _open_page(http, params)
        await http.post(
            route,
            content="p0=abcdefgh",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    from wlanpi_mcp.auth.token_context import current_token

    reset = current_token.set("mallory")
    try:
        with pytest.raises(netconfig_secrets.TicketGone):
            netconfig_secrets.take(route)
    finally:
        current_token.reset(reset)


async def test_create_without_url_elicitation_sends_the_config_as_is(mcp, _device_info):
    create = _device_info.post(CREATE).mock(
        return_value=httpx.Response(200, json={"id": "lab"})
    )
    async with _serve(mcp) as http:
        done = await wire.call(
            http, "create_network_config", {"config": PROFILE}, capabilities=wire.FORM
        )
    assert done["result"]["structuredContent"] == {"id": "lab"}
    assert create.called


async def test_create_with_a_psk_given_does_not_ask(mcp, _device_info, lan_host):
    create = _device_info.post(CREATE).mock(
        return_value=httpx.Response(200, json={"id": "lab"})
    )
    given = {
        **PROFILE,
        "namespaces": [
            {
                **PROFILE["namespaces"][0],
                "security": {"ssid": "x", "security": "WPA2-PSK", "psk": "abcdefgh"},
            }
        ],
    }
    async with _serve(mcp) as http:
        done = await wire.call(
            http, "create_network_config", {"config": given}, capabilities=wire.URL
        )
    assert done["result"]["structuredContent"] == {"id": "lab"}
    assert create.called


def test_wpa3_refuses_a_hex_key_and_wpa2_takes_one():
    hex_key = "a" * 64
    assert netconfig_secrets._check("WPA2-PSK", hex_key) is None
    assert netconfig_secrets._check("WPA3-PSK", hex_key) is not None
    assert netconfig_secrets._check("WPA3-PSK", "12345678") is None
    assert re.search(
        "printable", netconfig_secrets._check("WPA2-PSK", "\x01" * 9) or ""
    )
