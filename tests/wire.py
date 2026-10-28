"""2026-07-28 ("modern") MCP requests against the assembled /mcp app.

Elicitation (multi-round-trip) and tasks only exist on modern requests, which
carry their protocol version and client capabilities in _meta and are routed
by headers, so these helpers build exactly that, the way Claude Code does.
"""

from typing import Any

import httpx

from tests.test_server import MCP_HEADERS

VERSION = "2026-07-28"
CORE = "https://localhost:31415"

FORM = {"elicitation": {"form": {}}}
URL = {"elicitation": {"form": {}, "url": {}}}
TASKS = {"extensions": {"io.modelcontextprotocol/tasks": {}}}
NONE: dict[str, Any] = {}


def caps(*parts: dict[str, Any]) -> dict[str, Any]:
    """Merge capability fragments, e.g. caps(FORM, TASKS)."""
    out: dict[str, Any] = {}
    for part in parts:
        for key, value in part.items():
            out[key] = {**out.get(key, {}), **value}
    return out


async def rpc(
    http: httpx.AsyncClient,
    method: str,
    params: dict[str, Any],
    *,
    name: str,
    capabilities: dict[str, Any],
    token: str = "core.jwt",
) -> httpx.Response:
    """POST one modern JSON-RPC request; returns the raw HTTP response."""
    params = {
        **params,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": VERSION,
            "io.modelcontextprotocol/clientCapabilities": capabilities,
            "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "0"},
        },
    }
    return await http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": VERSION,
            "Mcp-Method": method,
            "Mcp-Name": name,
            **MCP_HEADERS,
        },
    )


async def call(
    http: httpx.AsyncClient,
    tool: str,
    arguments: dict[str, Any] | None = None,
    *,
    capabilities: dict[str, Any],
    token: str = "core.jwt",
    answers: dict[str, Any] | None = None,
    state: str | None = None,
) -> dict[str, Any]:
    """tools/call, optionally as a retry carrying inputResponses/requestState.

    Returns the JSON-RPC body (with 'result' or 'error').
    """
    params: dict[str, Any] = {"name": tool, "arguments": arguments or {}}
    if answers is not None:
        params["inputResponses"] = answers
    if state is not None:
        params["requestState"] = state
    response = await rpc(
        http, "tools/call", params, name=tool, capabilities=capabilities, token=token
    )
    body: dict[str, Any] = response.json()
    return body


async def task_method(
    http: httpx.AsyncClient,
    method: str,
    task_id: str,
    *,
    capabilities: dict[str, Any] = TASKS,
    token: str = "core.jwt",
    **extra: Any,
) -> dict[str, Any]:
    """tasks/get, tasks/update or tasks/cancel; the Mcp-Name is the task id."""
    response = await rpc(
        http,
        method,
        {"taskId": task_id, **extra},
        name=task_id,
        capabilities=capabilities,
        token=token,
    )
    body: dict[str, Any] = response.json()
    return body


def accept(content: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build an ElicitResult the user accepted."""
    return {"action": "accept", **({"content": content} if content else {})}


DECLINE = {"action": "decline"}


def question(body: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    """(key, elicitation params, requestState) of an input_required result."""
    result = body["result"]
    assert result["resultType"] == "input_required", body
    ((key, request),) = result["inputRequests"].items()
    assert request["method"] == "elicitation/create"
    return key, request["params"], result["requestState"]
