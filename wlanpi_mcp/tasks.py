"""
MCP Tasks extension (io.modelcontextprotocol/tasks, SEP-2663), built by hand.

mcp 2.3.0 has no runtime for the 2026-07-28 tasks extension (python-sdk
#2806, PR #3005), so this module serves it through the SDK's public
Extension API: an interceptor that answers an allowlisted tools/call with a
task handle and runs the call in the background, plus the tasks/get,
tasks/update and tasks/cancel methods. Keep it self-contained so it can be
swapped for the SDK's own Tasks() once that ships.

The wire rules that matter here:

- A task is returned only when the request's own _meta clientCapabilities
  declare the extension, on a 2026-07-28 request; everything else runs the
  tool synchronously as before. The daemon is stateless, so per-request
  capabilities are the only signal there is.
- tasks/get carries the outcome: 'completed' with the tool's exact
  CallToolResult (a tool error stays isError: true), 'failed' only for a
  JSON-RPC error, 'cancelled' after tasks/cancel. Unknown ids are -32602.
- A task is bound to the JWT that created it (sha256, as the middleware's
  principal): another token's tasks/* calls get the same -32602 as an unknown
  id, so task ids cannot be probed.

Task state lives in this process only. A daemon restart forgets running
tasks (their captures stop with their sockets) and a poll afterwards gets
-32602, which the spec allows for a task the server no longer has.

Tools running as a task report progress with set_status() or reporting(),
and can ask the user mid-task with request_input(); all three are no-ops or
unavailable outside a task. tasks/cancel is cooperative, as the spec allows:
a tool that can end early with a useful result (a capture cut short) calls
stop_early() when the cancel lands and completes normally with what it has,
since a 'cancelled' Task carries no result. Everything else ends 'cancelled'.
"""

import asyncio
import hashlib
import logging
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Collection
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.extension import Extension, MethodBinding
from mcp.shared.exceptions import MCPError
from mcp_types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    MISSING_REQUIRED_CLIENT_CAPABILITY,
    CallToolRequestParams,
    ClientCapabilities,
    RequestParams,
)
from pydantic import BaseModel

from wlanpi_mcp.auth.token_context import get_token
from wlanpi_mcp.elicit import is_modern

log = logging.getLogger(__name__)

EXTENSION_ID = "io.modelcontextprotocol/tasks"

#: Suggested tasks/get interval. Claude Code clamps it to 250-30000 ms.
POLL_INTERVAL_MS = 2000

#: How long a finished task stays answerable, in seconds. A client normally
#: collects the result on its next poll; this covers a reconnect.
RETAIN_S = 3600

#: Finished tasks kept at most, oldest dropped first. Running ones never are.
MAX_FINISHED = 100

#: How often reporting() refreshes a task's statusMessage, in seconds.
REPORT_EVERY_S = 1.0

Status = Literal["working", "input_required", "completed", "failed", "cancelled"]
TERMINAL = frozenset({"completed", "failed", "cancelled"})


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def _owner() -> str | None:
    """Fingerprint of the calling JWT; None without one (stdio)."""
    token = get_token()
    return hashlib.sha256(token.encode()).hexdigest() if token else None


def client_supports_tasks(
    protocol_version: str | None, capabilities: ClientCapabilities | None
) -> bool:
    """Return True when this request declared the tasks extension on 2026-07-28."""
    if not is_modern(protocol_version):
        return False
    extensions = capabilities.extensions if capabilities is not None else None
    return extensions is not None and EXTENSION_ID in extensions


@dataclass
class TaskRecord:
    """One task: its wire state plus the background job running the call."""

    task_id: str
    tool: str
    owner: str | None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    status: Status = "working"
    status_message: str | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    job: asyncio.Task[None] | None = None
    #: Set by tasks/cancel, so stop_early() can tell it from other cancels.
    cancel_requested: bool = False
    #: Outstanding in-task input requests (request_input), keyed per lifetime.
    input_requests: dict[str, Any] = field(default_factory=dict)
    _waiters: dict[str, asyncio.Future[dict[str, Any]]] = field(default_factory=dict)
    _keys_used: int = 0

    def touch(self, message: str | None = None) -> None:
        """Record a status-message change."""
        if message is not None:
            self.status_message = message
        self.updated_at = time.time()

    def finish(self, status: Status, message: str | None = None) -> None:
        """Move to a terminal status (once)."""
        if self.status in TERMINAL:
            return
        self.status = status
        self.input_requests.clear()
        self.touch(message)

    def wire(self) -> dict[str, Any]:
        """Return the Task fields shared by CreateTaskResult and tasks/get."""
        out: dict[str, Any] = {
            "taskId": self.task_id,
            "status": self.status,
            "createdAt": _iso(self.created_at),
            "lastUpdatedAt": _iso(self.updated_at),
            # Unlimited while running; once finished, how long we keep it.
            "ttlMs": (
                int((self.updated_at + RETAIN_S - self.created_at) * 1000)
                if self.status in TERMINAL
                else None
            ),
            "pollIntervalMs": POLL_INTERVAL_MS,
        }
        if self.status_message is not None:
            out["statusMessage"] = self.status_message
        if self.status == "input_required":
            out["inputRequests"] = dict(self.input_requests)
        elif self.status == "completed":
            out["result"] = self.result or {}
        elif self.status == "failed":
            out["error"] = self.error or {
                "code": INTERNAL_ERROR,
                "message": "Internal error",
            }
        return out


#: Live and recently finished tasks, keyed by task id.
_TASKS: dict[str, TaskRecord] = {}

#: The task the current coroutine runs under, if any.
_current: ContextVar[TaskRecord | None] = ContextVar("wlanpi_mcp_task", default=None)


def _prune(now: float) -> None:
    finished = sorted(
        (r for r in _TASKS.values() if r.status in TERMINAL),
        key=lambda r: r.updated_at,
    )
    stale = [r for r in finished if now - r.updated_at > RETAIN_S]
    stale += finished[len(stale) : max(len(stale), len(finished) - MAX_FINISHED)]
    for record in stale:
        _TASKS.pop(record.task_id, None)


def in_task() -> bool:
    """Return True when the current call is running as a task."""
    return _current.get() is not None


def set_status(message: str) -> None:
    """Set the current task's statusMessage; a no-op outside a task."""
    record = _current.get()
    if record is not None and record.status not in TERMINAL:
        record.touch(message)


@asynccontextmanager
async def reporting(
    describe: Callable[[], str], every_s: float = REPORT_EVERY_S
) -> AsyncIterator[None]:
    """
    Refresh the task's statusMessage from ``describe()`` while the block runs.

    Outside a task this does nothing, so a tool can wrap its long step
    unconditionally. ``describe`` must be cheap and must not raise.
    """
    if _current.get() is None:
        yield
        return

    async def tick() -> None:
        while True:
            set_status(describe())
            await asyncio.sleep(every_s)

    ticker = asyncio.create_task(tick())
    try:
        yield
    finally:
        ticker.cancel()
        set_status(describe())


def stop_early() -> bool:
    """
    Turn a tasks/cancel into an early, normal finish of the current task.

    Call it from an ``except asyncio.CancelledError`` block: it returns True,
    and withdraws the cancellation, only when the CancelledError came from
    tasks/cancel on the task this code runs under. The tool then finishes
    its work early and returns its partial result, which completes the task
    (a cancelled Task cannot carry one). On False, re-raise.
    """
    record = _current.get()
    job = asyncio.current_task()
    if record is None or not record.cancel_requested or job is not record.job:
        return False
    if job is not None:
        job.uncancel()
    record.touch("Stopping early: cancelled by the client")
    return True


async def request_input(
    request: dict[str, Any], label: str = "input", timeout_s: float | None = None
) -> dict[str, Any]:
    """
    Ask the client for input mid-task and wait for its tasks/update answer.

    ``request`` is one MRTR input request ({"method": "elicitation/create",
    "params": {...}}). The task shows input_required until the client
    answers; the answer (e.g. an ElicitResult dict) is returned. Each call
    gets a fresh key, as the spec requires keys to be unique per task.
    With ``timeout_s``, an unanswered question is withdrawn after that long.

    Raises:
        RuntimeError: outside a task.
        TimeoutError: no answer within ``timeout_s``.
    """
    record = _current.get()
    if record is None:
        raise RuntimeError("request_input is only available inside a task")
    record._keys_used += 1
    key = f"{label}-{record._keys_used}"
    waiter: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
    record._waiters[key] = waiter
    record.input_requests[key] = request
    record.status = "input_required"
    record.touch()
    try:
        return await asyncio.wait_for(waiter, timeout_s)
    finally:
        record._waiters.pop(key, None)
        record.input_requests.pop(key, None)
        if record.status == "input_required" and not record.input_requests:
            record.status = "working"
            record.touch()


def _lookup(task_id: str) -> TaskRecord:
    record = _TASKS.get(task_id)
    # Another token's task answers exactly like an unknown one.
    if record is None or record.owner != _owner():
        raise MCPError(code=INVALID_PARAMS, message=f"Unknown task: {task_id}")
    return record


def _require_capability(ctx: ServerRequestContext[Any, Any]) -> None:
    caps = ctx.session.client_capabilities if ctx.session is not None else None
    if not client_supports_tasks(ctx.protocol_version, caps):
        raise MCPError(
            code=MISSING_REQUIRED_CLIENT_CAPABILITY,
            message="This request requires the io.modelcontextprotocol/tasks extension",
            data={"requiredCapabilities": {"extensions": {EXTENSION_ID: {}}}},
        )


class TaskIdParams(RequestParams):
    """Params of tasks/get and tasks/cancel."""

    task_id: str


class UpdateTaskParams(TaskIdParams):
    """Params of tasks/update."""

    input_responses: dict[str, Any]


def _dump(result: Any) -> dict[str, Any]:
    if isinstance(result, BaseModel):
        dumped: dict[str, Any] = result.model_dump(
            by_alias=True, exclude_none=True, mode="json"
        )
        return dumped
    return dict(result)


async def _run(
    record: TaskRecord, call: Callable[[], Awaitable[HandlerResult]]
) -> None:
    """Run the intercepted call to completion and record its outcome."""
    _current.set(record)
    try:
        result = await call()
    except asyncio.CancelledError:
        record.finish("cancelled", "Cancelled by the client")
        return
    except MCPError as exc:
        record.error = {"code": exc.error.code, "message": exc.error.message}
        if exc.error.data is not None:
            record.error["data"] = exc.error.data
        record.finish("failed", exc.error.message)
        return
    except Exception as exc:
        log.exception("task %s (%s) failed", record.task_id, record.tool)
        record.error = {
            "code": INTERNAL_ERROR,
            "message": f"{type(exc).__name__}: {exc}",
        }
        record.finish("failed", record.error["message"])
        return
    record.result = _dump(result)
    record.finish("completed", record.status_message)


class Tasks(Extension):
    """Answer the allowlisted tools with a task when the client supports it."""

    identifier = EXTENSION_ID

    def __init__(self, tools: Collection[str]) -> None:
        self.task_tools = frozenset(tools)

    def methods(self) -> list[MethodBinding]:
        """Serve tasks/get, tasks/update and tasks/cancel."""
        return [
            MethodBinding("tasks/get", TaskIdParams, self._get),
            MethodBinding("tasks/update", UpdateTaskParams, self._update),
            MethodBinding("tasks/cancel", TaskIdParams, self._cancel),
        ]

    async def intercept_tool_call(
        self,
        params: CallToolRequestParams,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        """Run an allowlisted call as a task; pass anything else through."""
        caps = ctx.session.client_capabilities if ctx.session is not None else None
        if params.name not in self.task_tools or not client_supports_tasks(
            ctx.protocol_version, caps
        ):
            return await call_next(ctx)
        now = time.time()
        _prune(now)
        record = TaskRecord(
            task_id=f"{params.name}-{secrets.token_urlsafe(18)}",
            tool=params.name,
            owner=_owner(),
        )
        # Registered before we answer, so the first tasks/get always resolves.
        _TASKS[record.task_id] = record
        # create_task copies this context, so the job keeps the caller's JWT.
        record.job = asyncio.create_task(_run(record, lambda: call_next(ctx)))
        # A job cancelled before its first step never runs _run's handler.
        record.job.add_done_callback(
            lambda job: (
                record.finish("cancelled", "Cancelled by the client")
                if job.cancelled()
                else None
            )
        )
        log.info("tool %s running as task %s", params.name, record.task_id)
        return {"resultType": "task", **record.wire()}

    async def _get(
        self, ctx: ServerRequestContext[Any, Any], params: TaskIdParams
    ) -> dict[str, Any]:
        _require_capability(ctx)
        return _lookup(params.task_id).wire()

    async def _update(
        self, ctx: ServerRequestContext[Any, Any], params: UpdateTaskParams
    ) -> dict[str, Any]:
        _require_capability(ctx)
        record = _lookup(params.task_id)
        # Unknown or already answered keys are ignored, as the spec says.
        for key, response in params.input_responses.items():
            waiter = record._waiters.get(key)
            if waiter is not None and not waiter.done():
                waiter.set_result(_dump(response) if response is not None else {})
        return {}

    async def _cancel(
        self, ctx: ServerRequestContext[Any, Any], params: TaskIdParams
    ) -> dict[str, Any]:
        _require_capability(ctx)
        record = _lookup(params.task_id)
        # A repeat is acknowledged but not delivered again: it would cut short
        # the cleanup, or the early stop, that the first one started.
        if (
            record.job is not None
            and not record.job.done()
            and not record.cancel_requested
        ):
            record.cancel_requested = True
            # Cooperative: the job's own finally blocks (e.g. stopping a
            # capture) run before it reports 'cancelled'.
            record.job.cancel()
        return {}
