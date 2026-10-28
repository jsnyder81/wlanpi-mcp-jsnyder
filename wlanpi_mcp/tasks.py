"""
MCP Tasks support (the io.modelcontextprotocol/tasks extension).

A task lets a long-running tool answer its call immediately with a handle,
then run on in the background while the client polls. The mcp 2.3.0 SDK has
no first-class tasks helper: `tasks/get`, `tasks/update` and `tasks/cancel`
are served as additive extension methods through
`mcp.server.extension.MethodBinding`, and a tool signals task creation by
returning a `TaskCallResult`, a `CallToolResult` subclass the SDK serializes
verbatim as the claimed `resultType: "task"` shape.

The daemon is stateless, so the store is keyed on taskId alone, never on a
session: polls arrive as unrelated POSTs with no connection to the call that
created the task. A task outlives its request because the work itself runs in
an `asyncio.create_task` (the pattern `_CAPTURES` already proves), and the
store holds the record plus the hooks (progress, cancel) that reach it.
`spawn` is the shared body for tools that hand their work to the background:
it maps the work's end (return, Exception, CancelledError) onto the store's
three outcomes and publishes it from a teardown path that a second cancel
cannot interrupt. `_cancel_work` is the matching shared tasks/cancel hook
(wired by `TaskStore.create(cancel_work=True)`): at-most-once cancel of the
body task, then wait for its teardown.

`tasks/result`, `tasks/list` and `notifications/tasks` are deliberately not
implemented: the reference client (Claude Code's public beta) does not use
them, and the outcome rides in the `tasks/get` response instead.

`input_required` with `inputRequests` is the in-task elicitation route. The
store and the `tasks/update` handler carry the plumbing (park a task on a
question, accept the answer, resume), and profile_clients is its first user:
it parks on a "Keep going?" confirm when its time window ends early.
"""

import asyncio
import contextlib
import functools
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from mcp.server.context import ServerRequestContext
from mcp.server.extension import Extension, MethodBinding
from mcp.server.mcpserver import Context, require_client_extension
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolResult,
    CancelTaskRequestParams,
    GetTaskRequestParams,
    RequestParams,
    TaskStatus,
    TextContent,
)
from mcp_types import INVALID_PARAMS
from mcp_types.version import is_version_at_least

log = logging.getLogger(__name__)

#: Wire identifier of the Tasks extension, as advertised in client and
#: server capabilities under `extensions`.
TASKS_EXTENSION_ID = "io.modelcontextprotocol/tasks"

#: Task results exist only from this revision up (resultType is 2026-era
#: vocabulary); a client on an older wire would reject the shape outright.
_TASKS_VERSION = "2026-07-28"

#: How long a finished task's record is kept, in milliseconds from creation.
#: Pruning is lazy (on create and get), so the store holds at most the tasks
#: created within this window plus whatever is still working.
TASK_TTL_MS = 4 * 3600 * 1000

#: Suggested client polling cadence advertised on every task.
POLL_INTERVAL_MS = 1000

#: Statuses that end a task; the first writer to one of these wins and a
#: terminal task never transitions again.
_TERMINAL: frozenset[TaskStatus] = frozenset({"completed", "failed", "cancelled"})


def _new_task_id() -> str:
    """Return a fresh task id: printable ASCII, no spaces, well under 128."""
    return secrets.token_urlsafe(9)


def _iso(epoch: float) -> str:
    """Format an epoch float as the ISO 8601 string the wire wants."""
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


@dataclass
class TaskRecord:
    """One task's state, owned by the store and reached by the polls."""

    task_id: str
    created: float
    updated: float
    status: TaskStatus = "working"
    ttl_ms: int | None = TASK_TTL_MS
    status_message: str | None = None
    #: The outcome, reported by tasks/get once the task is terminal.
    result: dict[str, Any] | None = None
    #: Called by tasks/get while working to render live progress text.
    progress: Callable[[], str | None] | None = None
    #: Called by tasks/cancel to stop the underlying work. With spawn's
    #: shielded teardown the record's outcome may already be published while
    #: the teardown finishes in the background; the ownership rule still
    #: holds, the work is always torn down.
    cancel: Callable[[], Awaitable[None]] | None = None
    #: The body task started by spawn(), so a poll (or a test) can await it.
    work: asyncio.Task[None] | None = None
    #: Set by _cancel_work so a second cancel only waits (at-most-once).
    work_cancelled: bool = False
    #: Set by tasks/cancel before the hook runs so the work's own completion
    #: path reports "cancelled" rather than "completed".
    cancel_requested: bool = False
    #: The pending question while status is input_required (plumbing for #92).
    input_requests: dict[str, Any] | None = None
    #: Resolved by tasks/update with the client's answer; awaited by the work.
    answer: asyncio.Future[dict[str, Any] | None] | None = None

    @property
    def terminal(self) -> bool:
        """Whether this task has reached its final status."""
        return self.status in _TERMINAL


class TaskStore:
    """Hold task records keyed on taskId alone.

    The daemon is stateless, so a session id would never match across polls.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}

    def create(
        self,
        *,
        progress: Callable[[], str | None] | None = None,
        cancel: Callable[[], Awaitable[None]] | None = None,
        ttl_ms: int | None = TASK_TTL_MS,
        cancel_work: bool = False,
    ) -> TaskRecord:
        """Register a new working task and return its record.

        cancel_work=True wires the record's cancel hook to the shared
        _cancel_work (the spawn-backed tools' tasks/cancel path), so the
        caller does not have to build the functools.partial itself.
        """
        now = time.time()
        self.prune(now)
        record = TaskRecord(
            task_id=_new_task_id(),
            created=now,
            updated=now,
            ttl_ms=ttl_ms,
            progress=progress,
            cancel=cancel,
        )
        if cancel_work:
            record.cancel = functools.partial(_cancel_work, record)
        self._tasks[record.task_id] = record
        return record

    def get(self, task_id: str) -> TaskRecord | None:
        """Return the live record for task_id, or None if unknown or expired."""
        self.prune()
        return self._tasks.get(task_id)

    def prune(self, now: float | None = None) -> None:
        """Drop terminal tasks past their retention window.

        A working task is never pruned: its work is bounded by the tool that
        started it (a capture by duration_s), and dropping the record while
        work still ran would strand the outcome.
        """
        if now is None:
            now = time.time()
        for task_id, record in list(self._tasks.items()):
            if (
                record.terminal
                and record.ttl_ms is not None
                and now > record.created + record.ttl_ms / 1000
            ):
                del self._tasks[task_id]

    def clear(self) -> None:
        """Forget every task (test teardown; a daemon restart does the same)."""
        self._tasks.clear()

    def __len__(self) -> int:
        """Count the task records held, live and not yet pruned."""
        return len(self._tasks)

    def complete(self, record: TaskRecord, result: dict[str, Any]) -> None:
        """Finish a task successfully, carrying its outcome."""
        self._finish(record, "completed", result)

    def fail(self, record: TaskRecord, result: dict[str, Any]) -> None:
        """Finish a task as failed; the outcome still rides in tasks/get."""
        self._finish(record, "failed", result)

    def cancelled(self, record: TaskRecord, result: dict[str, Any] | None) -> None:
        """Mark a task cancelled from its own work path (see store.cancel)."""
        self._finish(record, "cancelled", result)

    async def cancel(self, record: TaskRecord) -> TaskRecord:
        """Stop a task's work through its cancel hook, then mark it cancelled.

        A parked input_required task is woken with a None answer before the
        hook runs: work that awaits the answer and a hook that awaits that
        work would otherwise deadlock, the wake waiting on the very task
        the hook is waiting for. The hook then tears the work down (and the
        work usually reports its own outcome through complete/fail, which
        wins because this transition is guarded) before the record goes
        terminal.
        """
        if record.terminal:
            return record
        record.cancel_requested = True
        if record.answer is not None and not record.answer.done():
            record.answer.set_result(None)
        record.answer = None
        record.input_requests = None
        if record.cancel is not None:
            await record.cancel()
        self._finish(record, "cancelled", None)
        return record

    def request_input(
        self, record: TaskRecord, input_requests: dict[str, Any]
    ) -> asyncio.Future[dict[str, Any] | None]:
        """Park a working task on a question; tasks/update delivers the answer.

        Returns the future the work awaits; it resolves to the answer dict
        (or None when the client sends no content or cancels while parked).
        profile_clients uses this for its "Keep going?" confirm.
        """
        if record.terminal:  # pragma: no cover - guard for misuse
            raise RuntimeError(f"task {record.task_id} is already {record.status}")
        future: asyncio.Future[dict[str, Any] | None] = (
            asyncio.get_running_loop().create_future()
        )
        record.input_requests = input_requests
        record.answer = future
        self._set_status(record, "input_required")
        return future

    def answer(self, record: TaskRecord, answer: dict[str, Any] | None) -> None:
        """Deliver a tasks/update answer and resume an input_required task.

        An answer for a task with no pending question is ignored (the wire
        call still succeeds with the task's current state).
        """
        if record.status != "input_required":
            return
        future, record.answer = record.answer, None
        record.input_requests = None
        self._set_status(record, "working")
        if future is not None and not future.done():
            future.set_result(answer)

    def _finish(
        self, record: TaskRecord, status: TaskStatus, result: dict[str, Any] | None
    ) -> None:
        if record.terminal:
            return
        if result is not None:
            record.result = result
        self._set_status(record, status)

    def _set_status(self, record: TaskRecord, status: TaskStatus) -> None:
        record.status = status
        record.updated = time.time()


#: The daemon's task store. Module-level like _CAPTURES: the extension
#: handlers and the tools must reach the same instance.
TASKS = TaskStore()


def wire(record: TaskRecord) -> dict[str, Any]:
    """Render a task record as the Task object the tasks/* responses carry."""
    out: dict[str, Any] = {
        "taskId": record.task_id,
        "status": record.status,
        "createdAt": _iso(record.created),
        "lastUpdatedAt": _iso(record.updated),
        "ttlMs": record.ttl_ms,
        "pollIntervalMs": POLL_INTERVAL_MS,
    }
    message = (
        record.progress() if record.status == "working" and record.progress else None
    )
    message = message or record.status_message
    if message is not None:
        out["statusMessage"] = message
    if record.status == "input_required" and record.input_requests is not None:
        out["inputRequests"] = record.input_requests
    return out


class UpdateTaskRequestParams(RequestParams):
    """Parameters for tasks/update: the task and the answer to its question."""

    task_id: str
    answer: dict[str, Any] | None = None


class TaskCallResult(CallToolResult):
    """A tools/call result that hands the client a task instead of an answer.

    The SDK serializes this verbatim as the claimed `resultType: "task"`
    shape; the fields below are the Tasks extension's wire fields. Clients
    that did not declare the extension must never see it (they would fail
    the result as "Unsupported result type 'task'"), so tools build it only
    behind `tasks_supported`.
    """

    task_id: str
    status: TaskStatus = "working"
    created_at: str
    last_updated_at: str
    ttl_ms: int | None = None
    poll_interval_ms: int | None = None
    status_message: str | None = None
    result_type: Literal["task"] = "task"


def task_call_result(
    record: TaskRecord, *, message: str, payload: dict[str, Any]
) -> Any:
    """Build the tools/call task result for a freshly created task.

    Typed as Any on purpose: the SDK forbids a CallToolResult subclass in a
    tool's return union, so a task-capable tool keeps its `dict[str, Any]`
    annotation and returns this through here. `payload` becomes the
    structuredContent of the start response (the capture's id, path and so
    on), which also satisfies the tool's derived output schema.
    """
    return TaskCallResult(
        content=[TextContent(type="text", text=message)],
        structured_content=payload,
        task_id=record.task_id,
        status=record.status,
        created_at=_iso(record.created),
        last_updated_at=_iso(record.updated),
        ttl_ms=record.ttl_ms,
        poll_interval_ms=POLL_INTERVAL_MS,
    )


async def _run_as_task(
    record: TaskRecord,
    work: Awaitable[dict[str, Any]],
    teardown: Callable[[], Awaitable[None]] | None,
    on_cancel: Callable[[], dict[str, Any]] | None,
    on_error: Callable[[BaseException], dict[str, Any]] | None,
) -> None:
    """Body task for spawn: map the work's end onto a published outcome."""
    outcome: TaskStatus = "completed"
    result: dict[str, Any] | None = None
    try:
        result = await work
    except asyncio.CancelledError:
        outcome = "cancelled"
        result = on_cancel() if on_cancel is not None else None
    except Exception as exc:  # noqa: BLE001 - the outcome rides in the task
        outcome = "failed"
        result = on_error(exc) if on_error is not None else {"error": str(exc)}
    try:
        if teardown is not None:
            # Shielded: a cancel landing here (or a second one) interrupts
            # only our wait, never the teardown. The underlying work (socket
            # stop and close) still runs to completion, detached.
            try:
                await asyncio.shield(teardown())
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001 - best-effort teardown
                # A wedged socket must not turn tasks/cancel into a protocol
                # error: the outcome in the record is what matters.
                log.debug("task %s teardown failed: %r", record.task_id, exc)
    finally:
        if outcome == "completed":
            TASKS.complete(record, result or {})
        elif outcome == "failed":
            TASKS.fail(record, result or {})
        else:
            TASKS.cancelled(record, result)
        # The record is terminal: drop the closures over the tool's run so
        # its capture state is not pinned for the rest of the TTL.
        record.progress = None
        record.cancel = None
    if outcome == "cancelled":
        raise asyncio.CancelledError


def spawn(
    record: TaskRecord,
    work: Awaitable[dict[str, Any]],
    *,
    teardown: Callable[[], Awaitable[None]] | None = None,
    on_cancel: Callable[[], dict[str, Any]] | None = None,
    on_error: Callable[[BaseException], dict[str, Any]] | None = None,
) -> asyncio.Task[None]:
    """Run work in the background as record's task body; return its handle.

    The work's return value completes the task, an Exception fails it
    (mapped through on_error) and a CancelledError cancels it (mapped
    through on_cancel, or no result at all). Teardown then publish run
    shielded, so a cancel cannot strand the underlying resources or leave
    the record without an outcome; a cancel landing after the work already
    returned still publishes that work's outcome, because the work was not
    cut short. A failing teardown is logged, never raised.
    """
    task = asyncio.create_task(
        _run_as_task(record, work, teardown, on_cancel, on_error)
    )
    record.work = task
    return task


async def _cancel_work(record: TaskRecord) -> None:
    """Cancel a task's work at most once and wait for it to end.

    The tasks/cancel hook shared by every spawn-backed tool (wired by
    TaskStore.create(cancel_work=True)): the first call delivers
    CancelledError to the body task, whose spawn teardown then releases
    the underlying resource; a second cancel while the first is unwinding
    only waits (re-cancelling interrupts nothing but buys no determinism).
    The wait swallows the CancelledError the body raises on its way out:
    the caller reads the outcome from the record.
    """
    work = record.work
    if work is None:
        return
    if not record.work_cancelled:
        record.work_cancelled = True
        work.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await work


def tasks_supported(ctx: Context[Any, Any] | None) -> bool:
    """Report whether this request's client can receive a task result.

    True only on the 2026-07-28 wire or newer with the tasks extension
    declared in the request's `_meta` client capabilities; anything else
    would reject `resultType: "task"`. Outside an active request (unit
    tests, direct calls) there is no negotiated version and no client to
    ask, so a None or bare context reports False.
    """
    if (
        ctx is None
        or ctx.protocol_version is None
        or not is_version_at_least(ctx.protocol_version, _TASKS_VERSION)
    ):
        return False
    capabilities = ctx.client_capabilities
    extensions = capabilities.extensions if capabilities is not None else None
    return extensions is not None and TASKS_EXTENSION_ID in extensions


class TasksExtension(Extension):
    """Serve the tasks/* methods against the module-level task store."""

    identifier = TASKS_EXTENSION_ID

    def methods(self) -> tuple[MethodBinding, ...]:
        """Bind tasks/get, tasks/update and tasks/cancel as extension methods.

        Gated to the protocol revision that introduced the task shapes: on
        an older wire the client never declared the extension and the result
        shapes do not exist.
        """
        modern = frozenset({_TASKS_VERSION})
        return (
            MethodBinding("tasks/get", GetTaskRequestParams, self._on_get, modern),
            MethodBinding(
                "tasks/update", UpdateTaskRequestParams, self._on_update, modern
            ),
            MethodBinding(
                "tasks/cancel", CancelTaskRequestParams, self._on_cancel, modern
            ),
        )

    async def _on_get(
        self, ctx: ServerRequestContext[Any, Any], params: GetTaskRequestParams
    ) -> dict[str, Any]:
        """Report one task's state, with its outcome once terminal."""
        record = self._require(ctx, params.task_id)
        out = wire(record)
        if record.result is not None:
            out["result"] = record.result
        return out

    async def _on_update(
        self, ctx: ServerRequestContext[Any, Any], params: UpdateTaskRequestParams
    ) -> dict[str, Any]:
        """Accept the answer to an input_required task's question."""
        record = self._require(ctx, params.task_id)
        TASKS.answer(record, params.answer)
        return wire(record)

    async def _on_cancel(
        self, ctx: ServerRequestContext[Any, Any], params: CancelTaskRequestParams
    ) -> dict[str, Any]:
        """Stop a task's work and report its (now terminal) state."""
        record = self._require(ctx, params.task_id)
        record = await TASKS.cancel(record)
        return wire(record)

    @staticmethod
    def _require(ctx: ServerRequestContext[Any, Any], task_id: str) -> TaskRecord:
        """Resolve a polled task id against the store.

        Raises:
            MCPError: -32021 if the client did not declare the extension,
                -32602 if the id is unknown or its record has expired (for
                example after a daemon restart).
        """
        require_client_extension(ctx, TASKS_EXTENSION_ID)
        record = TASKS.get(task_id)
        if record is None:
            raise MCPError(
                code=INVALID_PARAMS,
                message=f"unknown or expired task '{task_id}'",
            )
        return record
