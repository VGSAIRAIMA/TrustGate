"""Asynchronous human approval primitives for TrustGate."""

from dataclasses import dataclass, field
from enum import Enum
import asyncio
from datetime import datetime, timezone
import sys
import uuid
from typing import Any, Awaitable, Callable

from trustgate.storage.database import DEFAULT_DB_PATH, get_approval, list_approvals, save_approval


class ApprovalAction(str, Enum):
    BLOCK = "BLOCK"
    ALLOW_ONCE = "ALLOW_ONCE"
    APPROVE_UPDATE = "APPROVE_UPDATE"
    REJECT_UPDATE = "REJECT_UPDATE"


@dataclass
class PendingApproval:
    request_id: str
    server: str
    tool: str
    risk_score: int
    severity: str
    reason: str
    evidence: list[str] = field(default_factory=list)
    old_hash: str = ""
    new_hash: str = ""
    created_at: str = ""
    fingerprint_change: bool = False
    action: ApprovalAction | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "server": self.server,
            "tool": self.tool,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "timestamp": self.created_at,
            "fingerprint_change": self.fingerprint_change,
            "action": self.action.value if self.action else None,
        }


ApprovalHandler = Callable[[PendingApproval], Awaitable[ApprovalAction | str] | ApprovalAction | str]


class ApprovalManager:
    """Non-blocking approval registry with fail-closed timeout behavior."""

    def __init__(self, timeout: float = 30.0, handler: ApprovalHandler | None = None, db_path: str = DEFAULT_DB_PATH):
        self.timeout = timeout
        self.handler = handler
        self.db_path = db_path
        self.pending: dict[str, PendingApproval] = {}
        self._waiters: dict[str, asyncio.Future[ApprovalAction]] = {}

    async def request(self, pending: PendingApproval) -> tuple[PendingApproval, ApprovalAction]:
        loop = asyncio.get_running_loop()
        pending.created_at = pending.created_at or datetime.now(timezone.utc).isoformat()
        pending.request_id = pending.request_id or uuid.uuid4().hex
        self.pending[pending.request_id] = pending
        save_approval(pending.as_dict(), db_path=self.db_path)
        waiter: asyncio.Future[ApprovalAction] = loop.create_future()
        self._waiters[pending.request_id] = waiter
        try:
            if self.handler is not None:
                result = self.handler(pending)
                if asyncio.iscoroutine(result):
                    result = await asyncio.wait_for(result, timeout=self.timeout)
                if not await self.resolve(pending.request_id, result):
                    waiter.set_result(
                        ApprovalAction.REJECT_UPDATE
                        if pending.fingerprint_change
                        else ApprovalAction.BLOCK
                    )
            elif self._terminal_available():
                result = await self._wait_for_terminal_or_shared(pending)
                await self.resolve(pending.request_id, result)
            else:
                action = await self._poll_shared_resolution(pending.request_id, pending.fingerprint_change)
                if action is not None:
                    waiter.set_result(action)
            action = await asyncio.wait_for(waiter, timeout=self.timeout)
        except (asyncio.TimeoutError, EOFError, OSError):
            action = ApprovalAction.BLOCK
        finally:
            self.pending.pop(pending.request_id, None)
            self._waiters.pop(pending.request_id, None)
        pending.action = action
        record = pending.as_dict()
        record["resolved_at"] = datetime.now(timezone.utc).isoformat()
        save_approval(record, db_path=self.db_path)
        return pending, action

    async def resolve(self, request_id: str, action: ApprovalAction | str) -> bool:
        pending = self.pending.get(request_id)
        waiter = self._waiters.get(request_id)
        if pending is None or waiter is None or waiter.done():
            return False
        try:
            resolved = action if isinstance(action, ApprovalAction) else ApprovalAction(str(action).upper())
        except ValueError:
            return False
        if pending.fingerprint_change:
            valid = {ApprovalAction.APPROVE_UPDATE, ApprovalAction.REJECT_UPDATE}
        else:
            valid = {ApprovalAction.ALLOW_ONCE, ApprovalAction.BLOCK}
        if resolved not in valid:
            return False
        waiter.set_result(resolved)
        record = pending.as_dict()
        record["action"] = resolved.value
        record["resolved_at"] = datetime.now(timezone.utc).isoformat()
        save_approval(record, db_path=self.db_path)
        return True

    def list_pending(self) -> list[dict[str, Any]]:
        local = {item["request_id"]: item for item in (item.as_dict() for item in self.pending.values())}
        for item in list_approvals(db_path=self.db_path, pending_only=True):
            local[item["request_id"]] = item
        return list(local.values())

    async def _poll_shared_resolution(self, request_id: str, fingerprint_change: bool) -> ApprovalAction | None:
        deadline = asyncio.get_running_loop().time() + self.timeout
        valid = {ApprovalAction.APPROVE_UPDATE.value, ApprovalAction.REJECT_UPDATE.value} if fingerprint_change else {ApprovalAction.ALLOW_ONCE.value, ApprovalAction.BLOCK.value}
        while asyncio.get_running_loop().time() < deadline:
            record = get_approval(request_id, db_path=self.db_path)
            action = record.get("action") if record else None
            if action in valid:
                return ApprovalAction(action)
            await asyncio.sleep(0.1)
        return None

    async def _wait_for_terminal_or_shared(self, pending: PendingApproval) -> ApprovalAction:
        terminal_task = asyncio.create_task(asyncio.to_thread(self._prompt, pending))
        shared_task = asyncio.create_task(self._poll_shared_resolution(pending.request_id, pending.fingerprint_change))
        done, pending_tasks = await asyncio.wait(
            {terminal_task, shared_task},
            timeout=self.timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending_tasks:
            task.cancel()
        if not done:
            raise asyncio.TimeoutError
        result = next(iter(done)).result()
        return result if result is not None else ApprovalAction.BLOCK

    @staticmethod
    def _terminal_available() -> bool:
        return bool(getattr(sys.stdin, "isatty", lambda: False)()) or sys.platform == "win32"

    @staticmethod
    def _prompt(pending: PendingApproval) -> None:
        stream = None
        try:
            stream = open("CONIN$" if sys.platform == "win32" else "/dev/tty", "r", encoding="utf-8")
        except OSError:
            stream = sys.stdin
        print(
            f"\nTrustGate approval required\n"
            f"Tool: {pending.tool} | Server: {pending.server}\n"
            f"Threat: {pending.reason}\n"
            f"Risk: {pending.risk_score}/100 | Severity: {pending.severity}\n"
            f"Evidence: {', '.join(pending.evidence) or 'none'}\n",
            file=sys.stderr,
        )
        if pending.fingerprint_change:
            print(f"OLD HASH: {pending.old_hash}\nNEW HASH: {pending.new_hash}", file=sys.stderr)
            print("Choose [u] APPROVE UPDATE or [r] REJECT:", file=sys.stderr, flush=True)
            choice = stream.readline().strip().lower()
            action = ApprovalAction.APPROVE_UPDATE if choice == "u" else ApprovalAction.REJECT_UPDATE
        else:
            print("Choose [o] ALLOW ONCE or [b] BLOCK:", file=sys.stderr, flush=True)
            choice = stream.readline().strip().lower()
            action = ApprovalAction.ALLOW_ONCE if choice == "o" else ApprovalAction.BLOCK
        return action


async def terminal_or_handler_approval(manager: ApprovalManager, pending: PendingApproval) -> ApprovalAction:
    """Resolve a prompt through the manager's configured terminal/API path."""
    _, action = await manager.request(pending)
    return action
