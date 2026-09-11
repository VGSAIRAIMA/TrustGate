"""TrustGate inspection proxy core (Stage 17).

Bridges bidirectional stdio communication between an MCP client (agent)
and an MCP server child process, performing real-time security inspection:
- Inbound: intercepts `tools/list` responses, evaluates tool contracts via
  the Policy Engine, pins approved fingerprints, emits diffs, and withholds
  blocked tools.
- Outbound: intercepts `tools/call` responses, normalizes and sanitizes untrusted
  output data, redacting prompt injections before they reach the agent.
- Console: renders Rich terminal panels to stderr for every security event.
- Storage: logs all audit events to the SQLite vault.
"""

import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import threading
import uuid
from typing import Any

from trustgate.console.dashboard import show_event, show_sanitization_event
from trustgate.mechanisms.fingerprint import compute_tool_fingerprint
from trustgate.mechanisms.output_sanitizer import sanitize_mcp_response
from trustgate.policy.engine import (
    PolicyAction,
    PolicyDecision,
    decide,
    evaluate_tool_manifest,
)
from trustgate.proxy.parser import parse_message
from trustgate.proxy.approval import ApprovalAction, ApprovalHandler, ApprovalManager, PendingApproval
from trustgate.storage.database import (
    DEFAULT_DB_PATH,
    get_tool,
    init_db,
    log_event,
    save_tool,
)


class StdioProxy:
    """Bidirectional inspecting stdio proxy between client stdin/stdout and child server process."""

    def __init__(
        self,
        target_cmd: str,
        server_name: str | None = None,
        publisher: str | None = None,
        db_path: str = DEFAULT_DB_PATH,
        use_llm: bool = False,
        api_key: str | None = None,
        auto_pin_approved: bool = True,
        approval_timeout: float = 30.0,
        approval_handler: ApprovalHandler | None = None,
    ):
        self.target_cmd = target_cmd
        self.server_name = server_name
        self.publisher = publisher
        self.db_path = db_path
        self.use_llm = use_llm
        self.api_key = api_key
        self.auto_pin_approved = auto_pin_approved
        self.approvals = ApprovalManager(timeout=approval_timeout, handler=approval_handler, db_path=db_path)

        self.proc: asyncio.subprocess.Process | None = None
        self.stdin_queue: asyncio.Queue[str | None] = asyncio.Queue()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._stop_event = threading.Event()

        self.blocked_tools: set[str] = set()
        self.held_tools: set[str] = set()
        self.approved_tools: set[str] = set()
        self._held_decisions: dict[str, PolicyDecision] = {}
        self._held_manifests: dict[str, dict[str, Any]] = {}

        # Initialize SQLite database
        init_db(self.db_path)

    def _infer_server_name(self) -> str:
        """Infer server name from explicit argument, command path, or fallback."""
        if self.server_name:
            return self.server_name

        # Infer from target command
        try:
            parts = shlex.split(self.target_cmd)
            for part in parts:
                if part.endswith(".py"):
                    base = Path(part).stem
                    # If target is calculator_poisoned or calculator_v2, base identity is calculator
                    if base.startswith("calculator"):
                        return "calculator"
                    return base
        except Exception:
            pass

        return "mcp_server"

    def _stdin_reader(self) -> None:
        """Dedicated background thread to read sys.stdin without blocking asyncio on Windows."""
        try:
            while not self._stop_event.is_set():
                line = sys.stdin.readline()
                if not line:
                    if self.loop and self.loop.is_running():
                        self.loop.call_soon_threadsafe(self.stdin_queue.put_nowait, None)
                    break
                if self.loop and self.loop.is_running():
                    self.loop.call_soon_threadsafe(self.stdin_queue.put_nowait, line)
        except Exception:
            if self.loop and self.loop.is_running():
                self.loop.call_soon_threadsafe(self.stdin_queue.put_nowait, None)

    async def forward_inbound(self) -> None:
        """Forward client stdin lines to server process, intercepting calls to blocked tools."""
        server = self._infer_server_name()
        while True:
            line = await self.stdin_queue.get()
            if line is None:
                # Client closed stdin (EOF)
                if self.proc and self.proc.stdin and not self.proc.stdin.is_closing():
                    try:
                        self.proc.stdin.close()
                        await self.proc.stdin.wait_closed()
                    except Exception:
                        pass
                break

            parsed = parse_message(line)

            # Intercept tool calls targeted at blocked tools
            if parsed.is_tool_call:
                t_name, _ = parsed.get_tool_call_info()
                if t_name and t_name in self.blocked_tools:
                    # Return JSON-RPC error to client stdout without forwarding to server
                    req_id = parsed.data.get("id") if parsed.data else None
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32600,
                            "message": f"TrustGate Security Policy: Tool '{t_name}' on server '{server}' is BLOCKED.",
                        },
                    }
                    err_bytes = (json.dumps(err_resp) + "\n").encode("utf-8")
                    sys.stdout.buffer.write(err_bytes)
                    sys.stdout.buffer.flush()
                    continue
                if t_name and t_name in self.held_tools:
                    decision = self._held_decisions[t_name]
                    action = await self._request_approval(server, t_name, decision, parsed.data.get("id"))
                    if action == ApprovalAction.BLOCK or action == ApprovalAction.REJECT_UPDATE:
                        req_id = parsed.data.get("id") if parsed.data else None
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32600, "message": f"TrustGate Security Policy: Tool '{t_name}' approval denied."},
                        }
                        sys.stdout.buffer.write((json.dumps(err_resp) + "\n").encode("utf-8"))
                        sys.stdout.buffer.flush()
                        continue
                    if action == ApprovalAction.APPROVE_UPDATE:
                        manifest = self._held_manifests[t_name]
                        save_tool(server, t_name, compute_tool_fingerprint(manifest), manifest, db_path=self.db_path)
                        self.held_tools.discard(t_name)
                        self.approved_tools.add(t_name)
                        self._held_decisions.pop(t_name, None)
                        self._held_manifests.pop(t_name, None)

            if self.proc and self.proc.stdin and not self.proc.stdin.is_closing():
                data = line.encode("utf-8") if isinstance(line, str) else line
                self.proc.stdin.write(data)
                await self.proc.stdin.drain()

    def _process_tool_list_response(
        self,
        server: str,
        parsed_data: dict[str, Any],
    ) -> tuple[dict[str, Any], list[PolicyDecision]]:
        """Evaluate tools in a tools/list response, updating vault and filtering blocked tools."""
        result_obj = parsed_data.get("result", {})
        raw_tools = result_obj.get("tools", [])
        if not isinstance(raw_tools, list):
            return parsed_data, []

        allowed_tools: list[dict[str, Any]] = []
        decisions: list[PolicyDecision] = []

        for tool in raw_tools:
            if not isinstance(tool, dict):
                allowed_tools.append(tool)
                continue

            t_name = tool.get("name", "")
            decision = evaluate_tool_manifest(
                server=server,
                tool=tool,
                publisher=self.publisher,
                db_path=self.db_path,
                use_llm=self.use_llm,
                api_key=self.api_key,
            )
            decisions.append(decision)

            # Log audit event in database
            log_event(
                server=server,
                event_type="MANIFEST_INSPECTION",
                risk=decision.risk_score,
                decision=decision.action.value,
                detail=json.dumps(
                    {
                        "reasons": decision.reasons,
                        "signals": decision.signals,
                        "assessment": decision.as_dict(),
                        "diff": decision.diff,
                        "tool_name": t_name,
                    }
                ),
                db_path=self.db_path,
            )
            audit_detail = json.dumps({
                "request_id": uuid.uuid4().hex,
                "tool": t_name,
                "reasons": decision.reasons,
                "assessment": decision.as_dict(),
                "fingerprint_status": decision.evidence.get("fingerprint_status"),
            })
            for event_type in ("TOOL_DISCOVERY", "POLICY_DECISION"):
                log_event(
                    server=server,
                    event_type=event_type,
                    risk=decision.risk_score,
                    decision=decision.action.value,
                    detail=audit_detail,
                    db_path=self.db_path,
                )
            if decision.evidence.get("regex_findings"):
                log_event(server, "REGEX_FINDING", decision.risk_score, decision.action.value, audit_detail, db_path=self.db_path)
            if decision.signals.get("llm_status") != "SKIPPED":
                log_event(server, "LLM_ANALYSIS", decision.risk_score, decision.action.value, audit_detail, db_path=self.db_path)
            if decision.evidence.get("fingerprint_status") == "changed":
                log_event(server, "FINGERPRINT_CHANGE", decision.risk_score, decision.action.value, audit_detail, db_path=self.db_path)

            # Display panel to stderr console
            show_event(decision, server=server, tool_name=t_name)

            # Policy enforcement
            if decision.action == PolicyAction.BLOCK:
                self.blocked_tools.add(t_name)
                log_event(server, "BLOCK", decision.risk_score, decision.action.value, audit_detail, db_path=self.db_path)
                # Withhold tool from manifest forwarded to agent
                continue
            elif decision.action == PolicyAction.HOLD:
                self.held_tools.add(t_name)
                self._held_decisions[t_name] = decision
                self._held_manifests[t_name] = dict(tool)
                # Forward the tool so calls can enter the async approval flow.
                allowed_tools.append(tool)
            else:
                # ALLOW
                self.approved_tools.add(t_name)
                if self.auto_pin_approved:
                    fp = compute_tool_fingerprint(tool)
                    save_tool(server, t_name, fp, tool, db_path=self.db_path)
                    log_event(server, "FINGERPRINT_CREATED", decision.risk_score, decision.action.value, audit_detail, db_path=self.db_path)
                log_event(server, "ALLOW", decision.risk_score, decision.action.value, audit_detail, db_path=self.db_path)
                allowed_tools.append(tool)

        # Construct updated response
        new_data = deepcopy(parsed_data)
        new_data["result"]["tools"] = allowed_tools
        return new_data, decisions

    async def _request_approval(
        self,
        server: str,
        tool_name: str,
        decision: PolicyDecision,
        request_id: Any,
    ) -> ApprovalAction:
        approval_id = str(request_id) if request_id is not None else uuid.uuid4().hex
        old_record = get_tool(server, tool_name, db_path=self.db_path) or {}
        manifest = self._held_manifests.get(tool_name, {})
        pending = PendingApproval(
            request_id=approval_id,
            server=server,
            tool=tool_name,
            risk_score=decision.risk_score,
            severity=decision.severity,
            reason="; ".join(decision.reasons) or "TrustGate policy requires approval.",
            evidence=list(decision.evidence.get("regex_findings", [])),
            old_hash=old_record.get("fingerprint", ""),
            new_hash=compute_tool_fingerprint(manifest) if manifest else "",
            fingerprint_change=decision.evidence.get("fingerprint_status") == "changed",
        )
        log_event(
            server=server,
            event_type="HOLD",
            risk=decision.risk_score,
            decision=decision.action.value,
            detail=json.dumps({"request_id": approval_id, "tool": tool_name, "pending": pending.as_dict()}),
            db_path=self.db_path,
        )
        _, action = await self.approvals.request(pending)
        log_event(
            server=server,
            event_type=action.value,
            risk=decision.risk_score,
            decision=decision.action.value,
            detail=json.dumps({"request_id": approval_id, "tool": tool_name, "user_action": action.value}),
            db_path=self.db_path,
        )
        return action

    def _process_output_response(
        self,
        server: str,
        parsed_data: dict[str, Any],
    ) -> tuple[dict[str, Any], Any]:
        """Inspect and sanitize outbound tool call response."""
        sanitized_msg, res = sanitize_mcp_response(
            parsed_data,
            use_llm=self.use_llm,
            api_key=self.api_key,
        )

        if res.was_redacted or res.escalated:
            policy_decision = decide(
                is_output_injection=res.injection_detected,
                server=server,
                tool_name="tool_call",
            )
            log_event(
                server=server,
                event_type="OUTPUT_SANITIZATION",
                risk=policy_decision.risk_score,
                decision=res.action.value,
                detail=json.dumps(
                    {
                        "policy_action": policy_decision.action.value,
                        "policy_reasons": policy_decision.reasons,
                        "assessment": policy_decision.as_dict(),
                        "reason": res.reason,
                        "original_text": res.original_text,
                        "sanitized_text": res.sanitized_text,
                        "is_modified": res.is_modified,
                        "injection_detected": res.injection_detected,
                        "redacted_spans": res.redacted_spans,
                        "signals": {
                            "is_output_injection": res.injection_detected,
                            "llm_status": res.llm_status,
                            "llm_confidence": res.llm_confidence,
                            "llm_reason": res.llm_reason,
                            "llm_classification": res.llm_classification,
                            "llm_uncertainty": res.llm_uncertainty,
                            "llm_severity": res.llm_severity,
                            "llm_evidence": res.llm_evidence,
                        },
                    }
                ),
                db_path=self.db_path,
            )
            log_event(
                server=server,
                event_type="OUTPUT_THREAT",
                risk=policy_decision.risk_score,
                decision=policy_decision.action.value,
                detail=json.dumps({"assessment": policy_decision.as_dict(), "tool": "tool_call"}),
                db_path=self.db_path,
            )
            show_sanitization_event(res, server=server)

        return sanitized_msg, res

    async def forward_outbound(self) -> None:
        """Inspect and forward server process stdout lines to client stdout."""
        if not self.proc or not self.proc.stdout:
            return

        server = self._infer_server_name()

        while True:
            line = await self.proc.stdout.readline()
            if not line:
                break

            parsed = parse_message(line)

            # Check for serverInfo during initialize to capture official server name
            if parsed.is_response and parsed.data and "result" in parsed.data:
                s_info = parsed.data["result"].get("serverInfo")
                if isinstance(s_info, dict) and s_info.get("name"):
                    server = self.server_name or s_info.get("name") or server

            # Case A: Outbound Tool List Response
            if parsed.is_tool_list and parsed.data and "result" in parsed.data:
                updated_data, _ = self._process_tool_list_response(server, parsed.data)
                out_bytes = (json.dumps(updated_data) + "\n").encode("utf-8")
                sys.stdout.buffer.write(out_bytes)
                sys.stdout.buffer.flush()
                continue

            # Case B: Outbound Tool Call Result Response
            if parsed.is_response and parsed.data and "result" in parsed.data:
                res_obj = parsed.data["result"]
                if isinstance(res_obj, dict) and "content" in res_obj:
                    sanitized_data, _ = self._process_output_response(server, parsed.data)
                    out_bytes = (json.dumps(sanitized_data) + "\n").encode("utf-8")
                    sys.stdout.buffer.write(out_bytes)
                    sys.stdout.buffer.flush()
                    continue

            # Case C: All other messages pass through directly
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def forward_stderr(self) -> None:
        """Forward server process stderr to client stderr."""
        if not self.proc or not self.proc.stderr:
            return
        while True:
            line = await self.proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    async def run(self) -> int:
        """Launch target MCP server and run bidirectional inspecting proxy."""
        self.loop = asyncio.get_running_loop()
        server = self._infer_server_name()
        log_event(
            server=server,
            event_type="MCP_CONNECTION",
            risk=0,
            decision="ALLOW",
            detail=json.dumps({"event_id": uuid.uuid4().hex, "status": "connected"}),
            db_path=self.db_path,
        )

        parts = shlex.split(self.target_cmd, posix=(sys.platform != "win32"))
        if not parts:
            raise ValueError("Target command cannot be empty.")

        # Cross-platform resolution for python executable
        if sys.platform == "win32":
            if parts[0].lower() in ("python", "python3") and not shutil.which(parts[0]):
                parts[0] = sys.executable

        self.proc = await asyncio.create_subprocess_exec(
            *parts,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        reader_thread = threading.Thread(target=self._stdin_reader, daemon=True)
        reader_thread.start()

        inbound_task = asyncio.create_task(self.forward_inbound(), name="forward_inbound")
        outbound_task = asyncio.create_task(self.forward_outbound(), name="forward_outbound")
        stderr_task = asyncio.create_task(self.forward_stderr(), name="forward_stderr")

        async def monitor_proc():
            if self.proc:
                await self.proc.wait()
                if not inbound_task.done():
                    inbound_task.cancel()

        monitor_task = asyncio.create_task(monitor_proc(), name="monitor_proc")

        try:
            await asyncio.gather(inbound_task, outbound_task, stderr_task, return_exceptions=True)
        finally:
            self._stop_event.set()
            monitor_task.cancel()
            if self.proc and self.proc.returncode is None:
                try:
                    self.proc.terminate()
                    await self.proc.wait()
                except Exception:
                    pass
            log_event(
                server=server,
                event_type="MCP_DISCONNECTION",
                risk=0,
                decision="ALLOW",
                detail=json.dumps({"event_id": uuid.uuid4().hex, "status": "disconnected"}),
                db_path=self.db_path,
            )

        return self.proc.returncode if self.proc and self.proc.returncode is not None else 0
