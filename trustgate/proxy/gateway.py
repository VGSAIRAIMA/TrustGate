"""MCP-compatible TrustGate gateway.

The gateway exposes an MCP server to the upstream agent and uses an MCP
ClientSession to connect to one configured downstream MCP server. Security
inspection stays between those two protocol endpoints.
"""

from contextlib import AsyncExitStack
import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from trustgate.console.dashboard import show_event, show_sanitization_event
from trustgate.mechanisms.fingerprint import compute_tool_fingerprint
from trustgate.mechanisms.output_sanitizer import sanitize_mcp_response
from trustgate.policy.engine import PolicyAction, decide, evaluate_tool_manifest
from trustgate.proxy.approval import ApprovalAction, ApprovalHandler, ApprovalManager, PendingApproval
from trustgate.proxy.adapter import DownstreamConfig, inherited_overrides
from trustgate.storage.database import DEFAULT_DB_PATH, get_tool, init_db, log_event, save_tool


class MCPGateway:
    """Bridge one upstream MCP session to one inspected downstream session."""

    def __init__(
        self,
        downstream: DownstreamConfig,
        server_name: str,
        publisher: str | None = None,
        db_path: str = DEFAULT_DB_PATH,
        use_llm: bool = False,
        api_key: str | None = None,
        approval_timeout: float = 30.0,
        approval_handler: ApprovalHandler | None = None,
    ):
        self.downstream = downstream
        self.server_name = server_name
        self.publisher = publisher
        self.db_path = db_path
        self.use_llm = use_llm
        self.api_key = api_key
        self.approvals = ApprovalManager(timeout=approval_timeout, handler=approval_handler, db_path=db_path)
        self.session: ClientSession | None = None
        self.tools: dict[str, Tool] = {}
        self.blocked_tools: set[str] = set()
        self.held_tools: set[str] = set()
        self._held_decisions: dict[str, Any] = {}
        init_db(db_path)

    async def inspect_tools(self) -> list[Tool]:
        if self.session is None:
            raise RuntimeError("Downstream MCP session is not initialized.")

        result = await self.session.list_tools()
        allowed: list[Tool] = []
        self.tools.clear()
        self.blocked_tools.clear()
        self.held_tools.clear()
        self._held_decisions.clear()

        for tool in result.tools:
            manifest = tool.model_dump(by_alias=True, exclude_none=True)
            decision = evaluate_tool_manifest(
                server=self.server_name,
                tool=manifest,
                publisher=self.publisher,
                db_path=self.db_path,
                use_llm=self.use_llm,
                api_key=self.api_key,
            )
            log_event(
                server=self.server_name,
                event_type="MANIFEST_INSPECTION",
                risk=decision.risk_score,
                decision=decision.action.value,
                detail=json.dumps(
                    {
                        "reasons": decision.reasons,
                        "signals": decision.signals,
                        "assessment": decision.as_dict(),
                        "diff": decision.diff,
                        "tool_name": tool.name,
                        "gateway": True,
                    }
                ),
                db_path=self.db_path,
            )
            self._audit(
                "TOOL_DISCOVERY",
                tool.name,
                decision,
                request_id=uuid.uuid4().hex,
                fingerprint_status=decision.evidence.get("fingerprint_status"),
            )
            self._audit("POLICY_DECISION", tool.name, decision, request_id=uuid.uuid4().hex)
            if decision.evidence.get("fingerprint_status") == "changed":
                self._audit("FINGERPRINT_CHANGE", tool.name, decision, request_id=uuid.uuid4().hex)
            if decision.evidence.get("regex_findings"):
                self._audit("REGEX_FINDING", tool.name, decision, request_id=uuid.uuid4().hex)
            if decision.signals.get("llm_status") != "SKIPPED":
                self._audit("LLM_ANALYSIS", tool.name, decision, request_id=uuid.uuid4().hex)
            show_event(decision, server=self.server_name, tool_name=tool.name)

            if decision.action == PolicyAction.BLOCK:
                self.blocked_tools.add(tool.name)
                self._audit("BLOCK", tool.name, decision, request_id=uuid.uuid4().hex, user_action="POLICY")
                continue
            if decision.action == PolicyAction.HOLD:
                self.held_tools.add(tool.name)
                self._held_decisions[tool.name] = decision
                # Expose the tool so a call can enter the async approval flow.
                self.tools[tool.name] = tool
                allowed.append(tool)
                continue

            self.tools[tool.name] = tool
            allowed.append(tool)
            self._audit("ALLOW", tool.name, decision, request_id=uuid.uuid4().hex, user_action="POLICY")
            fp = compute_tool_fingerprint(manifest)
            save_tool(self.server_name, tool.name, fp, manifest, db_path=self.db_path)
            self._audit(
                "FINGERPRINT_CREATED",
                tool.name,
                decision,
                request_id=uuid.uuid4().hex,
                fingerprint_status="created",
                new_hash=fp,
            )

        return allowed

    async def list_tools(self, _context: Any, _params: Any) -> ListToolsResult:
        tools = await self.inspect_tools()
        return ListToolsResult(tools=tools)

    async def call_tool(self, _context: Any, params: Any) -> CallToolResult:
        tool_name = params.name
        if tool_name in self.blocked_tools:
            return self._tool_error(tool_name, "BLOCKED by TrustGate policy.")
        if tool_name in self.held_tools and tool_name not in self.tools:
            return self._tool_error(tool_name, "HELD pending TrustGate approval.")
        if tool_name not in self.tools:
            return self._tool_error(tool_name, "Tool is not exposed by TrustGate.")
        if self.session is None:
            return self._tool_error(tool_name, "Downstream MCP session is unavailable.")

        if tool_name in self.held_tools:
            decision = self._held_decisions[tool_name]
            request_id = uuid.uuid4().hex
            pending = PendingApproval(
                request_id=request_id,
                server=self.server_name,
                tool=tool_name,
                risk_score=decision.risk_score,
                severity=decision.severity,
                reason="; ".join(decision.reasons) or "TrustGate policy requires approval.",
                evidence=self._approval_evidence(decision),
                old_hash=(get_tool(self.server_name, tool_name, db_path=self.db_path) or {}).get("fingerprint", ""),
                new_hash=self._incoming_hash(tool_name),
                fingerprint_change=decision.evidence.get("fingerprint_status") == "changed",
            )
            self._audit("HOLD", tool_name, decision, request_id=request_id, user_action="PENDING_APPROVAL")
            pending, action = await self.approvals.request(pending)
            if action == ApprovalAction.BLOCK:
                self._audit("BLOCK", tool_name, decision, request_id=request_id, user_action=action.value)
                return self._tool_error(tool_name, "BLOCKED by TrustGate approval.")
            if action == ApprovalAction.REJECT_UPDATE:
                self._audit("FINGERPRINT_REJECTION", tool_name, decision, request_id=request_id, user_action=action.value, old_hash=pending.old_hash, new_hash=pending.new_hash)
                return self._tool_error(tool_name, "Fingerprint update rejected; pinned baseline retained.")
            if action == ApprovalAction.APPROVE_UPDATE:
                manifest = self.tools[tool_name].model_dump(by_alias=True, exclude_none=True)
                new_hash = self._incoming_hash(tool_name)
                save_tool(self.server_name, tool_name, new_hash, manifest, db_path=self.db_path)
                self.held_tools.discard(tool_name)
                self._held_decisions.pop(tool_name, None)
                self._audit("FINGERPRINT_APPROVAL", tool_name, decision, request_id=request_id, user_action=action.value, old_hash=pending.old_hash, new_hash=new_hash)
            else:
                self._audit("ALLOW_ONCE", tool_name, decision, request_id=request_id, user_action=action.value)

        try:
            result = await self.session.call_tool(tool_name, params.arguments or {})
        except Exception as exc:
            return self._tool_error(tool_name, f"Downstream MCP error: {type(exc).__name__}: {exc}")

        raw_result = result.model_dump(by_alias=True, exclude_none=True)
        response = {"result": raw_result}
        sanitized_response, sanitize_result = sanitize_mcp_response(
            response,
            use_llm=self.use_llm,
            api_key=self.api_key,
        )
        if sanitize_result.was_redacted or sanitize_result.escalated:
            policy_decision = decide(
                evidence={
                    "output_findings": [sanitize_result.reason] if sanitize_result.injection_detected else [],
                    "llm_classification": (
                        sanitize_result.llm_classification
                        if sanitize_result.llm_status in {"PERFORMED", "CACHED"}
                        else sanitize_result.llm_status
                    ),
                    "llm_confidence": sanitize_result.llm_confidence,
                    "llm_result": {
                        "classification": sanitize_result.llm_classification,
                        "malicious_probability": sanitize_result.llm_confidence,
                        "uncertainty": sanitize_result.llm_uncertainty,
                        "severity": sanitize_result.llm_severity,
                        "reason": sanitize_result.llm_reason,
                        "evidence": sanitize_result.llm_evidence,
                    },
                },
                tool_metadata={"server": self.server_name, "tool": tool_name, "channel": "output"},
                server=self.server_name,
                tool_name=tool_name,
            )
            # The policy assessment, rather than the detector, owns the score
            # displayed and recorded for this output inspection.
            sanitize_result.risk_score = policy_decision.risk_score
            log_event(
                server=self.server_name,
                event_type="OUTPUT_SANITIZATION",
                risk=policy_decision.risk_score,
                decision=sanitize_result.action.value,
                detail=json.dumps(
                    {
                        "policy_action": policy_decision.action.value,
                        "policy_reasons": policy_decision.reasons,
                        "assessment": {
                            "severity": policy_decision.severity,
                            "triggered_rules": policy_decision.triggered_rules,
                            "evidence": policy_decision.evidence,
                            "recommended_action": policy_decision.recommended_action.value,
                            "final_policy_decision": policy_decision.final_policy_decision.value,
                        },
                        "reason": sanitize_result.reason,
                        "redacted_spans": sanitize_result.redacted_spans,
                        "signals": {
                            "is_output_injection": sanitize_result.injection_detected,
                            "llm_status": sanitize_result.llm_status,
                            "llm_confidence": sanitize_result.llm_confidence,
                            "llm_reason": sanitize_result.llm_reason,
                            "llm_classification": sanitize_result.llm_classification,
                            "llm_uncertainty": sanitize_result.llm_uncertainty,
                            "llm_severity": sanitize_result.llm_severity,
                            "llm_evidence": sanitize_result.llm_evidence,
                        },
                        "tool_name": tool_name,
                        "gateway": True,
                    }
                ),
                db_path=self.db_path,
            )
            self._audit("OUTPUT_THREAT", tool_name, policy_decision, request_id=uuid.uuid4().hex)
            show_sanitization_event(sanitize_result, server=self.server_name, tool_name=tool_name)

        return CallToolResult.model_validate(sanitized_response["result"])

    def pending_approvals(self) -> list[dict[str, Any]]:
        """Return pending approval records for a terminal/UI integration."""
        return self.approvals.list_pending()

    def get_pending_approvals(self) -> list[dict[str, Any]]:
        """UI-friendly alias for listing pending approval requests."""
        return self.pending_approvals()

    async def approve(self, request_id: str, action: ApprovalAction | str) -> bool:
        """Resolve a pending approval from a UI/API without blocking MCP."""
        return await self.approvals.resolve(request_id, action)

    async def approve_pending(self, request_id: str, action: ApprovalAction | str) -> bool:
        """UI-friendly alias for resolving one pending request."""
        return await self.approve(request_id, action)

    def _incoming_hash(self, tool_name: str) -> str:
        tool = self.tools.get(tool_name)
        if tool is None:
            return ""
        return compute_tool_fingerprint(tool.model_dump(by_alias=True, exclude_none=True))

    @staticmethod
    def _approval_evidence(decision: Any) -> list[str]:
        evidence = list(decision.evidence.get("regex_findings", []))
        evidence.extend(decision.evidence.get("output_findings", []))
        if decision.llm_result:
            evidence.extend(decision.llm_result.get("evidence", []))
        return list(dict.fromkeys(evidence))

    def _audit(
        self,
        event_type: str,
        tool: str,
        decision: Any,
        request_id: str,
        user_action: str = "",
        fingerprint_status: str = "",
        old_hash: str = "",
        new_hash: str = "",
    ) -> None:
        detail = {
            "event_id": request_id,
            "request_id": request_id,
            "tool": tool,
            "server": self.server_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": decision.severity,
            "llm_result": decision.llm_result,
            "fingerprint_status": fingerprint_status or decision.evidence.get("fingerprint_status"),
            "triggered_rules": decision.triggered_rules,
            "user_action": user_action,
            "new_hash": new_hash,
            "old_hash": old_hash,
            "llm_classification": (decision.llm_result or {}).get("classification"),
            "llm_probability": (decision.llm_result or {}).get("malicious_probability"),
        }
        log_event(
            server=self.server_name,
            event_type=event_type,
            risk=decision.risk_score,
            decision=decision.action.value,
            detail=json.dumps(detail),
            db_path=self.db_path,
        )

    @staticmethod
    def _tool_error(tool_name: str, message: str) -> CallToolResult:
        return CallToolResult(
            is_error=True,
            content=[TextContent(type="text", text=f"TrustGate: {tool_name}: {message}")],
        )

    async def run(self) -> None:
        self._audit_connection("MCP_CONNECTION", "connected")
        params = self.downstream.mcp_parameters()
        async with AsyncExitStack() as stack:
            read, write = await stack.enter_async_context(stdio_client(params, errlog=sys.stderr))
            self.session = await stack.enter_async_context(ClientSession(read, write))
            await self.session.initialize()
            server = Server(
                "TrustGate Gateway",
                version="0.1.0",
                on_list_tools=self.list_tools,
                on_call_tool=self.call_tool,
            )
            init_options = server.create_initialization_options()
            async with stdio_server() as (upstream_read, upstream_write):
                await server.run(upstream_read, upstream_write, init_options)
        self._audit_connection("MCP_DISCONNECTION", "disconnected")

    def _audit_connection(self, event_type: str, status: str) -> None:
        log_event(
            server=self.server_name,
            event_type=event_type,
            risk=0,
            decision="ALLOW",
            detail=json.dumps({"status": status, "server": self.server_name, "event_id": uuid.uuid4().hex}),
            db_path=self.db_path,
        )
