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
from typing import Any

from trustgate.console.dashboard import show_event, show_sanitization_event
from trustgate.mechanisms.fingerprint import compute_tool_fingerprint
from trustgate.mechanisms.output_sanitizer import sanitize_mcp_response
from trustgate.policy.engine import (
    PolicyAction,
    PolicyDecision,
    evaluate_tool_manifest,
)
from trustgate.proxy.parser import parse_message
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
    ):
        self.target_cmd = target_cmd
        self.server_name = server_name
        self.publisher = publisher
        self.db_path = db_path
        self.use_llm = use_llm
        self.api_key = api_key
        self.auto_pin_approved = auto_pin_approved

        self.proc: asyncio.subprocess.Process | None = None
        self.stdin_queue: asyncio.Queue[str | None] = asyncio.Queue()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._stop_event = threading.Event()

        self.blocked_tools: set[str] = set()
        self.held_tools: set[str] = set()
        self.approved_tools: set[str] = set()

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
                detail="; ".join(decision.reasons) or "Clean manifest",
                db_path=self.db_path,
            )

            # Display panel to stderr console
            show_event(decision, server=server, tool_name=t_name)

            # Policy enforcement
            if decision.action == PolicyAction.BLOCK:
                self.blocked_tools.add(t_name)
                # Withhold tool from manifest forwarded to agent
                continue
            elif decision.action == PolicyAction.HOLD:
                self.held_tools.add(t_name)
                # Forward with hold status logged
                allowed_tools.append(tool)
            else:
                # ALLOW
                self.approved_tools.add(t_name)
                if self.auto_pin_approved:
                    fp = compute_tool_fingerprint(tool)
                    save_tool(server, t_name, fp, tool, db_path=self.db_path)
                allowed_tools.append(tool)

        # Construct updated response
        new_data = deepcopy(parsed_data)
        new_data["result"]["tools"] = allowed_tools
        return new_data, decisions

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
            log_event(
                server=server,
                event_type="OUTPUT_SANITIZATION",
                risk=res.risk_score,
                decision=res.action.value,
                detail=res.reason,
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

        return self.proc.returncode if self.proc and self.proc.returncode is not None else 0
