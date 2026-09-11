"""Reproducible four-scenario TrustGate approval rehearsal.

Uses the real MCP demo servers and MCP ClientSession. Set N8N_WEBHOOK_URL
optionally to forward the generated audit events to an n8n webhook.
"""

import argparse
import asyncio
from contextlib import AsyncExitStack
import os
from pathlib import Path
import sys
import tempfile

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from trustgate.mechanisms.fingerprint import compute_tool_fingerprint
from trustgate.proxy.adapter import DownstreamConfig
from trustgate.proxy.approval import ApprovalAction
from trustgate.proxy.gateway import MCPGateway
from trustgate.storage.database import get_events, get_tool, init_db


async def scenario(
    label: str,
    server_script: str,
    db_path: str,
    action: ApprovalAction | None = None,
    use_llm: bool = False,
    server_name: str = "calculator",
) -> str:
    print(f"\n=== {label} ===")
    target_folder = "demo_servers" if server_script == "suspicious.py" else "servers"
    target = f"{sys.executable} {target_folder}/{server_script}"
    gateway = MCPGateway(
        DownstreamConfig(target=target),
        server_name,
        publisher="trustgate-demo",
        db_path=db_path,
        use_llm=use_llm,
        approval_handler=(lambda _pending: action) if action else None,
        approval_timeout=10.0,
    )
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(
            stdio_client(StdioServerParameters(command=sys.executable, args=[target_folder + "/" + server_script]))
        )
        gateway.session = await stack.enter_async_context(ClientSession(read, write))
        await gateway.session.initialize()
        tools = await gateway.inspect_tools()
        print(f"Tools exposed: {[tool.name for tool in tools]}")
        tool_name = "calculate"
        result = await gateway.call_tool(None, type("Params", (), {"name": tool_name, "arguments": {"expression": "2 + 2"}})())
        text = result.content[0].text if result.content else ""
        print(f"Call result: error={result.is_error} {text}")
    return text


async def main(db_path: str | None, use_llm: bool) -> None:
    temporary = tempfile.TemporaryDirectory() if db_path is None else None
    path = db_path or str(Path(temporary.name) / "scenarios.db")
    init_db(path)
    print(f"TrustGate audit database: {path}")
    if os.environ.get("N8N_WEBHOOK_URL"):
        print("Optional n8n forwarding: configured")
    else:
        print("Optional n8n forwarding: disabled (N8N_WEBHOOK_URL is unset)")

    await scenario("SAFE: deterministic ALLOW", "calculator.py", path, use_llm=use_llm)
    await scenario("SUSPICIOUS: HOLD then ALLOW ONCE", "suspicious.py", path, ApprovalAction.ALLOW_ONCE, use_llm=use_llm, server_name="suspicious-demo")
    await scenario("MALICIOUS: BLOCK before downstream call", "calculator_poisoned.py", path, use_llm=use_llm)
    await scenario("FINGERPRINT CHANGE: HOLD then APPROVE UPDATE", "calculator_v2.py", path, ApprovalAction.APPROVE_UPDATE, use_llm=use_llm)

    baseline = get_tool("calculator", "calculate", db_path=path)
    print(f"\nFinal baseline: {baseline['fingerprint'] if baseline else 'not pinned'}")
    events = get_events(server="calculator", db_path=path, limit=100)
    print(f"Real TrustGate events recorded: {len(events)}")
    print("Event types:", sorted({event["event_type"] for event in events}))
    if temporary is not None:
        temporary.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run four real TrustGate security scenarios.")
    parser.add_argument("--db", default=None, help="SQLite path to share with the Web UI and optional n8n forwarding.")
    parser.add_argument("--use-llm", action="store_true", help="Run the configured OpenRouter semantic tier when meaningful.")
    args = parser.parse_args()
    asyncio.run(main(args.db, args.use_llm))
