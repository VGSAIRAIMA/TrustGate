"""MCP TrustGate Live Demo Rehearsal Script (Stage 17).

Executes all 5 scenes from DEMO_SCRIPT.md back-to-back live through the real TrustGate proxy:
  Scene 1: Typosquatted new server (fireb4se-mcp-server) -> flagged pre-approval (HOLD)
  Scene 2: Approve clean Calculator -> approved and pinned (ALLOW)
  Scene 3: Swap in poisoned Calculator -> blocked with unified diff (BLOCK)
  Scene 4: Query Docs Search with poisoned doc -> output sanitized (REDACTED)
  Scene 5: Swap in benign-update Calculator v2 -> held for re-approval (HOLD)

Usage:
  python demo_rehearsal.py
"""

import asyncio
import argparse
import os
import sys
import tempfile
import time

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from rich.console import Console
from rich.rule import Rule

from dashboard import build_scene_view, fetch_snapshot

console = Console(stderr=True)


def proxy_environment() -> dict[str, str]:
    """Forward optional semantic-scanner settings through MCP's child environment."""
    environment = {}
    for name in ("OPENROUTER_API_KEY", "OPENROUTER_MODEL"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


async def run_scene_1(python_exe: str, db_path: str):
    console.print(Rule("[bold yellow]SCENE 1: Typosquatted New Server (fireb4se-mcp-server)[/bold yellow]"))
    params = StdioServerParameters(
        command=python_exe,
        args=[
            "trustgate/main.py",
            "run",
            "--target",
            f"{python_exe} servers/calculator.py",
            "--name",
            "fireb4se-mcp-server",
            "--publisher",
            "unverified",
            "--db",
            db_path,
        ],
        env=proxy_environment(),
    )
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()


async def run_scene_2(python_exe: str, db_path: str):
    console.print(Rule("[bold green]SCENE 2: Initial Run & Approval of Clean Calculator[/bold green]"))
    params = StdioServerParameters(
        command=python_exe,
        args=[
            "trustgate/main.py",
            "run",
            "--target",
            f"{python_exe} servers/calculator.py",
            "--name",
            "calculator",
            "--publisher",
            "trustgate-demo",
            "--db",
            db_path,
        ],
        env=proxy_environment(),
    )
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            console.print(f"[dim]Discovered tools: {[t.name for t in tools.tools]}[/dim]")
            res = await session.call_tool("calculate", {"expression": "21 * 2"})
            console.print(f"[bold green]Execution result: 21 * 2 = {res.content[0].text}[/bold green]")


async def run_scene_3(python_exe: str, db_path: str):
    console.print(Rule("[bold red]SCENE 3: Swap in Poisoned Calculator (Silent Mutation / Rug-Pull)[/bold red]"))
    params = StdioServerParameters(
        command=python_exe,
        args=[
            "trustgate/main.py",
            "run",
            "--target",
            f"{python_exe} servers/calculator_poisoned.py",
            "--name",
            "calculator",
            "--publisher",
            "trustgate-demo",
            "--db",
            db_path,
        ],
        env=proxy_environment(),
    )
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            console.print(f"[dim]Available tools to agent: {[t.name for t in tools.tools]} (poisoned tool withheld!)[/dim]")


async def run_scene_4(python_exe: str, db_path: str):
    console.print(Rule("[bold yellow]SCENE 4: Query Docs Search with Poisoned Document[/bold yellow]"))
    params = StdioServerParameters(
        command=python_exe,
        args=[
            "trustgate/main.py",
            "run",
            "--target",
            f"{python_exe} servers/docs_search.py",
            "--name",
            "docs_search",
            "--publisher",
            "trustgate-demo",
            "--db",
            db_path,
        ],
        env=proxy_environment(),
    )
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            res = await session.call_tool("search_docs", {"query": "leave_policy_poisoned"})
            console.print("[bold cyan]Agent Received Sanitized Output:[/bold cyan]")
            console.print(f"[dim]{res.content[0].text}[/dim]")


async def run_scene_5(python_exe: str, db_path: str):
    console.print(Rule("[bold yellow]SCENE 5: Swap in Benign-Update Calculator (v2.0 Version Bump)[/bold yellow]"))
    params = StdioServerParameters(
        command=python_exe,
        args=[
            "trustgate/main.py",
            "run",
            "--target",
            f"{python_exe} servers/calculator_v2.py",
            "--name",
            "calculator",
            "--publisher",
            "trustgate-demo",
            "--db",
            db_path,
        ],
        env=proxy_environment(),
    )
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            console.print(f"[dim]Tools forwarded under review: {[t.name for t in tools.tools]}[/dim]")


async def main(db_path: str | None = None):
    console.print("[bold white on blue] === MCP TrustGate 5-Scene Demo Rehearsal === [/bold white on blue]\n")
    python_exe = sys.executable

    temp_dir = tempfile.TemporaryDirectory() if db_path is None else None
    try:
        rehearsal_db = db_path or os.path.join(temp_dir.name, "rehearsal.db")

        start = time.time()
        await run_scene_1(python_exe, rehearsal_db)
        console.print(build_scene_view(fetch_snapshot(rehearsal_db), "SCENE 1 / IDENTITY", "MANIFEST_INSPECTION"))
        await asyncio.sleep(0.5)

        await run_scene_2(python_exe, rehearsal_db)
        console.print(build_scene_view(fetch_snapshot(rehearsal_db), "SCENE 2 / APPROVAL", "MANIFEST_INSPECTION"))
        await asyncio.sleep(0.5)

        await run_scene_3(python_exe, rehearsal_db)
        console.print(build_scene_view(fetch_snapshot(rehearsal_db), "SCENE 3 / MUTATION", "MANIFEST_INSPECTION"))
        await asyncio.sleep(0.5)

        await run_scene_4(python_exe, rehearsal_db)
        console.print(build_scene_view(fetch_snapshot(rehearsal_db), "SCENE 4 / SANITIZATION", "OUTPUT_SANITIZATION"))
        await asyncio.sleep(0.5)

        await run_scene_5(python_exe, rehearsal_db)
        console.print(build_scene_view(fetch_snapshot(rehearsal_db), "SCENE 5 / BENIGN UPDATE", "MANIFEST_INSPECTION"))

        elapsed = time.time() - start
        console.print(f"\n[bold green][OK] All 5 scenes completed successfully in {elapsed:.2f}s![/bold green]")
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the five-scene TrustGate rehearsal.")
    parser.add_argument("--db", default=None, help="SQLite path shared with the live dashboard.")
    args = parser.parse_args()
    asyncio.run(main(args.db))
