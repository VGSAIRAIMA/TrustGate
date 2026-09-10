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
import os
import sys
import tempfile
import time

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from rich.console import Console
from rich.rule import Rule

console = Console(stderr=True)


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
    )
    async with stdio_client(params) as (read, write):
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
    )
    async with stdio_client(params) as (read, write):
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
    )
    async with stdio_client(params) as (read, write):
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
    )
    async with stdio_client(params) as (read, write):
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
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            console.print(f"[dim]Tools forwarded under review: {[t.name for t in tools.tools]}[/dim]")


async def main():
    console.print("[bold white on blue] === MCP TrustGate 5-Scene Demo Rehearsal === [/bold white on blue]\n")
    python_exe = sys.executable

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "rehearsal.db")

        start = time.time()
        await run_scene_1(python_exe, db_path)
        await asyncio.sleep(0.5)

        await run_scene_2(python_exe, db_path)
        await asyncio.sleep(0.5)

        await run_scene_3(python_exe, db_path)
        await asyncio.sleep(0.5)

        await run_scene_4(python_exe, db_path)
        await asyncio.sleep(0.5)

        await run_scene_5(python_exe, db_path)

        elapsed = time.time() - start
        console.print(f"\n[bold green]✓ All 5 scenes completed successfully in {elapsed:.2f}s![/bold green]")


if __name__ == "__main__":
    asyncio.run(main())
