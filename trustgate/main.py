"""MCP TrustGate CLI entrypoint (Stage 17)."""

import argparse
import asyncio
import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path when executed directly
project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from trustgate.proxy.core import StdioProxy
from trustgate.storage.database import DEFAULT_DB_PATH


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        prog="trustgate",
        description="MCP TrustGate - Real-time tool integrity and trust verification system for MCP",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # `run` command
    run_parser = subparsers.add_parser("run", help="Run MCP TrustGate proxy in front of an MCP server")
    run_parser.add_argument(
        "--target",
        required=True,
        help="Target command to launch the MCP server (e.g. 'python servers/calculator.py')",
    )
    run_parser.add_argument(
        "--name",
        default=None,
        help="Explicit server identity name (default: auto-inferred from target or serverInfo)",
    )
    run_parser.add_argument(
        "--publisher",
        default=None,
        help="Server publisher identity (used for registry typosquatting and impersonation checks)",
    )
    run_parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database (default: {DEFAULT_DB_PATH})",
    )
    run_parser.add_argument(
        "--use-llm",
        action="store_true",
        default=bool(os.environ.get("OPENROUTER_API_KEY")),
        help="Enable OpenRouter semantic LLM scanning tier (defaults to True if OPENROUTER_API_KEY is set)",
    )

    return parser.parse_args(args)


def main():
    args = parse_args()
    if args.command == "run":
        print(f"[TrustGate] Launching target: {args.target}", file=sys.stderr)
        proxy = StdioProxy(
            target_cmd=args.target,
            server_name=args.name,
            publisher=args.publisher,
            db_path=args.db,
            use_llm=args.use_llm,
        )
        try:
            return asyncio.run(proxy.run())
        except KeyboardInterrupt:
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
