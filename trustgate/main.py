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
from trustgate.proxy.adapter import DownstreamConfig, infer_server_name, inherited_overrides
from trustgate.proxy.gateway import MCPGateway
from trustgate.storage.database import DEFAULT_DB_PATH
from trustgate.web_dashboard import run_web_dashboard


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
    run_parser.add_argument("--approval-timeout", type=float, default=30.0, help="Seconds before pending approval fails closed.")

    gateway_parser = subparsers.add_parser(
        "gateway",
        help="Run an MCP-compatible TrustGate gateway in front of a downstream MCP server",
    )
    gateway_parser.add_argument("--target", required=True, help="Downstream MCP server command.")
    gateway_parser.add_argument("--name", default=None, help="Downstream server identity used by TrustGate.")
    gateway_parser.add_argument("--publisher", default=None, help="Downstream publisher identity.")
    gateway_parser.add_argument("--db", default=DEFAULT_DB_PATH, help="SQLite database path.")
    gateway_parser.add_argument(
        "--use-llm",
        action="store_true",
        default=bool(os.environ.get("OPENROUTER_API_KEY")),
        help="Enable OpenRouter semantic scanning when a key is configured.",
    )
    gateway_parser.add_argument("--approval-timeout", type=float, default=30.0, help="Seconds before pending approval fails closed.")
    gateway_parser.add_argument("--cwd", default=None, help="Working directory for the downstream server.")

    web_parser = subparsers.add_parser("web", help="Run the separate TrustGate Web UI and approval API.")
    web_parser.add_argument("--db", default=DEFAULT_DB_PATH, help="SQLite database path shared with TrustGate.")
    web_parser.add_argument("--host", default="127.0.0.1", help="Web UI bind host.")
    web_parser.add_argument("--port", type=int, default=8765, help="Web UI bind port.")

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
            approval_timeout=args.approval_timeout,
        )
        try:
            return asyncio.run(proxy.run())
        except KeyboardInterrupt:
            return 0
    if args.command == "gateway":
        name = args.name or infer_server_name(args.target)
        gateway = MCPGateway(
            downstream=DownstreamConfig(
                target=args.target,
                cwd=args.cwd,
                env=inherited_overrides(),
            ),
            server_name=name,
            publisher=args.publisher,
            db_path=args.db,
            use_llm=args.use_llm,
            approval_timeout=args.approval_timeout,
        )
        try:
            asyncio.run(gateway.run())
            return 0
        except KeyboardInterrupt:
            return 0
    if args.command == "web":
        run_web_dashboard(db_path=args.db, host=args.host, port=args.port)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
