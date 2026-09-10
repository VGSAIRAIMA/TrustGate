"""MCP TrustGate CLI entrypoint."""

import argparse
import asyncio
from pathlib import Path
import sys

# Ensure repository root is on sys.path when executed directly
project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from trustgate.proxy.core import StdioProxy


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

    return parser.parse_args(args)


def main():
    args = parse_args()
    if args.command == "run":
        print(f"[TrustGate] Launching target: {args.target}", file=sys.stderr)
        proxy = StdioProxy(args.target)
        try:
            return asyncio.run(proxy.run())
        except KeyboardInterrupt:
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
