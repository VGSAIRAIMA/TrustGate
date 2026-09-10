"""Configuration for a downstream MCP server connection."""

from dataclasses import dataclass, field
import os
import shlex
import shutil
import sys
from pathlib import Path


@dataclass(frozen=True)
class DownstreamConfig:
    """Command and process settings for one downstream MCP server."""

    target: str
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None

    def command_parts(self) -> list[str]:
        parts = shlex.split(self.target, posix=(sys.platform != "win32"))
        if not parts:
            raise ValueError("Downstream target command cannot be empty.")
        if sys.platform == "win32" and parts[0].lower() in {"python", "python3"}:
            if not shutil.which(parts[0]):
                parts[0] = sys.executable
        return parts

    def mcp_parameters(self):
        from mcp.client.stdio import StdioServerParameters

        return StdioServerParameters(
            command=self.command_parts()[0],
            args=self.command_parts()[1:],
            env=self.env or None,
            cwd=Path(self.cwd) if self.cwd else None,
        )


def infer_server_name(target: str) -> str:
    """Choose a stable default identity without tying the gateway to one server."""
    try:
        for part in shlex.split(target, posix=(sys.platform != "win32")):
            if part.endswith(".py"):
                stem = Path(part).stem
                if stem.startswith("calculator"):
                    return "calculator"
                return stem
    except ValueError:
        pass
    return "mcp_server"


def inherited_overrides() -> dict[str, str]:
    """Return optional environment values that must cross an MCP process boundary."""
    return {
        name: value
        for name in ("OPENROUTER_API_KEY", "OPENROUTER_MODEL")
        if (value := os.environ.get(name))
    }
