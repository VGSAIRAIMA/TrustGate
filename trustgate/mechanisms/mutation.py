"""TrustGate mutation and diff engine.

Detects silent mutations in MCP tool manifests by comparing incoming client-side
computed fingerprints against pinned hashes in the SQLite vault, and produces
line-level unified diffs explaining exactly what was altered.
"""

from dataclasses import dataclass
import difflib
import json
from typing import Any

from trustgate.mechanisms.fingerprint import compute_tool_fingerprint
from trustgate.storage.database import DEFAULT_DB_PATH, get_tool


@dataclass
class MutationResult:
    server: str
    tool_name: str
    is_new: bool
    changed: bool
    diff: str
    current_fingerprint: str
    stored_fingerprint: str | None = None
    stored_manifest: dict[str, Any] | None = None
    current_manifest: dict[str, Any] | None = None

    @property
    def has_mutated(self) -> bool:
        return self.changed


def generate_manifest_diff(
    server: str,
    tool_name: str,
    stored_manifest: dict[str, Any],
    incoming_manifest: dict[str, Any],
    stored_fingerprint: str = "",
    current_fingerprint: str = "",
) -> str:
    """Generate a clean, line-level unified diff between stored and incoming tool manifests."""
    stored_lines = json.dumps(stored_manifest, indent=2, sort_keys=True).splitlines(keepends=True)
    incoming_lines = json.dumps(incoming_manifest, indent=2, sort_keys=True).splitlines(keepends=True)

    from_label = f"{server}/{tool_name} [pinned {stored_fingerprint[:8]}...]" if stored_fingerprint else f"{server}/{tool_name} [pinned]"
    to_label = f"{server}/{tool_name} [incoming {current_fingerprint[:8]}...]" if current_fingerprint else f"{server}/{tool_name} [incoming]"

    diff_lines = list(difflib.unified_diff(
        stored_lines,
        incoming_lines,
        fromfile=from_label,
        tofile=to_label,
    ))
    return "".join(diff_lines)


def check_mutation(
    server: str,
    tool: dict[str, Any],
    db_path: str = DEFAULT_DB_PATH,
    stored_tool: dict[str, Any] | None = None,
) -> MutationResult:
    """Check whether an incoming tool manifest mutates from its pinned vault fingerprint.

    If tool is brand new: returns is_new=True, changed=False.
    If tool matches pinned hash: returns is_new=False, changed=False.
    If tool differs from pinned hash: returns is_new=False, changed=True, plus line-level diff.
    """
    tool_name = tool.get("name", "")
    current_fp = compute_tool_fingerprint(tool)

    stored = stored_tool or get_tool(server, tool_name, db_path=db_path)

    # 1. New unpinned tool
    if not stored:
        return MutationResult(
            server=server,
            tool_name=tool_name,
            is_new=True,
            changed=False,
            diff="",
            current_fingerprint=current_fp,
            stored_fingerprint=None,
            stored_manifest=None,
            current_manifest=tool,
        )

    stored_fp = stored["fingerprint"]

    # 2. Unchanged tool matching pinned fingerprint
    if stored_fp == current_fp:
        return MutationResult(
            server=server,
            tool_name=tool_name,
            is_new=False,
            changed=False,
            diff="",
            current_fingerprint=current_fp,
            stored_fingerprint=stored_fp,
            stored_manifest=stored.get("manifest"),
            current_manifest=tool,
        )

    # 3. Mutated tool (silent modification / rug-pull)
    stored_manifest = stored.get("manifest", {})
    diff_text = generate_manifest_diff(
        server=server,
        tool_name=tool_name,
        stored_manifest=stored_manifest,
        incoming_manifest=tool,
        stored_fingerprint=stored_fp,
        current_fingerprint=current_fp,
    )

    return MutationResult(
        server=server,
        tool_name=tool_name,
        is_new=False,
        changed=True,
        diff=diff_text,
        current_fingerprint=current_fp,
        stored_fingerprint=stored_fp,
        stored_manifest=stored_manifest,
        current_manifest=tool,
    )
