"""TrustGate cryptographic fingerprinting and pin engine.

Computes client-side deterministic SHA-256 fingerprints over tool manifests
(name + description + parameter schema). Never accepts a server-supplied hash.
"""

import hashlib
import hmac
import json
from typing import Any

from trustgate.security.normalizer import normalize_text, normalize_tool_manifest


def canonicalize_tool(tool: dict[str, Any], normalize_first: bool = True) -> str:
    """Canonicalize a single tool manifest dictionary to deterministic sorted JSON.

    Extracts canonical tool identity fields:
    - name: tool identifier
    - description: human-facing description
    - inputSchema: parameters JSON schema
    - outputSchema: output JSON schema (if present)

    Any server-provided hash or fingerprint fields are discarded.
    """
    if not isinstance(tool, dict):
        raise TypeError(f"Tool manifest must be a dict, got {type(tool).__name__}")

    # Work on a copy and strip any server-supplied hash keys
    raw_tool = {k: v for k, v in tool.items() if k not in ("hash", "fingerprint", "_fingerprint")}

    if normalize_first:
        raw_tool = normalize_tool_manifest(raw_tool)

    # Standardize schema key names if SDK variants use camelCase / snake_case
    canonical_dict = {
        "name": raw_tool.get("name", ""),
        "description": raw_tool.get("description", ""),
        "inputSchema": raw_tool.get("inputSchema") or raw_tool.get("input_schema") or {},
    }

    if "outputSchema" in raw_tool or "output_schema" in raw_tool:
        canonical_dict["outputSchema"] = raw_tool.get("outputSchema") or raw_tool.get("output_schema")

    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_tool_fingerprint(tool: dict[str, Any], normalize_first: bool = True) -> str:
    """Compute client-side SHA-256 fingerprint for a single tool.

    Never accepts or returns a server-supplied hash.
    """
    canonical_json = canonicalize_tool(tool, normalize_first=normalize_first)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_manifest_fingerprint(tools: list[dict[str, Any]], normalize_first: bool = True) -> str:
    """Compute client-side SHA-256 fingerprint for an entire server's tool manifest.

    Tools are sorted by name to ensure order-invariant canonicalization.
    """
    if not isinstance(tools, list):
        raise TypeError(f"Tools must be a list, got {type(tools).__name__}")

    # Sort tools by name for canonical ordering
    sorted_tools = sorted(tools, key=lambda t: t.get("name", "") if isinstance(t, dict) else "")

    canonical_tools = [
        canonicalize_tool(t, normalize_first=normalize_first)
        for t in sorted_tools
        if isinstance(t, dict)
    ]

    canonical_manifest = json.dumps(canonical_tools, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical_manifest.encode("utf-8")).hexdigest()


def verify_tool_fingerprint(tool: dict[str, Any], expected_fingerprint: str) -> bool:
    """Verify whether a tool matches an expected pinned fingerprint using constant-time comparison."""
    if not expected_fingerprint:
        return False
    actual_fingerprint = compute_tool_fingerprint(tool)
    return hmac.compare_digest(actual_fingerprint.lower(), expected_fingerprint.lower())
