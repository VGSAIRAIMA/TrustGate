"""TrustGate registry identity check (pre-approval typosquatting & impersonation detector).

Screens never-before-seen MCP server names against a curated known-good registry
using rapidfuzz similarity scoring to detect typosquatting (e.g., 'fireb4se-mcp-server'
vs 'firebase-mcp-server') and publisher impersonation before initial approval.
Deterministic, rule-based, no LLM required.
"""

from dataclasses import dataclass
from typing import Any

from rapidfuzz import fuzz


@dataclass(frozen=True)
class RegistryEntry:
    name: str
    publisher: str
    verified: bool = True
    description: str = ""


# Curated known-good MCP server registry
KNOWN_REGISTRY: dict[str, RegistryEntry] = {
    "firebase-mcp-server": RegistryEntry(
        name="firebase-mcp-server",
        publisher="firebase",
        verified=True,
        description="Official Firebase MCP server for cloud backend operations.",
    ),
    "calculator": RegistryEntry(
        name="calculator",
        publisher="trustgate-demo",
        verified=True,
        description="Demo calculator MCP server.",
    ),
    "docs_search": RegistryEntry(
        name="docs_search",
        publisher="trustgate-demo",
        verified=True,
        description="Demo documentation search MCP server.",
    ),
    "email_tool": RegistryEntry(
        name="email_tool",
        publisher="trustgate-demo",
        verified=True,
        description="Demo email dispatch MCP server.",
    ),
    "github-mcp-server": RegistryEntry(
        name="github-mcp-server",
        publisher="github",
        verified=True,
        description="Official GitHub repository and issue management MCP server.",
    ),
    "filesystem-mcp-server": RegistryEntry(
        name="filesystem-mcp-server",
        publisher="modelcontextprotocol",
        verified=True,
        description="Standard reference filesystem MCP server.",
    ),
    "postgres-mcp-server": RegistryEntry(
        name="postgres-mcp-server",
        publisher="modelcontextprotocol",
        verified=True,
        description="PostgreSQL database query and schema MCP server.",
    ),
    "slack-mcp-server": RegistryEntry(
        name="slack-mcp-server",
        publisher="slack",
        verified=True,
        description="Slack messaging and channel administration MCP server.",
    ),
    "sqlite-mcp-server": RegistryEntry(
        name="sqlite-mcp-server",
        publisher="modelcontextprotocol",
        verified=True,
        description="SQLite database MCP server.",
    ),
    "brave-search-mcp-server": RegistryEntry(
        name="brave-search-mcp-server",
        publisher="brave",
        verified=True,
        description="Brave web search MCP server.",
    ),
}


@dataclass
class RegistryCheckResult:
    server_name: str
    publisher: str | None
    flagged: bool
    similarity: float
    matched_name: str | None = None
    matched_publisher: str | None = None
    reason: str = ""

    @property
    def is_flagged(self) -> bool:
        return self.flagged


def compute_name_similarity(name1: str, name2: str) -> float:
    """Compute normalized similarity score (0.0 to 1.0) between two server names."""
    n1 = name1.strip().lower()
    n2 = name2.strip().lower()
    if n1 == n2:
        return 1.0
    return fuzz.ratio(n1, n2) / 100.0


def registry_check(
    server_name: str,
    publisher: str | None = None,
    threshold: float = 0.85,
    registry: dict[str, RegistryEntry] | None = None,
) -> RegistryCheckResult:
    """Screen a server name against curated known-good registry for typosquatting or impersonation.

    Checks:
    1. Exact Name Match:
       - If server name is in the registry and publisher matches the verified publisher -> NOT FLAGGED (authentic).
       - If publisher is provided and does not match the verified publisher -> FLAGGED (impersonation / publisher mismatch).
       - If no publisher is provided and server claims an official name -> FLAGGED as unverified.

    2. High Similarity Match (Typosquatting / Slopsquatting):
       - If server name is not identical, but similarity >= threshold (e.g. fireb4se-mcp-server vs firebase-mcp-server)
         and publisher is not the verified publisher -> FLAGGED (typosquatting detected).

    3. Low Similarity / Genuinely New:
       - If highest similarity < threshold -> NOT FLAGGED (novel unique server).
    """
    reg = registry if registry is not None else KNOWN_REGISTRY
    normalized_name = server_name.strip().lower()
    pub_clean = publisher.strip().lower() if publisher else None

    # Check 1: Exact match with a known-good registry name
    for entry in reg.values():
        if normalized_name == entry.name.lower():
            known_pub = entry.publisher.lower()
            if pub_clean == known_pub:
                return RegistryCheckResult(
                    server_name=server_name,
                    publisher=publisher,
                    flagged=False,
                    similarity=1.0,
                    matched_name=entry.name,
                    matched_publisher=entry.publisher,
                    reason=f"Authentic verified server from publisher '{entry.publisher}'.",
                )
            else:
                return RegistryCheckResult(
                    server_name=server_name,
                    publisher=publisher,
                    flagged=True,
                    similarity=1.0,
                    matched_name=entry.name,
                    matched_publisher=entry.publisher,
                    reason=(
                        f"Impersonation alert: '{server_name}' claims official registry name "
                        f"but publisher '{publisher or 'unverified'}' does not match verified publisher '{entry.publisher}'."
                    ),
                )

    # Check 2: Similarity search for lookalike / typosquatted names
    best_entry: RegistryEntry | None = None
    best_score: float = 0.0

    for entry in reg.values():
        score = compute_name_similarity(normalized_name, entry.name)
        if score > best_score:
            best_score = score
            best_entry = entry

    best_score = round(best_score, 4)

    if best_entry and best_score >= threshold:
        # Publisher mismatch / unverified typosquat
        known_pub = best_entry.publisher.lower()
        if pub_clean != known_pub:
            return RegistryCheckResult(
                server_name=server_name,
                publisher=publisher,
                flagged=True,
                similarity=best_score,
                matched_name=best_entry.name,
                matched_publisher=best_entry.publisher,
                reason=(
                    f"Typosquatting detected: '{server_name}' has {best_score:.1%} similarity to "
                    f"known '{best_entry.name}' with mismatched publisher '{publisher or 'unverified'}' "
                    f"(expected '{best_entry.publisher}')."
                ),
            )

    # Check 3: New unique server name
    return RegistryCheckResult(
        server_name=server_name,
        publisher=publisher,
        flagged=False,
        similarity=best_score,
        matched_name=best_entry.name if best_entry else None,
        matched_publisher=best_entry.publisher if best_entry else None,
        reason="New unique server name; no typosquatting detected.",
    )
