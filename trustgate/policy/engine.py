"""TrustGate Policy Engine (Stage 15).

Deterministic weighted-scoring decision function combining multi-tier signals
(registry screening, cryptographic fingerprint diffs, regex signatures, LLM semantic
confidence, and data-channel output injection).

Explicitly NOT an LLM decision; purely deterministic math and rule-based policy.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from trustgate.mechanisms.mutation import check_mutation
from trustgate.mechanisms.output_sanitizer import sanitize_output
from trustgate.mechanisms.registry import registry_check
from trustgate.security.llm_scanner import llm_scan
from trustgate.security.normalizer import normalize_text
from trustgate.security.patterns import regex_scan
from trustgate.storage.database import DEFAULT_DB_PATH

# Default tuned weights aligned with ARCHITECTURE.md line 91-105
DEFAULT_WEIGHT_REGISTRY = 40
DEFAULT_WEIGHT_FINGERPRINT = 20
DEFAULT_WEIGHT_REGEX = 20
DEFAULT_WEIGHT_LLM = 30
DEFAULT_WEIGHT_OUTPUT_INJECTION = 40

DEFAULT_THRESHOLD_BLOCK = 60
DEFAULT_THRESHOLD_HOLD = 20


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


@dataclass
class PolicyDecision:
    action: PolicyAction
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)
    server: str = ""
    tool_name: str = ""
    diff: str = ""

    @property
    def is_allowed(self) -> bool:
        return self.action == PolicyAction.ALLOW

    @property
    def is_held(self) -> bool:
        return self.action == PolicyAction.HOLD

    @property
    def is_blocked(self) -> bool:
        return self.action == PolicyAction.BLOCK


def decide(
    registry_flagged: bool = False,
    fingerprint_changed: bool = False,
    regex_flagged: bool = False,
    llm_flagged: bool = False,
    llm_confidence: float = 0.0,
    is_output_injection: bool = False,
    server: str = "",
    tool_name: str = "",
    diff: str = "",
    weight_registry: int = DEFAULT_WEIGHT_REGISTRY,
    weight_fingerprint: int = DEFAULT_WEIGHT_FINGERPRINT,
    weight_regex: int = DEFAULT_WEIGHT_REGEX,
    weight_llm: int = DEFAULT_WEIGHT_LLM,
    weight_output_injection: int = DEFAULT_WEIGHT_OUTPUT_INJECTION,
    threshold_block: int = DEFAULT_THRESHOLD_BLOCK,
    threshold_hold: int = DEFAULT_THRESHOLD_HOLD,
) -> PolicyDecision:
    """Deterministic weighted-scoring decision function.

    Formula:
    risk = 0
    +40 if registry_flagged
    +20 if fingerprint_changed
    +20 if regex_flagged
    +30 if llm_confidence > 0.8
    +40 if is_output_injection

    Policy thresholds:
    risk >= 60  -> BLOCK
    risk >= 20  -> HOLD
    else        -> ALLOW
    """
    risk = 0
    reasons: list[str] = []
    signals: dict[str, Any] = {}

    if registry_flagged:
        risk += weight_registry
        reasons.append("Registry alert: server name flagged for typosquatting or publisher mismatch (+40).")
        signals["registry_flagged"] = True
    else:
        signals["registry_flagged"] = False

    if fingerprint_changed:
        risk += weight_fingerprint
        reasons.append("Fingerprint alert: tool contract mutated from pinned SQLite vault hash (+20).")
        signals["fingerprint_changed"] = True
    else:
        signals["fingerprint_changed"] = False

    if regex_flagged:
        risk += weight_regex
        reasons.append("Regex alert: known prompt injection or exfiltration phrasing detected (+20).")
        signals["regex_flagged"] = True
    else:
        signals["regex_flagged"] = False

    if llm_flagged and llm_confidence > 0.8:
        risk += weight_llm
        reasons.append(f"LLM semantic alert: malicious instruction identified with {llm_confidence:.0%} confidence (+30).")
        signals["llm_flagged"] = True
        signals["llm_confidence"] = llm_confidence
    else:
        signals["llm_flagged"] = False
        signals["llm_confidence"] = llm_confidence

    if is_output_injection:
        risk += weight_output_injection
        reasons.append("Output alert: data-channel prompt injection detected in tool response (+40).")
        signals["is_output_injection"] = True
    else:
        signals["is_output_injection"] = False

    # Deterministic threshold evaluation
    if risk >= threshold_block:
        action = PolicyAction.BLOCK
    elif risk >= threshold_hold:
        action = PolicyAction.HOLD
    else:
        action = PolicyAction.ALLOW

    return PolicyDecision(
        action=action,
        risk_score=risk,
        reasons=reasons,
        signals=signals,
        server=server,
        tool_name=tool_name,
        diff=diff,
    )


def evaluate_tool_manifest(
    server: str,
    tool: dict[str, Any],
    publisher: str | None = None,
    db_path: str = DEFAULT_DB_PATH,
    use_llm: bool = False,
    api_key: str | None = None,
) -> PolicyDecision:
    """Evaluate an incoming tool manifest through the entire TrustGate inspection pipeline."""
    tool_name = tool.get("name", "")
    description = tool.get("description", "")
    norm_desc = normalize_text(description)

    # 1. Check mutation against vault
    mutation_res = check_mutation(server, tool, db_path=db_path)
    is_new = mutation_res.is_new
    has_mutated = mutation_res.changed
    diff_text = mutation_res.diff

    # 2. Check registry identity (for new servers)
    reg_flagged = False
    if is_new:
        reg_res = registry_check(server, publisher=publisher)
        reg_flagged = reg_res.flagged

    # 3. Regex scan description
    regex_res = regex_scan(norm_desc, normalize_first=False)
    reg_tripped = regex_res.matched

    # 4. Optional LLM scan
    llm_flagged = False
    llm_conf = 0.0
    if use_llm or (reg_tripped and has_mutated):
        llm_res = llm_scan(norm_desc, api_key=api_key, normalize_first=False)
        if not llm_res.is_inconclusive and llm_res.malicious:
            llm_flagged = True
            llm_conf = llm_res.confidence

    # 5. Decide
    return decide(
        registry_flagged=reg_flagged,
        fingerprint_changed=has_mutated,
        regex_flagged=reg_tripped,
        llm_flagged=llm_flagged,
        llm_confidence=llm_conf,
        is_output_injection=False,
        server=server,
        tool_name=tool_name,
        diff=diff_text,
    )
