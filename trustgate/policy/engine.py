"""TrustGate Policy Engine (Stage 15).

Deterministic weighted-scoring decision function combining multi-tier signals
(registry screening, cryptographic fingerprint diffs, regex signatures, LLM semantic
confidence, and data-channel output injection).

Explicitly NOT an LLM decision; purely deterministic math and rule-based policy.
"""

from dataclasses import dataclass, field
from enum import Enum
import os
import time
from typing import Any

from trustgate.mechanisms.mutation import check_mutation
from trustgate.mechanisms.output_sanitizer import sanitize_output
from trustgate.mechanisms.registry import registry_check
from trustgate.security.llm_scanner import llm_scan
from trustgate.security.normalizer import normalize_text
from trustgate.security.patterns import regex_scan
from trustgate.storage.database import DEFAULT_DB_PATH

# Default tuned weights aligned with ARCHITECTURE.md line 91-105 and BUILD_PLAN.md Stage 15
DEFAULT_WEIGHT_REGISTRY = 40
DEFAULT_WEIGHT_FINGERPRINT = 20
DEFAULT_WEIGHT_REGEX = 40
DEFAULT_WEIGHT_LLM = 30
DEFAULT_WEIGHT_OUTPUT_INJECTION = 40

DEFAULT_THRESHOLD_BLOCK = 60
DEFAULT_THRESHOLD_HOLD = 20
LLM_CACHE_POLICY_VERSION = "1"
DEFAULT_LLM_CACHE_TTL_SECONDS = 300.0
_LLM_CACHE: dict[tuple[str, str, str, str, str], tuple[float, Any]] = {}


def clear_llm_cache() -> None:
    """Invalidate semantic results after policy/configuration changes."""
    _LLM_CACHE.clear()


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


@dataclass
class SecurityAssessment:
    """Complete, deterministic assessment of one TrustGate inspection.

    Detector output is evidence only.  This object is the single place where
    evidence becomes a risk score and an enforcement decision.
    """

    action: PolicyAction
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)
    triggered_rules: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    llm_result: dict[str, Any] | None = None
    severity: str = "low"
    recommended_action: PolicyAction = PolicyAction.ALLOW
    final_policy_decision: PolicyAction = PolicyAction.ALLOW
    server: str = ""
    tool_name: str = ""
    diff: str = ""

    @property
    def decision(self) -> PolicyAction:
        """Compatibility alias for callers that refer to the final decision."""
        return self.final_policy_decision

    def as_dict(self) -> dict[str, Any]:
        """Return the complete assessment in an audit- and UI-friendly shape."""
        return {
            "risk_score": self.risk_score,
            "triggered_rules": list(self.triggered_rules),
            "evidence": dict(self.evidence),
            "llm_result": self.llm_result,
            "severity": self.severity,
            "recommended_action": self.recommended_action.value,
            "final_policy_decision": self.final_policy_decision.value,
        }

    @property
    def is_allowed(self) -> bool:
        return self.action == PolicyAction.ALLOW

    @property
    def is_held(self) -> bool:
        return self.action == PolicyAction.HOLD

    @property
    def is_blocked(self) -> bool:
        return self.action == PolicyAction.BLOCK


# Existing callers import PolicyDecision; keep that public API while exposing
# the more precise assessment name for new integrations.
PolicyDecision = SecurityAssessment


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
    evidence: dict[str, Any] | None = None,
    tool_metadata: dict[str, Any] | None = None,
) -> PolicyDecision:
    """Deterministic weighted-scoring decision function.

    Formula:
    risk = 0
    +40 if registry_flagged
    +20 if fingerprint_changed
    +40 if regex_flagged
    +30 if llm_classification == "malicious"
    +40 if is_output_injection

    Policy thresholds:
    risk >= 60  -> BLOCK
    risk >= 20  -> HOLD
    else        -> ALLOW
    """
    evidence = dict(evidence or {})
    tool_metadata = dict(tool_metadata or evidence.get("tool_metadata", {}))
    llm_confidence = float(evidence.get("llm_confidence", llm_confidence))

    # Normalize legacy flags into the structured evidence contract.  The
    # policy engine scores classifications and findings, never raw confidence.
    registry_status = evidence.get("registry_status", "flagged" if registry_flagged else "clean")
    fingerprint_status = evidence.get("fingerprint_status", "changed" if fingerprint_changed else "match")
    regex_findings = list(evidence.get("regex_findings", []))
    if regex_flagged and not regex_findings:
        regex_findings = ["known_pattern_match"]
    llm_classification = str(evidence.get("llm_classification", "malicious" if llm_flagged else "SKIPPED"))
    output_findings = list(evidence.get("output_findings", []))
    if is_output_injection and not output_findings:
        output_findings = ["output_injection"]

    registry_flagged = registry_status == "flagged"
    fingerprint_changed = fingerprint_status == "changed"
    regex_flagged = bool(regex_findings)
    llm_flagged = llm_classification == "malicious"
    is_output_injection = bool(output_findings)

    risk = 0
    reasons: list[str] = []
    triggered_rules: list[str] = []
    contributions: dict[str, int] = {}

    def add_signal(rule: str, amount: int, reason: str) -> None:
        nonlocal risk
        risk += amount
        triggered_rules.append(rule)
        contributions[rule] = amount
        reasons.append(f"{reason} (+{amount}).")

    if registry_flagged:
        add_signal("registry_flagged", weight_registry, "Registry alert: server identity flagged for typosquatting or publisher mismatch")

    if fingerprint_changed:
        add_signal("fingerprint_changed", weight_fingerprint, "Fingerprint alert: tool contract changed from the pinned SQLite vault hash")

    if regex_flagged:
        add_signal("regex_findings", weight_regex, "Regex alert: known prompt injection or exfiltration phrasing detected")

    if llm_flagged:
        add_signal("llm_malicious", weight_llm, "LLM semantic alert: malicious instruction classified")

    if is_output_injection:
        add_signal("output_findings", weight_output_injection, "Output alert: data-channel prompt injection detected in tool response")

    # Deterministic threshold evaluation
    if risk >= threshold_block:
        action = PolicyAction.BLOCK
    elif risk >= threshold_hold:
        action = PolicyAction.HOLD
    else:
        action = PolicyAction.ALLOW

    severity = "high" if risk >= threshold_block else "medium" if risk >= threshold_hold else "low"
    normalized_evidence = {
        "registry_status": registry_status,
        "fingerprint_status": fingerprint_status,
        "regex_findings": regex_findings,
        "llm_classification": llm_classification,
        "llm_confidence": llm_confidence,
        "output_findings": output_findings,
        "tool_metadata": tool_metadata,
        "policy_contributions": contributions,
    }
    signals = {
        "registry_flagged": registry_flagged,
        "fingerprint_changed": fingerprint_changed,
        "regex_flagged": regex_flagged,
        "llm_flagged": llm_flagged,
        "llm_confidence": llm_confidence,
        "is_output_injection": is_output_injection,
        "registry_status": registry_status,
        "fingerprint_status": fingerprint_status,
        "regex_findings": regex_findings,
        "llm_classification": llm_classification,
        "output_findings": output_findings,
        "tool_metadata": tool_metadata,
        "policy_contributions": contributions,
    }
    return SecurityAssessment(
        action=action,
        risk_score=risk,
        reasons=reasons,
        signals=signals,
        triggered_rules=triggered_rules,
        evidence=normalized_evidence,
        llm_result=evidence.get("llm_result"),
        severity=severity,
        recommended_action=action,
        final_policy_decision=action,
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
    skip_llm_if_clean: bool = True,
    llm_cache_ttl: float = DEFAULT_LLM_CACHE_TTL_SECONDS,
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

    # 3. Cheap deterministic regex scan description
    regex_res = regex_scan(norm_desc, normalize_first=False)
    reg_tripped = regex_res.matched

    # 4. Optional LLM scan
    llm_flagged = False
    llm_conf = 0.0
    llm_result: dict[str, Any] | None = None
    llm_status = "SKIPPED"
    llm_reason = "LLM scan not requested for this manifest."
    llm_model = ""
    trusted_unchanged_clean = (
        not is_new
        and not has_mutated
        and not reg_flagged
        and not reg_tripped
    )
    should_run_llm = (use_llm and not (skip_llm_if_clean and trusted_unchanged_clean)) or (reg_tripped and has_mutated)
    if should_run_llm:
        requested_model = os.environ.get("OPENROUTER_MODEL", "openrouter/free")
        cache_key = (
            server,
            tool_name,
            mutation_res.current_fingerprint,
            requested_model,
            LLM_CACHE_POLICY_VERSION,
        )
        cached = _LLM_CACHE.get(cache_key)
        if cached is not None and time.monotonic() - cached[0] <= llm_cache_ttl:
            llm_res = cached[1]
            llm_status = "CACHED"
        else:
            llm_res = llm_scan(norm_desc, api_key=api_key, normalize_first=False)
            if not llm_res.is_inconclusive:
                _LLM_CACHE[cache_key] = (time.monotonic(), llm_res)
            llm_status = "UNAVAILABLE" if llm_res.is_inconclusive else "PERFORMED"
        llm_model = llm_res.model_used
        llm_reason = llm_res.reason
        llm_conf = llm_res.malicious_probability
        llm_result = llm_res.as_dict()
        llm_result["status"] = llm_status
        if not llm_res.is_inconclusive and llm_res.classification == "malicious":
            llm_flagged = True

    evidence = {
        "registry_status": "flagged" if reg_flagged else "clean",
        "fingerprint_status": "changed" if has_mutated else "match" if not is_new else "new",
        "regex_findings": regex_res.matches,
        "llm_classification": "malicious" if llm_flagged else "benign" if llm_status in {"PERFORMED", "CACHED"} else llm_status,
        "llm_confidence": llm_conf,
        "llm_result": llm_result or {
            "status": llm_status,
            "classification": "benign" if llm_status in {"PERFORMED", "CACHED"} else llm_status,
            "malicious_probability": llm_conf,
            "uncertainty": 1.0 if llm_status not in {"PERFORMED", "CACHED"} else 0.0,
            "severity": "low",
            "reason": llm_reason,
            "evidence": [],
            "model": llm_model,
        },
        "output_findings": [],
    }

    # 5. Aggregate evidence and make the deterministic policy decision.
    decision = decide(
        evidence=evidence,
        tool_metadata={"server": server, "tool": tool_name, "is_new": is_new},
        server=server,
        tool_name=tool_name,
        diff=diff_text,
    )
    decision.signals["llm_status"] = llm_status
    decision.signals["llm_reason"] = llm_reason
    decision.signals["llm_uncertainty"] = llm_result.get("uncertainty", 1.0) if llm_result else 1.0
    decision.signals["llm_severity"] = llm_result.get("severity", "low") if llm_result else "low"
    decision.signals["llm_evidence"] = llm_result.get("evidence", []) if llm_result else []
    if llm_model:
        decision.signals["llm_model"] = llm_model
    return decision
