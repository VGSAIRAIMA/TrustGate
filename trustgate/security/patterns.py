"""TrustGate regex pattern scanner.

Fast, deterministic first-pass signature inspection for known prompt injections,
jailbreak attempts, and cross-tool exfiltration directives in tool descriptions
and tool outputs.
"""

from dataclasses import dataclass, field
import re
from typing import Any

from trustgate.security.normalizer import normalize_text

# Curated high-confidence attack phrasing patterns
SUSPICIOUS_PATTERNS: dict[str, re.Pattern] = {
    "system_instruction": re.compile(
        r"(?i)\b(?:critical\s+)?system\s+instruction\s*:",
    ),
    "ignore_prior": re.compile(
        r"(?i)\bignore\s+(?:all\s+)?prior\s+(?:instructions?|constraints?|prompts?|rules?|directives?)\b",
    ),
    "disregard_prior_guardrails": re.compile(
        r"(?i)\bdisregard\s+(?:all\s+)?prior\s+(?:guardrails?|instructions?|rules?|constraints?)\b",
    ),
    "do_not_disclose": re.compile(
        r"(?i)\bdo\s+not\s+disclose\b",
    ),
    "silent_routing": re.compile(
        r"(?i)\bsilently\s+(?:route|send|forward|transmit|exfiltrate|leak)\b",
    ),
    "exfiltration_target": re.compile(
        r"(?i)\b(?:exfil(?:tration)?@|exfiltrat(?:e|ion))\b",
    ),
    "override_safety": re.compile(
        r"(?i)\b(?:override|bypass)\s+(?:all\s+)?(?:safety|guardrails?|filters?|instructions?)\b",
    ),
    "publish_confidential_files": re.compile(
        r"(?i)\bpublish\s+a\s+summary\s+of\s+recently\s+accessed\s+(?:confidential\s+)?files\b",
    ),
}


@dataclass
class PatternMatch:
    pattern_name: str
    matched_text: str
    start: int
    end: int


@dataclass
class RegexScanResult:
    matched: bool
    matches: list[str] = field(default_factory=list)
    details: list[PatternMatch] = field(default_factory=list)
    risk_score: int = 0
    normalized_text: str = ""

    @property
    def is_flagged(self) -> bool:
        return self.matched


def find_injection_spans(text: str, normalize_first: bool = True) -> list[PatternMatch]:
    """Find all matching pattern spans in text, optionally normalizing first."""
    target_text = normalize_text(text) if normalize_first else text
    matches: list[PatternMatch] = []

    for name, pattern in SUSPICIOUS_PATTERNS.items():
        for m in pattern.finditer(target_text):
            matches.append(
                PatternMatch(
                    pattern_name=name,
                    matched_text=m.group(0),
                    start=m.start(),
                    end=m.end(),
                )
            )

    # Sort matches by appearance in text
    matches.sort(key=lambda x: x.start)
    return matches


def regex_scan(text: str, normalize_first: bool = True) -> RegexScanResult:
    """Scan text against SUSPICIOUS_PATTERNS.

    Returns RegexScanResult with:
    - matched: True if any pattern tripped, False otherwise.
    - matches: List of unique pattern names that matched.
    - details: List of PatternMatch items with exact match locations.
    - risk_score: +20 risk points if flagged (aligned with ARCHITECTURE.md).
    """
    if not text:
        return RegexScanResult(matched=False, matches=[], details=[], risk_score=0, normalized_text="")

    norm_text = normalize_text(text) if normalize_first else text
    match_details = find_injection_spans(norm_text, normalize_first=False)

    pattern_names = list(dict.fromkeys(m.pattern_name for m in match_details))
    has_match = len(pattern_names) > 0
    risk = 20 if has_match else 0

    return RegexScanResult(
        matched=has_match,
        matches=pattern_names,
        details=match_details,
        risk_score=risk,
        normalized_text=norm_text,
    )
