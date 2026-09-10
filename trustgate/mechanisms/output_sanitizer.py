"""TrustGate Output Sanitizer (Stage 14).

Sanitizes untrusted tool output from outbound 'tools/call' responses before it
re-enters the agent's context.

Pipeline:
1. Unicode normalization (strip zero-width characters, NFKC, homoglyph folding).
2. Regex signature inspection (SUSPICIOUS_PATTERNS).
3. LLM semantic inspection (fallback for ambiguous/reworded attacks).
4. Policy action:
   - PASS: forward output unchanged when benign.
   - REDACTED: cleanly redacts high-confidence separable prompt injections while
     preserving legitimate clean content.
   - ESCALATE_FOR_REVIEW: holds ambiguous, entangled, or entirely malicious payloads
     for operator review instead of guessing.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any

from trustgate.security.llm_scanner import llm_scan
from trustgate.security.normalizer import normalize_text
from trustgate.security.patterns import find_injection_spans, regex_scan


class SanitizerAction(str, Enum):
    PASS = "PASS"
    REDACTED = "REDACTED"
    ESCALATE_FOR_REVIEW = "ESCALATE_FOR_REVIEW"


@dataclass
class SanitizeResult:
    action: SanitizerAction
    original_text: str
    sanitized_text: str
    is_modified: bool
    injection_detected: bool
    redacted_spans: list[str] = field(default_factory=list)
    reason: str = ""
    risk_score: int = 0

    @property
    def passed(self) -> bool:
        return self.action == SanitizerAction.PASS

    @property
    def was_redacted(self) -> bool:
        return self.action == SanitizerAction.REDACTED

    @property
    def escalated(self) -> bool:
        return self.action == SanitizerAction.ESCALATE_FOR_REVIEW


def extract_sentence_boundaries(text: str, start: int, end: int) -> tuple[int, int]:
    """Expand match span [start, end] to the surrounding sentence or statement boundaries."""
    # Find start of sentence (character after previous period/newline or start of text)
    span_start = 0
    delimiters = [". ", ".\n", "\n\n", "\n", "! ", "? "]
    
    # Look backwards from start
    best_delim_pos = -1
    for delim in delimiters:
        pos = text.rfind(delim, 0, start)
        if pos != -1:
            after_delim = pos + len(delim)
            if after_delim > best_delim_pos:
                best_delim_pos = after_delim

    if best_delim_pos != -1:
        span_start = best_delim_pos

    # Look forwards from end for sentence terminal
    span_end = len(text)
    end_delimiters = [".", "\n", "!", "?"]
    best_end_pos = len(text)

    for delim in end_delimiters:
        pos = text.find(delim, end)
        if pos != -1:
            after_end = pos + len(delim)
            if after_end < best_end_pos:
                best_end_pos = after_end

    if best_end_pos != len(text):
        span_end = best_end_pos

    return span_start, span_end


def sanitize_output(
    text: str,
    use_llm: bool = False,
    api_key: str | None = None,
    replacement: str = "[REDACTED]",
) -> SanitizeResult:
    """Sanitize tool output text against prompt injection and cross-tool hijacking.

    Returns SanitizeResult with:
    - action: PASS, REDACTED, or ESCALATE_FOR_REVIEW
    - sanitized_text: Cleaned text or original if PASS
    - is_modified: True if text was modified
    - injection_detected: True if an injection was found
    - risk_score: +40 if injection detected (per ARCHITECTURE.md)
    """
    if not text or not text.strip():
        return SanitizeResult(
            action=SanitizerAction.PASS,
            original_text=text,
            sanitized_text=text,
            is_modified=False,
            injection_detected=False,
            reason="Empty output text; passed.",
            risk_score=0,
        )

    # 1. Normalize text
    norm_text = normalize_text(text)

    # 2. Tier 1: Fast Regex Pattern Scan
    pattern_matches = find_injection_spans(norm_text, normalize_first=False)

    if pattern_matches:
        # High-confidence injection detected via regex signatures
        # Merge overlapping or contiguous sentence boundaries
        sentence_spans: list[tuple[int, int]] = []
        for m in pattern_matches:
            s_start, s_end = extract_sentence_boundaries(norm_text, m.start, m.end)
            sentence_spans.append((s_start, s_end))

        # Sort and merge spans
        sentence_spans.sort(key=lambda x: x[0])
        merged_spans: list[tuple[int, int]] = []
        for span in sentence_spans:
            if not merged_spans:
                merged_spans.append(span)
            else:
                prev_start, prev_end = merged_spans[-1]
                if span[0] <= prev_end:
                    merged_spans[-1] = (prev_start, max(prev_end, span[1]))
                else:
                    merged_spans.append(span)

        # Calculate total characters of malicious spans vs total content
        malicious_chars = sum(end - start for start, end in merged_spans)
        total_chars = len(norm_text.strip())

        # If the entire output is malicious (>85% injection with no meaningful clean content)
        # or nothing separable remains, escalate for operator review
        if malicious_chars >= total_chars * 0.85 or total_chars - malicious_chars < 15:
            return SanitizeResult(
                action=SanitizerAction.ESCALATE_FOR_REVIEW,
                original_text=text,
                sanitized_text=replacement,
                is_modified=True,
                injection_detected=True,
                redacted_spans=[norm_text[s:e] for s, e in merged_spans],
                reason="Ambiguous/entangled payload: output is predominantly or entirely injection; escalated for human review.",
                risk_score=40,
            )

        # Cleanly separable injection: perform redaction
        # Build sanitized text by replacing merged spans
        redacted_snippets: list[str] = []
        chunks: list[str] = []
        last_pos = 0

        for start, end in merged_spans:
            chunks.append(norm_text[last_pos:start])
            redacted_snippets.append(norm_text[start:end].strip())
            if replacement:
                chunks.append(f" {replacement} " if chunks and chunks[-1] and not chunks[-1].endswith(" ") else f"{replacement} ")
            last_pos = end

        chunks.append(norm_text[last_pos:])
        cleaned_text = "".join(chunks)

        # Normalize redundant whitespace
        cleaned_text = re.sub(r"[ \t]+", " ", cleaned_text)
        cleaned_text = re.sub(r"\n\s+", "\n", cleaned_text).strip()

        return SanitizeResult(
            action=SanitizerAction.REDACTED,
            original_text=text,
            sanitized_text=cleaned_text,
            is_modified=True,
            injection_detected=True,
            redacted_spans=redacted_snippets,
            reason=f"Separable injection redacted ({len(redacted_snippets)} segment(s) removed).",
            risk_score=40,
        )

    # 3. Tier 2: Optional LLM Semantic Scan (when enabled or needed)
    if use_llm:
        llm_res = llm_scan(norm_text, api_key=api_key, normalize_first=False)
        if not llm_res.is_inconclusive and llm_res.malicious and llm_res.confidence > 0.8:
            # Semantic injection detected without exact regex boundaries:
            # Ambiguous/entangled case per PRD -> escalate to human
            return SanitizeResult(
                action=SanitizerAction.ESCALATE_FOR_REVIEW,
                original_text=text,
                sanitized_text=text,
                is_modified=False,
                injection_detected=True,
                redacted_spans=[],
                reason=f"Semantic injection flagged by LLM (confidence: {llm_res.confidence:.2f}): {llm_res.reason}; escalated for human review.",
                risk_score=40,
            )

    # 4. Clean content: pass through unchanged
    return SanitizeResult(
        action=SanitizerAction.PASS,
        original_text=text,
        sanitized_text=text,
        is_modified=False,
        injection_detected=False,
        redacted_spans=[],
        reason="Clean output verified; passed without modification.",
        risk_score=0,
    )


def sanitize_mcp_response(
    response_msg: dict[str, Any],
    use_llm: bool = False,
    api_key: str | None = None,
    replacement: str = "[REDACTED]",
) -> tuple[dict[str, Any], SanitizeResult]:
    """Sanitize an MCP JSON-RPC tool response message.

    If redacted, updates the text items in result.content and returns the new message.
    """
    if not isinstance(response_msg, dict):
        return response_msg, SanitizeResult(
            action=SanitizerAction.PASS,
            original_text="",
            sanitized_text="",
            is_modified=False,
            injection_detected=False,
        )

    result_obj = response_msg.get("result")
    if not isinstance(result_obj, dict):
        return response_msg, SanitizeResult(
            action=SanitizerAction.PASS,
            original_text="",
            sanitized_text="",
            is_modified=False,
            injection_detected=False,
        )

    content_list = result_obj.get("content")
    if not isinstance(content_list, list) or not content_list:
        return response_msg, SanitizeResult(
            action=SanitizerAction.PASS,
            original_text="",
            sanitized_text="",
            is_modified=False,
            injection_detected=False,
        )

    # Find and sanitize text items
    overall_action = SanitizerAction.PASS
    last_res: SanitizeResult | None = None
    modified = False
    new_response = deepcopy(response_msg)

    for item in new_response["result"]["content"]:
        if isinstance(item, dict) and item.get("type") == "text":
            orig_text = item.get("text", "")
            res = sanitize_output(orig_text, use_llm=use_llm, api_key=api_key, replacement=replacement)
            last_res = res
            if res.was_redacted:
                item["text"] = res.sanitized_text
                modified = True
                overall_action = SanitizerAction.REDACTED
            elif res.escalated:
                overall_action = SanitizerAction.ESCALATE_FOR_REVIEW

    if last_res:
        return new_response, SanitizeResult(
            action=overall_action,
            original_text=last_res.original_text,
            sanitized_text=last_res.sanitized_text if modified else last_res.original_text,
            is_modified=modified,
            injection_detected=overall_action != SanitizerAction.PASS,
            redacted_spans=last_res.redacted_spans,
            reason=last_res.reason,
            risk_score=last_res.risk_score,
        )

    return response_msg, SanitizeResult(
        action=SanitizerAction.PASS,
        original_text="",
        sanitized_text="",
        is_modified=False,
        injection_detected=False,
    )
