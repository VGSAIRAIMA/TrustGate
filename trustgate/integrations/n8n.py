"""Optional n8n webhook integration.

TrustGate does not depend on n8n. When N8N_WEBHOOK_URL is unset, this module
is inert. Only structured, non-secret audit metadata is sent to the webhook.
"""

import json
import os
from typing import Any
import urllib.error
import urllib.request


def _safe_detail(detail: str) -> dict[str, Any]:
    try:
        value = json.loads(detail)
    except (TypeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    allowed = (
        "request_id",
        "event_id",
        "tool",
        "tool_name",
        "severity",
        "llm_classification",
        "llm_probability",
        "fingerprint_status",
        "triggered_rules",
        "user_action",
        "status",
        "assessment",
    )
    return {key: value[key] for key in allowed if key in value}


def build_payload(
    server: str,
    event_type: str,
    risk: int,
    decision: str,
    detail: str,
    timestamp: str,
    event_id: int | str,
) -> dict[str, Any]:
    """Build the allowlisted webhook payload; never include raw event detail."""
    return {
        "source": "trustgate",
        "event_id": str(event_id),
        "timestamp": timestamp,
        "event_type": event_type,
        "server": server,
        "risk_score": risk,
        "decision": decision,
        "metadata": _safe_detail(detail),
    }


def emit_event(
    server: str,
    event_type: str,
    risk: int,
    decision: str,
    detail: str,
    timestamp: str,
    event_id: int | str,
    timeout: float = 2.0,
) -> bool:
    """Send one audit event to n8n when configured; failures never affect TrustGate."""
    url = os.environ.get("N8N_WEBHOOK_URL", "").strip()
    if not url:
        return False
    payload = build_payload(server, event_type, risk, decision, detail, timestamp, event_id)
    headers = {"Content-Type": "application/json", "User-Agent": "TrustGate-n8n/1.0"}
    token = os.environ.get("N8N_WEBHOOK_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False
