"""Read-only live terminal dashboard for TrustGate's SQLite audit database."""

import argparse
import json
from pathlib import Path
import sqlite3
import time
from typing import Any

from rich import box
from rich.console import Group
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from trustgate.storage.database import DEFAULT_DB_PATH


SIGNAL_KEYS = (
    "registry_flagged",
    "fingerprint_changed",
    "regex_flagged",
    "llm_flagged",
    "llm_confidence",
    "llm_classification",
    "llm_uncertainty",
    "llm_severity",
    "llm_evidence",
    "is_output_injection",
)


def fetch_snapshot(db_path: str, limit: int = 10) -> dict[str, Any]:
    """Read one consistent dashboard snapshot from SQLite."""
    empty_snapshot = {"counts": {"servers": 0, "tools": 0, "threats": 0, "events": 0}, "events": []}
    if not Path(db_path).exists():
        return empty_snapshot

    db_uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(db_uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        counts = {
            "servers": conn.execute("SELECT COUNT(DISTINCT server) FROM events").fetchone()[0],
            "tools": conn.execute("SELECT COUNT(*) FROM tools").fetchone()[0],
            "threats": conn.execute(
                "SELECT COUNT(*) FROM events WHERE decision IN ('BLOCK', 'HOLD')"
            ).fetchone()[0],
            "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        }
        rows = conn.execute(
            """
            SELECT id, timestamp, server, event_type, risk, decision, detail
            FROM events ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return {"counts": counts, "events": [dict(row) for row in rows]}
    finally:
        conn.close()


def parse_detail(event: dict[str, Any]) -> dict[str, Any]:
    """Decode structured metadata while tolerating older plain-text events."""
    try:
        detail = json.loads(event["detail"])
    except (TypeError, json.JSONDecodeError):
        return {"reason": event["detail"], "signals": {}}
    return detail if isinstance(detail, dict) else {"reason": str(detail), "signals": {}}


def action_style(decision: str) -> str:
    return {"ALLOW": "green", "HOLD": "yellow", "BLOCK": "red", "REDACTED": "yellow"}.get(
        decision, "white"
    )


def build_header(snapshot: dict[str, Any]) -> Panel:
    recent = snapshot["events"]
    alert = any(row["decision"] in {"BLOCK", "HOLD"} for row in recent)
    status = "ALERT" if alert else "PROTECTED"
    color = "red" if alert else "green"
    title = Text("TRUSTGATE — MCP Runtime Security Gateway", style="bold white")
    body = Text.assemble(("STATUS  ", "bold"), (status, f"bold {color}"))
    return Panel(body, title=title, border_style=color)


def build_counters(snapshot: dict[str, Any]) -> Table:
    counts = snapshot["counts"]
    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("SERVERS SEEN", justify="center")
    table.add_column("TOOLS TRACKED", justify="center")
    table.add_column("THREATS (BLOCK + HOLD)", justify="center")
    table.add_column("TOTAL EVENTS", justify="center")
    table.add_row(*(str(counts[key]) for key in ("servers", "tools", "threats", "events")))
    return table


def build_pipeline() -> Panel:
    pipeline = "Registry  ->  Fingerprint  ->  Scanner  ->  Policy  ->  ALLOW / HOLD / BLOCK"
    return Panel(pipeline, title="Inspection Pipeline", border_style="cyan")


def build_event_feed(snapshot: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Timestamp", no_wrap=True)
    table.add_column("Server")
    table.add_column("Event")
    table.add_column("Risk", justify="right")
    table.add_column("Decision")
    rows = snapshot["events"]
    if not rows:
        table.add_row("", "", "no events yet", "0", "")
    else:
        for row in rows:
            style = action_style(row["decision"])
            table.add_row(
                row["timestamp"],
                row["server"],
                row["event_type"],
                str(row["risk"]),
                Text(row["decision"], style=f"bold {style}"),
            )
    return Panel(table, title="Live Event Feed (latest 10)", border_style="blue")


def build_detail(snapshot: dict[str, Any]) -> Panel:
    event = next(
        (row for row in snapshot["events"] if row["decision"] in {"BLOCK", "REDACTED"}),
        None,
    )
    if event is None:
        return Panel("no BLOCK or REDACT event yet", title="Security Detail", border_style="dim")

    detail = parse_detail(event)
    signals = detail.get("signals", {})
    llm_result = detail.get("assessment", {}).get("llm_result", {})
    lines: list[Any] = [
        Text(f"{event['decision']} | {event['server']} | risk {event['risk']}", style=f"bold {action_style(event['decision'])}"),
        Text("Signal breakdown:", style="bold underline"),
    ]
    for key in SIGNAL_KEYS:
        if key in signals:
            value = signals[key]
            if key == "llm_confidence" and isinstance(value, (float, int)):
                value = f"{value:.0%}"
            lines.append(Text(f"  {key}: {value}"))
        else:
            lines.append(Text(f"  {key}: not provided by this event", style="dim"))

    if llm_result:
        lines.extend((Text("LLM analysis:", style="bold underline"), Text(
            f"  classification={llm_result.get('classification', 'unavailable').upper()} "
            f"probability={llm_result.get('malicious_probability', 0.0):.0%} "
            f"uncertainty={llm_result.get('uncertainty', 1.0):.0%} "
            f"severity={llm_result.get('severity', 'low').upper()}"
        )))
        if llm_result.get("reason"):
            lines.append(Text(f"  reason: {llm_result['reason']}"))
        lines.extend(Text(f"  evidence: {item}", style="yellow") for item in llm_result.get("evidence", []))

    diff = detail.get("diff", "")
    redacted = detail.get("redacted_spans", [])
    reason = detail.get("reason", "")
    if reason:
        lines.extend((Text("Reason/detail:", style="bold underline"), Text(reason)))
    if diff:
        lines.extend((Text("Manifest diff:", style="bold underline"), Text(diff, style="red")))
    if redacted:
        lines.append(Text("Redacted spans:", style="bold underline"))
        lines.extend(Text(f"  {span}", style="yellow") for span in redacted)
    return Panel(Group(*lines), title="Security Detail", border_style=action_style(event["decision"]))


def build_scene_view(
    snapshot: dict[str, Any],
    scene_title: str,
    event_type: str | None = None,
) -> Panel:
    """Render the latest real event as a compact single-terminal scene dashboard."""
    event = next(
        (row for row in snapshot["events"] if event_type is None or row["event_type"] == event_type),
        None,
    )
    if event is None:
        return Panel("no events yet", title="TRUSTGATE SECURITY PROXY", border_style="dim")

    detail = parse_detail(event)
    signals = detail.get("signals", {})
    llm_result = detail.get("assessment", {}).get("llm_result", {})
    decision = event["decision"]
    decision_label = {"BLOCK": "WITHHOLD", "HOLD": "REVIEW", "ALLOW": "ALLOW"}.get(decision, decision)
    access = {"BLOCK": "DENIED", "HOLD": "PENDING REVIEW", "ALLOW": "GRANTED", "REDACTED": "GRANTED (SANITIZED)"}.get(
        decision, "REVIEW"
    )
    color = action_style(decision)

    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Server", event["server"])
    if detail.get("tool_name"):
        table.add_row("Tool", detail["tool_name"])
    table.add_row("Risk score", str(event["risk"]))
    table.add_row("Decision", Text(f"{decision_label} ({decision})", style=f"bold {color}"))
    table.add_row("Agent access", Text(access, style=f"bold {color}"))
    table.add_row("Audit", "RECORDED")

    findings: list[str] = []
    finding_labels = {
        "registry_flagged": "IDENTITY MISMATCH",
        "fingerprint_changed": "SILENT TOOL MUTATION",
        "regex_flagged": "INJECTION SIGNATURE DETECTED",
        "llm_flagged": "SEMANTIC THREAT DETECTED",
        "is_output_injection": "OUTPUT INJECTION DETECTED",
    }
    for key, label in finding_labels.items():
        if signals.get(key):
            findings.append(f"[!] {label}")
    if not findings:
        findings.append("[+] POLICY SIGNALS CLEAN")

    signal_table = Table.grid(padding=(0, 1))
    signal_table.add_column(style="bold")
    signal_table.add_column()
    if event["event_type"] == "OUTPUT_SANITIZATION":
        signal_labels = {"is_output_injection": "Output Sanitizer"}
    else:
        signal_labels = {
            "registry_flagged": "Registry Check",
            "fingerprint_changed": "Fingerprint Vault",
            "regex_flagged": "Regex Patterns",
            "llm_flagged": "LLM Semantic",
            "is_output_injection": "Output Sanitizer",
        }
    for key, label in signal_labels.items():
        if key == "registry_flagged":
            value = "FLAGGED (typosquat/mismatch)" if signals.get(key) else "CLEAN"
        elif key == "fingerprint_changed":
            value = "MUTATED (diff detected)" if signals.get(key) else "MATCH (pinned hash)"
        elif key == "regex_flagged":
            value = "TRIPPED (injection signature)" if signals.get(key) else "CLEAN"
        elif key == "llm_flagged":
            confidence = signals.get("llm_confidence", 0.0)
            if signals.get(key):
                value = f"MALICIOUS ({confidence:.0%} confidence)"
            elif signals.get("llm_status") == "not_run":
                value = "NOT RUN"
            elif signals.get("llm_status") == "inconclusive":
                value = "INCONCLUSIVE"
            else:
                value = "CLEAN"
        else:
            value = "INJECTION DETECTED" if signals.get(key) else "CLEAN"
        signal_table.add_row(f"{label}:", Text(value, style="red" if signals.get(key) else "green"))

    llm_confidence = signals.get("llm_confidence")
    llm_reason = signals.get("llm_reason")
    if llm_confidence is not None:
        signal_table.add_row("LLM Confidence:", Text(f"{llm_confidence:.0%}", style="cyan"))
    if llm_reason:
        signal_table.add_row("LLM Explanation:", Text(llm_reason))

    blocks: list[Any] = [
        Text("Continuous Trust Verification for MCP Agents", style="dim"),
        Text(scene_title, style="bold cyan"),
        Text(""),
        table,
        Text(""),
        Text("Inspection Signals:", style="bold underline"),
        signal_table,
        Text(""),
        Text("\n".join(findings), style=color),
    ]
    reason = detail.get("reason") or "; ".join(detail.get("reasons", []))
    if reason:
        blocks.extend((Text(""), Text(f"Reason: {reason}")))
    llm_reason = signals.get("llm_reason", "")
    if llm_reason and signals.get("llm_status") == "inconclusive":
        blocks.extend((Text(""), Text(f"LLM status: {llm_reason}", style="yellow")))
    if llm_result:
        blocks.extend((Text(""), Text("LLM ANALYSIS", style="bold underline")))
        blocks.append(Text(
            f"Classification: {llm_result.get('classification', 'unavailable').upper()} | "
            f"Probability: {llm_result.get('malicious_probability', 0.0):.0%} | "
            f"Uncertainty: {llm_result.get('uncertainty', 1.0):.0%} | "
            f"Severity: {llm_result.get('severity', 'low').upper()}"
        ))
        if llm_result.get("reason"):
            blocks.append(Text(f"Reason: {llm_result['reason']}"))
        blocks.extend(Text(f"Evidence: {item}", style="yellow") for item in llm_result.get("evidence", []))
    diff = detail.get("diff", "")
    if diff:
        blocks.extend((Text(""), Text("Manifest diff:", style="bold underline"), Text(diff, style="red")))
    redacted = detail.get("redacted_spans", [])
    if redacted:
        blocks.extend((Text(""), Text("Redacted output:", style="bold underline")))
        blocks.extend(Text(f"  {span}", style="yellow") for span in redacted)

    return Panel(Group(*blocks), title="TRUSTGATE SECURITY PROXY", border_style=color, padding=(1, 2))


def build_layout(snapshot: dict[str, Any]) -> Layout:
    layout = Layout(name="root")
    layout.split_column(
        Layout(build_header(snapshot), name="header", size=3),
        Layout(build_counters(snapshot), name="counters", size=4),
        Layout(build_pipeline(), name="pipeline", size=3),
        Layout(build_event_feed(snapshot), name="feed", ratio=2),
        Layout(build_detail(snapshot), name="detail", ratio=3),
    )
    return layout


def run_dashboard(db_path: str, refresh: float = 1.0) -> None:
    """Poll the audit database until interrupted."""
    with Live(build_layout(fetch_snapshot(db_path)), refresh_per_second=4, screen=True) as live:
        try:
            while True:
                live.update(build_layout(fetch_snapshot(db_path)))
                time.sleep(refresh)
        except KeyboardInterrupt:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only TrustGate SQLite security dashboard.")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="SQLite database path.")
    parser.add_argument("--refresh", type=float, default=1.0, help="Polling interval in seconds.")
    args = parser.parse_args()
    run_dashboard(args.db, max(0.2, args.refresh))


if __name__ == "__main__":
    main()
