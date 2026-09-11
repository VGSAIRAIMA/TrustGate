"""TrustGate storage module.

Implements the SQLite trust vault and audit event log using standard sqlite3:
- `tools` table: Approved tools and their cryptographically pinned SHA-256 fingerprints.
- `events` table: Audit log recording every inspection, score, decision, and diff.
"""

from datetime import datetime, timezone
import json
import sqlite3
import threading
from typing import Any

DEFAULT_DB_PATH = "trustgate.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tools (
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    manifest TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    PRIMARY KEY (server, tool)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    server TEXT NOT NULL,
    event_type TEXT NOT NULL,
    risk INTEGER NOT NULL,
    decision TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    request_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    risk INTEGER NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    old_hash TEXT NOT NULL,
    new_hash TEXT NOT NULL,
    fingerprint_change INTEGER NOT NULL,
    action TEXT
);
"""


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Return a configured SQLite connection with row factory enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize SQLite database tables if they do not exist."""
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def save_tool(
    server: str,
    tool: str,
    fingerprint: str,
    manifest: dict[str, Any] | str,
    approved_at: str | None = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """Pin an approved tool and its client-computed fingerprint in the trust vault."""
    init_db(db_path)
    if approved_at is None:
        approved_at = datetime.now(timezone.utc).isoformat()

    manifest_json = manifest if isinstance(manifest, str) else json.dumps(manifest, sort_keys=True)

    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO tools (server, tool, fingerprint, manifest, approved_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (server, tool, fingerprint, manifest_json, approved_at),
        )
        conn.commit()
    finally:
        conn.close()


def get_tool(server: str, tool: str, db_path: str = DEFAULT_DB_PATH) -> dict[str, Any] | None:
    """Retrieve an approved tool record from the vault by server and tool name."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT server, tool, fingerprint, manifest, approved_at FROM tools WHERE server = ? AND tool = ?",
            (server, tool),
        )
        row = cursor.fetchone()
        if not row:
            return None

        manifest_data = row["manifest"]
        try:
            manifest_dict = json.loads(manifest_data)
        except Exception:
            manifest_dict = manifest_data

        return {
            "server": row["server"],
            "tool": row["tool"],
            "fingerprint": row["fingerprint"],
            "manifest": manifest_dict,
            "approved_at": row["approved_at"],
        }
    finally:
        conn.close()


def list_tools(server: str | None = None, db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """List all approved tools in the vault, optionally filtered by server."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        if server:
            cursor = conn.execute(
                "SELECT server, tool, fingerprint, manifest, approved_at FROM tools WHERE server = ? ORDER BY tool",
                (server,),
            )
        else:
            cursor = conn.execute(
                "SELECT server, tool, fingerprint, manifest, approved_at FROM tools ORDER BY server, tool"
            )

        results = []
        for row in cursor.fetchall():
            try:
                manifest_dict = json.loads(row["manifest"])
            except Exception:
                manifest_dict = row["manifest"]

            results.append({
                "server": row["server"],
                "tool": row["tool"],
                "fingerprint": row["fingerprint"],
                "manifest": manifest_dict,
                "approved_at": row["approved_at"],
            })
        return results
    finally:
        conn.close()


def delete_tool(server: str, tool: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Delete a pinned tool from the vault. Returns True if a row was deleted."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("DELETE FROM tools WHERE server = ? AND tool = ?", (server, tool))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def log_event(
    server: str,
    event_type: str,
    risk: int,
    decision: str,
    detail: str,
    timestamp: str | None = None,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Append a security event to the audit log. Returns the generated event ID."""
    init_db(db_path)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    conn = get_connection(db_path)
    try:
        cursor = conn.execute(
            """
            INSERT INTO events (timestamp, server, event_type, risk, decision, detail)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (timestamp, server, event_type, risk, decision, detail),
        )
        conn.commit()
        event_id = cursor.lastrowid or 0
        try:
            from trustgate.integrations.n8n import emit_event

            threading.Thread(
                target=emit_event,
                args=(server, event_type, risk, decision, detail, timestamp, event_id),
                daemon=True,
            ).start()
        except Exception:
            # Optional integrations must never disrupt local audit persistence.
            pass
        return event_id
    finally:
        conn.close()


def get_events(
    server: str | None = None,
    limit: int = 100,
    db_path: str = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    """Retrieve audit events in descending order of creation."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        if server:
            cursor = conn.execute(
                """
                SELECT id, timestamp, server, event_type, risk, decision, detail
                FROM events WHERE server = ? ORDER BY id DESC LIMIT ?
                """,
                (server, limit),
            )
        else:
            cursor = conn.execute(
                """
                SELECT id, timestamp, server, event_type, risk, decision, detail
                FROM events ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            )

        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def save_approval(approval: dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> None:
    """Persist a pending approval request without storing private payload content."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO approvals
            (request_id, created_at, resolved_at, server, tool, risk, severity, reason,
             evidence, old_hash, new_hash, fingerprint_change, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval["request_id"], approval["timestamp"], approval.get("resolved_at"),
                approval["server"], approval["tool"], approval["risk_score"],
                approval["severity"], approval["reason"], json.dumps(approval.get("evidence", [])),
                approval.get("old_hash", ""), approval.get("new_hash", ""),
                int(bool(approval.get("fingerprint_change"))), approval.get("action"),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_approval(request_id: str, db_path: str = DEFAULT_DB_PATH) -> dict[str, Any] | None:
    """Return one pending or resolved approval request."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM approvals WHERE request_id = ?", (request_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            result["evidence"] = json.loads(result["evidence"])
        except (TypeError, json.JSONDecodeError):
            result["evidence"] = []
        result["fingerprint_change"] = bool(result["fingerprint_change"])
        result["risk_score"] = result["risk"]
        result["timestamp"] = result["created_at"]
        return result
    finally:
        conn.close()


def list_approvals(db_path: str = DEFAULT_DB_PATH, pending_only: bool = True) -> list[dict[str, Any]]:
    """List approval requests, newest first."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM approvals"
        params: tuple[Any, ...] = ()
        if pending_only:
            query += " WHERE action IS NULL"
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            try:
                item["evidence"] = json.loads(item["evidence"])
            except (TypeError, json.JSONDecodeError):
                item["evidence"] = []
            item["fingerprint_change"] = bool(item["fingerprint_change"])
            item["risk_score"] = item["risk"]
            item["timestamp"] = item["created_at"]
            results.append(item)
        return results
    finally:
        conn.close()


def resolve_approval(request_id: str, action: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Resolve a pending approval for a gateway process polling the shared DB."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.execute(
            "UPDATE approvals SET action = ?, resolved_at = ? WHERE request_id = ? AND action IS NULL",
            (action, datetime.now(timezone.utc).isoformat(), request_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()
