"""TrustGate storage module.

Implements the SQLite trust vault and audit event log using standard sqlite3:
- `tools` table: Approved tools and their cryptographically pinned SHA-256 fingerprints.
- `events` table: Audit log recording every inspection, score, decision, and diff.
"""

from datetime import datetime, timezone
import json
import sqlite3
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
        return cursor.lastrowid or 0
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
