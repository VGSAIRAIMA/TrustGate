



"""Separate read-only TrustGate Web UI and approval API."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from trustgate.storage.database import DEFAULT_DB_PATH, get_events, list_approvals, list_tools, resolve_approval

_HTML_FILE = Path(__file__).resolve().parent.parent / "web_dashboard.html"


def _load_html() -> str:
    if _HTML_FILE.exists():
        return _HTML_FILE.read_text(encoding="utf-8")
    return "<!doctype html><html><body>TRUSTGATE: Pending Approvals Recent Threats Fingerprint Changes Audit History</body></html>"


HTML = _load_html()


def get_html_content() -> bytes:
    if _HTML_FILE.exists():
        return _HTML_FILE.read_bytes()
    return HTML.encode("utf-8")


def _event_detail(event: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(event.get("detail", "{}"))
        return value if isinstance(value, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def snapshot(db_path: str) -> dict[str, Any]:
    events = get_events(db_path=db_path, limit=100)
    tools = list_tools(db_path=db_path)
    approvals = list_approvals(db_path=db_path, pending_only=True)
    threats = [event for event in events if event["decision"] in {"BLOCK", "HOLD", "REDACTED"}]
    blocked = [event for event in events if event["decision"] == "BLOCK"]
    servers: dict[str, dict[str, Any]] = {}
    for tool in tools:
        servers.setdefault(tool["server"], {"server": tool["server"], "tools": 0, "status": "PROTECTED"})["tools"] += 1
    for event in events:
        servers.setdefault(event["server"], {"server": event["server"], "tools": 0, "status": "CONNECTED"})
        if event["event_type"] == "MCP_DISCONNECTION":
            servers[event["server"]]["status"] = "DISCONNECTED"
    changes = [event for event in events if event["event_type"] in {"FINGERPRINT_CHANGE", "FINGERPRINT_APPROVAL", "FINGERPRINT_REJECTION"}]
    return {
        "counts": {
            "servers": len(servers),
            "tools": len(tools),
            "threats": len(threats),
            "blocked": len(blocked),
            "pending": len(approvals),
            "events": len(events),
        },
        "servers": list(servers.values()),
        "tools": tools,
        "approvals": approvals,
        "threats": threats[:20],
        "fingerprint_changes": changes[:20],
        "events": events[:50],
    }


class DashboardHandler(BaseHTTPRequestHandler):
    db_path = DEFAULT_DB_PATH

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/api/state":
            self._send(200, json.dumps(snapshot(self.db_path)).encode(), "application/json")
        else:
            self._send(200, get_html_content())

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/approvals/"):
            self._send(404, b"not found", "text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
            action = str(data.get("action", "")).upper()
            valid = {"BLOCK", "ALLOW_ONCE", "APPROVE_UPDATE", "REJECT_UPDATE"}
            if action not in valid:
                raise ValueError("invalid action")
            ok = resolve_approval(path.rsplit("/", 1)[-1], action, db_path=self.db_path)
            self._send(200 if ok else 404, json.dumps({"resolved": ok}).encode(), "application/json")
        except (ValueError, json.JSONDecodeError):
            self._send(400, b"invalid approval", "text/plain")

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def run_web_dashboard(db_path: str = DEFAULT_DB_PATH, host: str = "127.0.0.1", port: int = 8765) -> None:
    DashboardHandler.db_path = db_path
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"TrustGate Web UI: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
