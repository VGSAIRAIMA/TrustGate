"""Separate read-only TrustGate Web UI and approval API."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from trustgate.storage.database import DEFAULT_DB_PATH, get_events, list_approvals, list_tools, resolve_approval


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TrustGate Security Gateway</title>
<style>
:root{--bg:#0b1118;--panel:#111c27;--panel2:#162431;--line:#263746;--text:#e8eef2;--muted:#8ea2b3;--green:#49d49a;--yellow:#f2c66d;--red:#f17676;--cyan:#6cc7df}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#0b1118,#0d1821 55%,#101d28);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}main{width:min(1420px,calc(100% - 36px));margin:28px auto 52px}.top{display:flex;align-items:end;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:20px}.eyebrow{color:var(--cyan);font:700 11px Consolas,monospace;letter-spacing:.18em}.brand{font-size:31px;font-weight:700;letter-spacing:.04em}.sub{color:var(--muted);margin-top:4px}.status{display:flex;gap:9px;align-items:center;color:var(--green);font-weight:700}.dot{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 14px var(--green)}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:18px 0}.metric,.card{border:1px solid var(--line);background:rgba(17,28,39,.9);border-radius:6px}.metric{padding:15px}.metric b{font-size:25px;display:block}.metric span{color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:1.15fr .85fr;gap:14px}.card{padding:17px;margin-bottom:14px}.card h2{font-size:15px;margin:0 0 13px;letter-spacing:.04em}.table{width:100%;border-collapse:collapse}.table th{color:var(--muted);font-size:11px;text-align:left;text-transform:uppercase;letter-spacing:.08em}.table td,.table th{padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}.pill{font-weight:700;font-size:11px;letter-spacing:.06em}.allow{color:var(--green)}.hold{color:var(--yellow)}.block{color:var(--red)}.muted{color:var(--muted)}.approval{border-left:3px solid var(--yellow);padding:13px;background:#18232b;margin:10px 0}.approval strong{display:block;margin-bottom:4px}.meta{color:var(--muted);font-size:12px}.actions{display:flex;gap:7px;margin-top:10px;flex-wrap:wrap}button{border:1px solid var(--line);background:#1d303e;color:var(--text);padding:8px 11px;border-radius:4px;font-weight:700;cursor:pointer}button:hover{border-color:var(--cyan)}button.danger{border-color:#7d3d46;color:#ffaaaa}button.good{border-color:#32795f;color:#9bf0c9}.hash{font:11px Consolas,monospace;color:var(--cyan);word-break:break-all}.detail{white-space:pre-wrap;color:var(--muted);font-size:12px;max-height:190px;overflow:auto}.empty{color:var(--muted);padding:10px 0}@media(max-width:900px){.metrics{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.top{align-items:start;gap:20px;flex-direction:column}}
</style></head><body><main><header class="top"><div><div class="eyebrow">MCP RUNTIME SECURITY</div><div class="brand">TRUSTGATE</div><div class="sub">Deterministic policy, human approval, auditable enforcement</div></div><div class="status"><i class="dot"></i> Gateway Running</div></header><section class="metrics" id="metrics"></section><div class="grid"><div><section class="card"><h2>Pending Approvals</h2><div id="approvals"></div></section><section class="card"><h2>Recent Threats</h2><div id="threats"></div></section><section class="card"><h2>Audit History</h2><div id="events"></div></section></div><div><section class="card"><h2>Protected Servers</h2><div id="servers"></div></section><section class="card"><h2>Tool Inventory</h2><div id="tools"></div></section><section class="card"><h2>Fingerprint Changes</h2><div id="fingerprints"></div></section></div></div></main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pct=n=>`${Math.round(Number(n||0)*100)}%`; const action=a=>`<span class="pill ${String(a).toLowerCase()}">${esc(a)}</span>`;
function detail(e){try{return JSON.parse(e.detail||'{}')}catch{return {reason:e.detail}}}
function render(d){const c=d.counts;document.getElementById('metrics').innerHTML=[['Protected Servers',c.servers],['Tools Monitored',c.tools],['Threats Detected',c.threats],['Blocked Requests',c.blocked],['Pending Approvals',c.pending]].map(x=>`<div class="metric"><b>${x[1]}</b><span>${x[0]}</span></div>`).join('');
const ap=d.approvals;document.getElementById('approvals').innerHTML=ap.length?ap.map(a=>`<div class="approval"><strong>SECURITY WARNING</strong><div><b>Tool:</b> ${esc(a.tool)} <span class="meta">on ${esc(a.server)}</span></div><div><b>Risk:</b> ${a.risk_score}/100 &nbsp; <b>Severity:</b> ${esc(a.severity)}</div><div><b>Threat:</b> ${esc(a.reason)}</div><div><b>Evidence:</b> ${esc((a.evidence||[]).join(', ')||'none')}</div>${a.fingerprint_change?`<div class="hash"><b>Previous fingerprint:</b> ${esc(a.old_hash)}<br><b>Current fingerprint:</b> ${esc(a.new_hash)}</div><div class="actions"><button class="danger" onclick="resolve('${a.request_id}','REJECT_UPDATE')">REJECT UPDATE</button><button class="good" onclick="resolve('${a.request_id}','APPROVE_UPDATE')">APPROVE UPDATE</button></div>`:`<div class="actions"><button class="danger" onclick="resolve('${a.request_id}','BLOCK')">BLOCK</button><button class="good" onclick="resolve('${a.request_id}','ALLOW_ONCE')">ALLOW ONCE</button></div>`}</div>`).join(''):'<div class="empty">No pending approvals.</div>';
const threatRows=d.threats.map(e=>{const x=detail(e);const a=x.assessment||{};const l=a.llm_result||{};return `<tr><td>${esc(x.tool||x.tool_name||'unknown')}</td><td>${e.risk}/100</td><td>${esc(a.severity||x.severity||'n/a')}</td><td>${action(e.decision)}</td><td>${esc(l.status||'SKIPPED')} ${l.malicious_probability!=null?`· ${pct(l.malicious_probability)}`:''}</td></tr>`}).join('');document.getElementById('threats').innerHTML=threatRows?`<table class="table"><tr><th>Tool</th><th>Risk</th><th>Severity</th><th>Action</th><th>LLM</th></tr>${threatRows}</table>`:'<div class="empty">No threats recorded.</div>';
document.getElementById('servers').innerHTML=d.servers.length?d.servers.map(s=>`<div class="approval"><strong>${esc(s.server)}</strong><div class="meta">${esc(s.status)} · ${s.tools} tool(s)</div></div>`).join(''):'<div class="empty">No MCP servers recorded.</div>';
document.getElementById('tools').innerHTML=d.tools.length?`<table class="table"><tr><th>Tool</th><th>Server</th><th>Fingerprint</th></tr>${d.tools.map(t=>`<tr><td>${esc(t.tool)}</td><td>${esc(t.server)}</td><td class="hash">${esc(t.fingerprint)}</td></tr>`).join('')}</table>`:'<div class="empty">No pinned tools.</div>';
const fp=d.fingerprint_changes.map(e=>{const x=detail(e);return `<div class="approval"><strong>${esc(x.tool||x.tool_name||'tool')} · ${esc(e.event_type)}</strong><div class="hash">OLD ${esc(x.old_hash||'not recorded')}<br>NEW ${esc(x.new_hash||'not recorded')}</div><div class="detail">${esc(x.reason||x.policy_reasons||'Fingerprint status changed')}</div></div>`}).join('');document.getElementById('fingerprints').innerHTML=fp||'<div class="empty">No fingerprint changes recorded.</div>';
document.getElementById('events').innerHTML=d.events.length?`<table class="table"><tr><th>Time</th><th>Event</th><th>Server</th><th>Risk</th><th>Decision</th></tr>${d.events.map(e=>`<tr><td class="meta">${esc(e.timestamp)}</td><td>${esc(e.event_type)}</td><td>${esc(e.server)}</td><td>${e.risk}</td><td>${action(e.decision)}</td></tr>`).join('')}</table>`:'<div class="empty">No audit events recorded.</div>'}
async function load(){const r=await fetch('/api/state');render(await r.json())} async function resolve(id,actionName){await fetch('/api/approvals/'+encodeURIComponent(id),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:actionName})});load()}load();setInterval(load,1500);
</script></body></html>'''


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
        "counts": {"servers": len(servers), "tools": len(tools), "threats": len(threats), "blocked": len(blocked), "pending": len(approvals)},
        "servers": list(servers.values()), "tools": tools, "approvals": approvals,
        "threats": threats[:20], "fingerprint_changes": changes[:20], "events": events[:50],
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
            self._send(200, HTML.encode())

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
