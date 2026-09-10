# Architecture

## System type
A **local CLI stdio proxy and MCP-compatible gateway**. This is explicitly NOT a
client-server web application.
No backend service, database server, or HTTP layer is required for the core system.

```
Agent (Claude Desktop / Claude Code / Antigravity)
        |  stdio (stdin/stdout pipes)
        v
  TrustGate CLI  (launches the real server as a hidden subprocess,
                   inspects every message in both directions)
        |  stdio
        v
  Real MCP Server  (e.g. calculator.py, docs_search.py — unmodified)
```

TrustGate is invisible to both sides: the agent believes it's talking to the real server,
the real server believes it's talking to the agent.

The existing `run` command provides the transparent raw JSON-RPC proxy. The `gateway`
command provides an MCP SDK server endpoint to the agent and an MCP SDK client session
to one configured downstream server. Both modes reuse the same inspection engine.

## Why no backend/web server for the core
MCP servers of this kind communicate over stdio, not HTTP. There is no request/response
web cycle happening anywhere in this pipeline to intercept — using FastAPI/REST here
would mean solving a problem that doesn't exist in this project.

## Inspection pipeline

### Inbound: tool manifest (`tools/list` response, i.e. a description arrives/changes)
```
raw bytes
  -> parser.parse_message()               # classify message kind
  -> normalizer.normalize_text()          # on every description field
  -> [new server only] registry.registry_check()
  -> fingerprint.create_fingerprint()      -> compare to SQLite vault
  -> [changed] mutation.check_mutation()   -> line-level diff
  -> patterns.regex_scan(description)
  -> llm_scanner.llm_scan(description)
  -> policy.decide(...)
  -> console.show_event(...)

  ALLOW    -> forward manifest to agent unchanged
  HOLD     -> forward, log, require explicit re-approval before related tool CALLS run
  BLOCK    -> withhold that tool from the agent's tool list, log why
```

### Outbound: tool call result (`tools/call` response, i.e. data comes back)
```
raw bytes
  -> parser.parse_message()
  -> normalizer.normalize_text()
  -> output_sanitizer.sanitize_mcp_response()  # sanitizes each text item
  -> policy.decide(is_output_injection=...)    # records deterministic risk
  -> console.show_sanitization_event(...)      # only when redacted/escalated

  PASS               -> forward unchanged
  REDACTED           -> forward the cleaned text only
  ESCALATE_FOR_REVIEW -> hold, show operator, wait for approve/deny keypress
```

## Storage — SQLite (`trustgate.db`, single local file)
```
tools(server, tool, fingerprint, manifest, approved_at)   PRIMARY KEY (server, tool)
events(id, timestamp, server, event_type, risk, decision, detail)   -- audit log
```
`tools` is the trust vault: one row per approved tool and its pinned fingerprint.
`events` is what you show a judge who asks "prove this actually caught something" —
every check that ever ran, its risk score, its decision, and why, in order.

## Module map
See PROJECT_STRUCTURE.md for the exact folder tree. In short:
- `trustgate/proxy/` — core.py (stdio bridge), parser.py (message classification)
- `trustgate/security/` — normalizer.py, patterns.py (regex), llm_scanner.py (OpenRouter)
- `trustgate/mechanisms/` — fingerprint.py, mutation.py, registry.py, output_sanitizer.py
- `trustgate/storage/` — database.py (SQLite vault + event log)
- `trustgate/policy/` — engine.py (deterministic weighted-scoring decision function)
- `trustgate/console/` — dashboard.py (rich terminal panels)
- `trustgate/proxy/adapter.py` — configurable downstream MCP command adapter
- `trustgate/proxy/gateway.py` — MCP server/client gateway mode
- `servers/` — the 3 demo MCP servers + poisoned/benign-update variants

## Optional stretch goal: read-only browser dashboard
A **separate** process, `trustgate/dashboard/server.py` — a small FastAPI app using
Server-Sent Events that only `SELECT`s from `trustgate.db` and streams new event rows to
a browser page for demo polish. It:
- never writes to the database,
- never sits in the stdio path,
- must not replace or interfere with the core proxy or the terminal console.

Build this **only** if the core pipeline and all 5 demo scenes already work end-to-end in
the terminal, and time remains. If built, stop claiming "no browser dependency" as an
absolute in the pitch — say it's true of the MVP core, not the optional viewer.

## Policy engine decision flow (deterministic, no LLM decides ALLOW/HOLD/BLOCK)
```
risk = 0
+40 if registry_flagged
+20 if fingerprint_changed
+40 if regex_flagged
+30 if llm_confidence > 0.8
+40 if is_output_injection

risk >= 60  -> BLOCK
risk >= 20  -> HOLD
else        -> ALLOW
```
Weights are self-defined and explicitly tunable — not a claimed industry standard.
