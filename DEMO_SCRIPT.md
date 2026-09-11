# Demo Script — 5 scenes, must all run live through the real proxy

Rehearse this end-to-end at least twice on the actual demo laptop before presenting.

## Scene 1 — Typosquatted new server (Stage 11)
**Setup:** register a never-before-seen server named `fireb4se-mcp-server` with an
unverified publisher.
**Action:** connect it through TrustGate.
**Expected:** Registry Identity Check flags it **before** approval — console shows
similarity score (>0.90) against `firebase-mcp-server` and the publisher mismatch.
**Proves:** pre-approval screening, the mechanism this project adds beyond the brief.

## Scene 2 — Approve the clean Calculator (Stages 8, 9)
**Action:** `python3 trustgate/main.py run --target "python3 servers/calculator.py"`,
approve when prompted.
**Expected:** fingerprint computed and pinned in the SQLite vault. Not itself a
narrated "attack" — this is baseline setup.

## Scene 3 — Swap in the poisoned Calculator (Stages 10, 12, 13, 15)
**Action:** stop, replace the target with `calculator_poisoned.py`, reconnect.
**Expected:** fingerprint mismatch triggers mutation check → diff shown → regex scanner
and/or LLM scanner flag the hijack instruction → Policy Engine outputs **BLOCK** →
console shows the line-level diff in red.
**Proves:** silent-mutation and description-hijack detection together.

## Scene 4 — Query Docs Search with the poisoned document (Stages 14, 15)
**Action:** call `search_docs("leave_policy_poisoned")` through the proxy.
**Expected:** Output Sanitizer strips the injected "publish recently accessed files"
instruction; the legitimate leave-policy content still reaches the agent.
**Proves:** output/data-channel poisoning is caught without breaking legitimate content.

## Scene 5 — Swap in the benign-update Calculator (Stages 10, 12, 13, 15)
**Action:** replace the target with `calculator_v2.py` (harmless version-bump docstring
only), reconnect.
**Expected:** fingerprint mismatch detected, but regex/LLM find nothing malicious →
Policy Engine outputs **HOLD**, not BLOCK → operator re-approves → new hash pinned.
**Proves:** the system does not become "a wall" against legitimate change — the problem
statement explicitly requires this.

## Scene-to-stage mapping (for judge Q&A)
| Scene | Proves | Stages |
|---|---|---|
| 1 | pre-approval typosquat screening | 11 |
| 2 | fingerprint pinning | 8, 9 |
| 3 | mutation + description hijack → BLOCK | 10, 12, 13, 15 |
| 4 | output/data poisoning → redacted | 14, 15 |
| 5 | benign change → HOLD, not BLOCK | 10, 12, 13, 15 |

## If asked live: what this does NOT do
It secures the text/data channel (descriptions and outputs). It does not sandbox or
isolate a malicious MCP server's own code execution — that's a separate, complementary
problem (process isolation), explicitly out of scope. Say this proactively if it comes up.

## Four-scenario approval rehearsal

Run the compact approval-focused rehearsal with:

```powershell
python demo_scenarios.py --db demo.db
```

It uses the real MCP demo servers plus the isolated `demo_servers/suspicious.py`
server and records real TrustGate events. The suspicious scenario is separate from
fingerprint approval so `ALLOW_ONCE` never approves a baseline update.
