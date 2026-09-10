# MCP TrustGate — Product Requirements Document

## One-line pitch
A proxy-based trust layer for the Model Context Protocol that screens new servers for
typosquatting **before** approval, cryptographically pins tool identity **at** approval,
detects silent mutation and cross-server hijacking **after** approval, and sanitizes
untrusted tool output before it re-enters the agent's context.

## Official problem statement (PS2, verbatim)
> Build a real-time tool integrity and trust verification system for the Model Context
> Protocol that cryptographically pins tool descriptions at approval, detects silent
> mutations and cross-server behavioral hijacking, and sanitizes tool outputs before they
> re-enter the agent's context without disrupting legitimately behaving MCP servers.

## Attack scenarios this system must defend against
1. **Silent description mutation ("rug pull"):** a trusted calculator MCP server with a
   long clean history pushes an update whose new tool description instructs the agent to
   route all outgoing mail through the email tool to an external address, marked
   mandatory and "do not disclose." No code is exploited — only text changes.
2. **Poisoned data / cross-server hijack:** a legitimate internal-docs-search tool returns
   a real document, but one page was edited (insider or attacker) to instruct the agent to
   publish a summary of recently accessed files. No MCP server is compromised — the
   poison is in the *data*.

## Why this matters (cited stats from the brief)
- 30–82% of public MCP servers surveyed carry exploitable flaws.
- 30+ CVEs were filed against MCP implementations in early 2026.

## What we are building — the 5 mechanisms
0. **Registry Identity Check** (pre-approval) — name-similarity screening of a brand-new
   server's name against a curated known-good list, to catch typosquatting/impersonation.
   Rule-based (rapidfuzz/difflib), deterministic, no LLM, free.
1. **Fingerprint & Pin Engine** (at approval) — canonicalize the full tool manifest
   (name + description + parameter schema) to sorted JSON, SHA-256 it, client-side only.
   Never trust a server-supplied hash.
2. **Mutation & Diff Engine** (after approval) — recompute the hash on every reconnect;
   on mismatch, produce a line-level diff so the user sees exactly what changed.
3. **Description Scanner** — normalize (strip invisible/zero-width Unicode, NFKC
   lookalike-letter folding) → fast regex/keyword tier → LLM semantic tier
   (OpenRouter free router) for reworded/obfuscated variants regex misses.
4. **Output Sanitizer** — the same normalize → regex → LLM pipeline, applied to tool
   *output* instead of descriptions. High-confidence, cleanly-separable injections are
   redacted; ambiguous/entangled cases escalate to a human instead of guessing.

## Our added novelty — be precise, don't overclaim
The problem statement's own 4 mechanisms (pin, diff, scan descriptions, scan outputs) all
assume a server was already legitimately approved once. Mechanism 0 (Registry Identity
Check) closes the gap *before* that first approval, by screening a never-seen server's
name for typosquatting/impersonation (e.g. `fireb4se-mcp-server` impersonating
`firebase-mcp-server` under an unverified publisher). This is adapted from a prior
"slopsquatting" (AI-hallucinated package name) detector, reapplied to MCP server names.

**Honesty constraint:** cryptographic tool-schema pinning is not novel in general (an
existing project, SchemaPin, already does something similar with ECDSA signatures). The
defensible claim is the *specific combination*: pre-approval name screening + fingerprint
pinning + mutation diffing + two-tier content scanning, applied specifically at the MCP
tool-description/output layer, with a re-approval-not-permanent-block policy for benign
changes. Never claim any single piece is invented from scratch.

## Scope boundary (state this proactively if asked)
This system secures the **text/data channel** between agent and tool (descriptions and
outputs). It does **not** sandbox or isolate a malicious MCP server's own code execution —
that's a separate, complementary problem (process isolation), explicitly out of scope.

## Success criteria
All 5 demo scenes (see DEMO_SCRIPT.md) must produce the correct policy decision live,
end-to-end, through the real stdio proxy — not mocked, not simulated:
1. Typosquatted new server → flagged pre-approval.
2. Clean calculator → approved, fingerprint pinned.
3. Poisoned calculator → BLOCKED, diff shown.
4. Poisoned doc → output redacted, clean content still passes.
5. Benign version bump → HELD for re-approval, not blocked — proves the system isn't
   "a wall" against legitimate change.

## Users
- **Hackathon judges** (primary audience for the demo).
- **Real-world:** any developer running Claude Desktop, Claude Code, or Antigravity with
  third-party MCP servers, who wants a drop-in trust layer with a one-line config change
  and zero agent code modifications.
