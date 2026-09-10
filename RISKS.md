# Risks — 24-hour hackathon build

## Technical risks
- **Stage 4 (asyncio stdio bridging) is the single highest-risk piece.** Bugs here are
  silent and confusing (messages that just never arrive) rather than loud crashes.
  *Mitigation:* budget a full dedicated hour for it, alone, before writing any scanner.
  Verify with a manually-typed raw MCP line before building anything on top.
- **MCP Python SDK / FastMCP version drift.** The SDK is young; method signatures can
  shift between versions. *Mitigation:* pin the version in TECH_STACK.md once you've
  confirmed it works, and don't `pip install -U` mid-hackathon.
- **LLM scanner latency/availability during a live demo.** A slow or failed API call
  mid-demo is visible to judges. *Mitigation:* add a timeout with a safe fallback (treat
  as inconclusive → let regex + fingerprint signals still drive the policy decision,
  rather than hanging or crashing the whole pipeline).
- **API rate limits or a dry trial credit** on demo day. *Mitigation:* set a Console
  billing spend cap in advance so a bug can't silently drain the key, and test with the
  real key well before presenting, not for the first time on stage.

## Dependency risks
- Stages 6–14 (parser → normalizer → fingerprint → mutation → registry → regex → LLM →
  output sanitizer) can be built in parallel by different people once Stage 4
  (passthrough) is solid, since they're mostly pure functions. Stage 15 (policy engine)
  and Stage 16 (console) both depend on all of them being done first — don't start those
  early expecting to "fill in" the inputs later.
- The demo itself depends on the agent config wiring (Stage 5) working with whatever
  agent app you actually demo from (Claude Desktop / Claude Code / Antigravity) —
  confirm this on the *actual* demo laptop, not just a dev machine, since restart/config
  reload behavior can differ.

## Scope risks
- Temptation to build the optional dashboard (Stage "stretch") before the terminal
  demo is airtight. *Mitigation:* AGENTS.md and BUILD_PLAN.md both gate this explicitly
  behind all 5 core scenes working first.
- Temptation to overclaim novelty under time pressure while writing pitch slides.
  *Mitigation:* reuse the exact honesty framing already written in PRD.md verbatim.

## Resourcing risks
- If solo: the fingerprint/mutation/registry/regex stages (8, 10, 11, 12) are small and
  fast — don't over-invest time there at the expense of Stage 4 or the demo rehearsal
  (Stage 17), which are the actual bottlenecks.
- Reserve the last 60–90 minutes purely for rehearsing DEMO_SCRIPT.md end to end,
  twice, on the presenting laptop, with no code changes in between.
