# Agent Instructions — read this before writing any code

You are building **MCP TrustGate**, described fully in PRD.md, ARCHITECTURE.md,
TECH_STACK.md, BUILD_PLAN.md, DEMO_SCRIPT.md, and PROJECT_STRUCTURE.md in this repo.
Read all of them before starting. Everything in those files is a fixed, agreed decision,
not an open design question.

## Hard constraints — do not deviate without asking first
1. **No FastAPI, no REST API, no web server, no HTML/JS in the core system.** This is a
   stdio CLI proxy. The only allowed exception is the optional, separate, read-only
   stretch-goal dashboard in `trustgate/dashboard/`, built last and only if time remains —
   ask before starting it.
2. **Follow the build order in BUILD_PLAN.md exactly.** Stage 4 (raw passthrough proxy,
   zero inspection logic) must work and be manually verified before any scanner is
   written. Do not skip ahead to "interesting" mechanisms before plumbing works.
3. **Use exactly the tech stack in TECH_STACK.md.** If you believe a substitution or
   addition is warranted, stop and ask — do not silently swap a library.
4. **Never accept a server-supplied hash as a fingerprint.** Fingerprints are always
   computed client-side, from the manifest TrustGate itself received.
5. **The Policy Engine is deterministic, not an LLM call.** The LLM (Haiku) only scores
   individual text; `policy/engine.py` combines signals with a plain weighted function.
6. **Don't overclaim novelty.** If asked or if writing any pitch/README copy, use the
   honesty framing in PRD.md — the combination is the contribution, not any single
   mechanism in isolation.
7. **Test each stage before moving to the next**, per the Definition of Done in
   BUILD_PLAN.md. A stage "looking right" in code review is not the same as running it.
8. **Do not reference or blend in any other project.** This repo is scoped to MCP
   TrustGate only.

## Working style
- Build and verify one stage at a time. After each stage, report what you ran and what
  you observed, not just what you wrote.
- `eval()` is used inside the deliberately toy calculator server for the demo only —
  don't "fix" it into something safer that changes the demo's behavior, and don't reuse
  that pattern anywhere else.
- Keep the terminal console (Stage 16) last. Prove every mechanism with plain `print()`
  first.
- If a real run behaves differently from what a stage's Definition of Done expects, stop
  and surface the discrepancy rather than adjusting the DoD to match the code.

## When you're unsure
Ask, rather than guessing an architecture change, a scope change, or a different
attack-scenario framing than what's in PRD.md and DEMO_SCRIPT.md.
