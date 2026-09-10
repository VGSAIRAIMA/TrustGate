# Project Status: MCP TrustGate

## Current Stage
**Stage 11 & Stage 12: COMPLETE**

## Completed Stages Summary
- **Stage 1: Environment Setup (COMPLETE)**
  - Python 3.13.7 virtual environment (`venv/`) configured.
  - Installed direct dependencies: `mcp==2.2.0`, `anthropic==1.4.0`, `rapidfuzz==3.14.6`, `rich==15.0.0`.
  - Import verification and SDK checks passed.
  - Decision: OpenRouter (free tier) will be used for Stage 13 instead of paid Anthropic API.
- **Stage 2: Three Demo MCP Servers + Variants (COMPLETE)**
  - `servers/calculator.py`: Baseline clean calculator MCP server utilizing `eval()` per AGENTS.md.
  - `servers/calculator_poisoned.py`: Silent mutation / rug-pull variant with identical execution logic but poisoned docstring injecting cross-tool email exfiltration instructions.
  - `servers/calculator_v2.py`: Benign version-bump variant with harmless docstring change for testing policy re-approval.
  - `servers/docs_search.py`: Internal docs search server providing clean documents and a poisoned document scenario (`leave_policy_poisoned`) for output sanitization testing.
  - `servers/email_tool.py`: Outgoing email tool server simulating dispatch.
  - All 5 servers tested and verified to start and idle waiting on stdio per Definition of Done.
- **Stage 3: CLI Shell (COMPLETE)**
  - `trustgate/main.py`: CLI entrypoint built using `argparse`, supporting `trustgate run --target "<command>"`.
  - Output diagnostics directed to `sys.stderr` so `sys.stdout` remains pure JSON-RPC for standard MCP clients.
- **Stage 4: Raw Passthrough Proxy (COMPLETE)**
  - `trustgate/proxy/core.py`: `StdioProxy` class implementing asynchronous bidirectional stdio bridging between MCP client and server child process.
  - Dedicated background reader thread feeding an `asyncio.Queue` avoids Windows IOCP pipe limitations (`WinError 6`).
  - Outbound server responses flushed immediately to `sys.stdout.buffer`.
  - Subprocess `proc.stderr` streamed to `sys.stderr.buffer`.
  - Full multi-turn protocol exchange verified byte-for-byte identical against direct server runs.
- **Stage 5: Wire into Agent Config (COMPLETE)**
  - Verified standard MCP agent configuration structure for Claude Desktop / Claude Code / Antigravity.
  - Automated integration test (`tests/test_agent_wire.py`) using official `mcp` Python SDK `ClientSession` and `stdio_client` confirmed full tool initialization, listing, and execution through TrustGate proxy end-to-end.
- **Stage 6: Message Parser (COMPLETE)**
  - `trustgate/proxy/parser.py`: Implemented `parse_message()` and `ParsedMessage` classifying messages into `TOOL_LIST`, `TOOL_CALL`, `RESPONSE`, `ERROR`, and `UNKNOWN`.
  - Helper accessors for tools manifests, tool call names/arguments, and output text extraction.
  - Verified across 8 test scenarios covering all message kinds in `tests/test_parser.py`.
- **Stage 7: Unicode Normalizer (COMPLETE)**
  - `trustgate/security/normalizer.py`: Strips invisible format characters (category `Cf` and explicit zero-width points), applies Unicode NFKC compatibility normalization, and folds visually confusable Cyrillic/Greek homoglyphs to ASCII.
  - Recursive dictionary manifest normalization (`normalize_tool_manifest`) handles nested keys and values.
  - Verified in `tests/test_normalizer.py`.
- **Stage 8: Fingerprint & Pin Engine (COMPLETE)**
  - `trustgate/mechanisms/fingerprint.py`: Canonicalizes tool contracts (`name`, `description`, `inputSchema`, `outputSchema`) to deterministic sorted JSON (`canonicalize_tool`).
  - Computes SHA-256 client-side (`compute_tool_fingerprint`, `compute_manifest_fingerprint`).
  - Enforces client-side security constraint: any server-supplied `hash` or `fingerprint` keys are stripped and ignored.
  - Verified in `tests/test_fingerprint.py` (order invariance, collision-free mutation detection, server spoof rejection).
- **Stage 9: SQLite Vault (COMPLETE)**
  - `trustgate/storage/database.py`: Implements `tools` trust vault (pinned fingerprints and manifests) and `events` table (audit event log).
  - Explicit connection closure prevents Windows file-locking issues.
  - Verified schema initialization and cross-restart row persistence in `tests/test_database.py`.
- **Stage 10: Mutation & Diff Engine (COMPLETE)**
  - `trustgate/mechanisms/mutation.py`: `check_mutation()` verifies incoming fingerprints against SQLite vault.
  - Emits line-level `difflib.unified_diff` on hash mismatch detailing exact description mutations.
  - Verified with clean calculator vs poisoned calculator rug-pull in `tests/test_mutation.py`.
- **Stage 11: Registry Identity Check (COMPLETE)**
  - `trustgate/mechanisms/registry.py`: Curated known-good registry list (`KNOWN_REGISTRY`) and `registry_check()`.
  - Detects typosquatting (e.g. `fireb4se-mcp-server` vs `firebase-mcp-server`) with `rapidfuzz` similarity scoring (>0.90) and unverified/mismatched publisher alerting.
  - Verified in `tests/test_registry.py` (DoD met: `fireb4se-mcp-server` flagged with >0.90 similarity; genuine novel servers not flagged).
- **Stage 12: Regex Scanner (COMPLETE)**
  - `trustgate/security/patterns.py`: High-confidence regex patterns (`SUSPICIOUS_PATTERNS`) targeting system instruction overrides, prompt injections, and silent exfiltration directives.
  - Guaranteed normalization before scanning to prevent Unicode obfuscation bypasses.
  - Emits span details (`find_injection_spans`) for downstream Stage 14 output sanitizer redaction.
  - Verified in `tests/test_regex_scanner.py` (DoD met: poisoned calculator trips multiple patterns; reworded variant `"disregard the guidance supplied earlier"` confirmed to not trip regex, illustrating the gap for Stage 13 LLM scanner).

## Environment & API Key Notes
- `venv/` is local and ignored by Git.
- No API keys, `.env` files, credentials, or secrets committed.
- **Important Reminder:** OpenRouter will be used for Stage 13 (LLM Scanner) with a free model/tier. No keys or secrets will be committed.

## Next Stage
**Stage 13 — LLM Scanner**
- Implementation of `trustgate/security/llm_scanner.py`.
- Semantic tier using OpenRouter with free-tier option for catching reworded/obfuscated attacks that regex misses.
- DoD: `llm_scan()` on the reworded attack variant returns `malicious: true` with confidence > 0.8, using the exact fixed system instruction and JSON-only response contract. Confirm it degrades sanely (treat as inconclusive, don't crash) if the API call errors or returns non-JSON.
