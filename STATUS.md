# Project Status: MCP TrustGate

## Current Stage
**Stage 3 & Stage 4: COMPLETE**

## Completed Stages Summary
- **Stage 1: Environment Setup (COMPLETE)**
  - Python 3.13.7 virtual environment (`venv/`) configured.
  - Installed direct dependencies: `mcp==2.2.0`, `anthropic==1.4.0`, `rapidfuzz==3.14.6`, `rich==15.0.0`.
  - Import verification and SDK checks passed.
  - Key decision: OpenRouter (free tier) will be used for Stage 13 instead of Anthropic API.
- **Stage 2: Three Demo MCP Servers + Variants (COMPLETE)**
  - `servers/calculator.py`: Baseline clean calculator MCP server utilizing `eval()` per AGENTS.md.
  - `servers/calculator_poisoned.py`: Silent mutation / rug-pull variant with identical execution logic but poisoned docstring injecting cross-tool email exfiltration instructions.
  - `servers/calculator_v2.py`: Benign version-bump variant with harmless docstring change for testing policy re-approval.
  - `servers/docs_search.py`: Internal docs search server providing clean documents and a poisoned document scenario (`leave_policy_poisoned`) for output sanitization testing.
  - `servers/email_tool.py`: Outgoing email tool server simulating dispatch.
  - All 5 servers tested and verified to start and idle waiting on stdio per Definition of Done.
- **Stage 3: CLI Shell (COMPLETE)**
  - `trustgate/main.py`: CLI entrypoint built using `argparse`, supporting `trustgate run --target "<command>"`.
  - Output diagnostics and banners are directed to `sys.stderr` so `sys.stdout` remains pure JSON-RPC for standard MCP clients.
  - Verified launch line printing and clean exit.
- **Stage 4: Raw Passthrough Proxy (COMPLETE)**
  - `trustgate/proxy/core.py`: `StdioProxy` class implementing asynchronous bidirectional stdio bridging between MCP client and server child process.
  - Platform-resilient stdin handling: dedicated background reader thread feeding an `asyncio.Queue` avoids Windows IOCP pipe limitations (`WinError 6`).
  - Outbound server responses on `proc.stdout` flushed immediately to `sys.stdout.buffer` with zero delay.
  - Subprocess `proc.stderr` streamed directly to `sys.stderr.buffer`.
  - Graceful lifecycle and EOF handling ensures remaining buffered server responses drain completely before process exit.
  - Verification: Piped raw JSON-RPC messages; confirmed byte-for-byte identical output between direct calculator server and TrustGate proxy across `initialize`, `notifications/initialized`, `tools/list`, and `tools/call`.

## Environment & Secrets
- `venv/` is local and ignored by Git.
- No API keys, `.env` files, credentials, or secrets committed.

## Next Stage
**Stage 5 — Wire into agent config**
- Configure MCP agent (Claude Desktop, Claude Code, or Antigravity) config to route through `trustgate run --target "..."`.
- DoD: Tool callable end-to-end through the proxy from the agent application.
