# Project Status: MCP TrustGate

## Current Stage
**Stage 2: COMPLETE**

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

## Environment & Secrets
- `venv/` is local and ignored by Git.
- No API keys, `.env` files, credentials, or secrets committed.

## Next Stage
**Stage 3 — CLI Shell**
- Implementation of `trustgate/main.py` CLI entrypoint using `argparse`.
- DoD: `python3 trustgate/main.py run --target "python3 servers/calculator.py"` prints launch line and exits cleanly.
