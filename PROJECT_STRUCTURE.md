# Project Structure

```
mcp-trustgate/
├── PRD.md
├── ARCHITECTURE.md
├── TECH_STACK.md
├── BUILD_PLAN.md
├── DEMO_SCRIPT.md
├── AGENTS.md
├── RISKS.md
├── pyproject.toml                 # optional — only needed for `pip install trustgate` polish
├── trustgate.db                   # created at runtime, gitignore this
├── trustgate/
│   ├── __init__.py
│   ├── main.py                    # Stage 3 — CLI entrypoint (argparse)
│   ├── proxy/
│   │   ├── __init__.py
│   │   ├── core.py                # Stage 4 — asyncio raw stdio bridge
│   │   ├── adapter.py             # Configurable downstream MCP command
│   │   ├── gateway.py             # MCP server/client gateway mode
│   │   └── parser.py              # Stage 6 — message classification
│   ├── security/
│   │   ├── __init__.py
│   │   ├── normalizer.py          # Stage 7 — unicode normalization
│   │   ├── patterns.py            # Stage 12 — regex scanner
│   │   └── llm_scanner.py         # Stage 13 — OpenRouter semantic scanner
│   ├── mechanisms/
│   │   ├── __init__.py
│   │   ├── fingerprint.py         # Stage 8
│   │   ├── mutation.py            # Stage 10
│   │   ├── registry.py            # Stage 11
│   │   └── output_sanitizer.py    # Stage 14
│   ├── storage/
│   │   ├── __init__.py
│   │   └── database.py            # Stage 9 — SQLite vault + event log
│   ├── policy/
│   │   ├── __init__.py
│   │   └── engine.py              # Stage 15 — deterministic decision function
│   ├── console/
│   │   ├── __init__.py
│   │   └── dashboard.py           # Stage 16 — rich terminal panels
│   └── dashboard/                 # OPTIONAL stretch goal only — do not build early
│       ├── __init__.py
│       └── server.py              # FastAPI + SSE, read-only, separate process
├── servers/
│   ├── calculator.py
│   ├── calculator_poisoned.py
│   ├── calculator_v2.py           # benign version-bump variant
│   ├── docs_search.py
│   └── email_tool.py
└── tests/
    ├── test_fingerprint.py
    ├── test_mutation.py
    ├── test_registry.py
    ├── test_regex_scanner.py
    ├── test_output_sanitizer.py
    └── test_policy_engine.py
```

## Packaging (optional — see TECH_STACK.md for the full snippet)
A `pyproject.toml` with a `[project.scripts] trustgate = "trustgate.main:main"` entry
point is what makes `pip install trustgate` behave like `pip install rich`. Not required
for the hackathon demo — running `python3 trustgate/main.py run --target "..."` from the
repo root is fine and is what the build guide assumes throughout.

## `.gitignore` essentials
```
venv/
trustgate.db
__pycache__/
.env
```
Never commit `ANTHROPIC_API_KEY` — load it from the environment only.
