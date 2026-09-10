# Tech Stack

Use exactly this. If a change seems necessary, stop and ask before substituting anything.

| Layer | Technology | Why |
|---|---|---|
| Protocol/SDK | Official Anthropic `mcp` Python SDK (`FastMCP`) | Real MCP servers/clients, not simulated. Minimal boilerplate. |
| Proxy core | Python 3.11+, `asyncio`, `subprocess` | Reads from agent and server simultaneously without blocking either side. |
| CLI shell | `argparse` (built-in) | Zero extra dependency for a single-command (`run`) tool. |
| Registry check | `rapidfuzz` (or `difflib.SequenceMatcher`) | Fast, deterministic name-similarity scoring. Deliberately **not** an LLM — this is a solved math problem (edit distance); an LLM would add cost, latency, and non-determinism for no benefit. |
| Fingerprinting | `hashlib` (SHA-256) + `json.dumps(sort_keys=True)` | Deterministic, unspoofable when computed client-side over the canonical manifest. |
| Diffing | `difflib.unified_diff` | Turns a hash mismatch into a human-readable line-level explanation. |
| Normalization | `unicodedata` (NFKC + strip `Cf` category chars) | Defeats invisible-character and lookalike-letter obfuscation before any scanner runs. |
| Pattern scanning | `re` (built-in) | Instant first-pass check for known attack phrasing. |
| Semantic scanning | Anthropic API, model `claude-haiku-4-5-20251001` | Cheapest/fastest current tier, appropriate for narrow structured-JSON classification, not open-ended chat. Catches reworded/obfuscated attacks regex misses. |
| Storage | `sqlite3` (built-in) | Single local file, no server process — correct for a local, single-user MVP. |
| Console | `rich` | Live-updating colored terminal panels. Zero browser/web-server dependency. |
| Policy engine | Plain Python function | Deterministic weighted scoring, explicitly not an LLM decision and not a claimed industry standard. |

## Explicitly excluded from the core system
- **No FastAPI.** No REST API. No web server. No HTML/JS for the core proxy.
- Real MCP servers of this class talk over stdio, not HTTP — there is no web conversation
  to build a backend around.
- The *only* place FastAPI may appear at all is the optional, separate, read-only
  stretch-goal dashboard described in ARCHITECTURE.md — never inside the stdio path.

## Install
```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install mcp anthropic rapidfuzz rich
export ANTHROPIC_API_KEY="sk-ant-..."   # from console.anthropic.com, NOT your claude.ai login
```

## Packaging for real distribution (post-hackathon, or demo polish)
Not required to run the demo — `python3 trustgate/main.py run --target "..."` from inside
the repo works fine for that. If you want `pip install trustgate` to work like
`pip install rich`, add a `pyproject.toml` with a console-script entry point:

```toml
[project]
name = "trustgate"
version = "0.1.0"
dependencies = ["mcp", "anthropic", "rapidfuzz", "rich"]

[project.scripts]
trustgate = "trustgate.main:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
```
Then `pip install -e .` locally gives you a global `trustgate` command immediately.
