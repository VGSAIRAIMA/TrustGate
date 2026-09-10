# TrustGate MCP Gateway

TrustGate now has two stdio modes:

- `run`: the existing transparent raw JSON-RPC inspection proxy.
- `gateway`: an MCP-compatible gateway with an MCP server endpoint toward the agent and an MCP client session toward one configured downstream server.

## Gateway flow

```text
MCP agent/client
      |
      | MCP over stdio
      v
TrustGate Gateway (MCP Server)
      |
      | tools/list inspection
      | tools/call forwarding and output sanitization
      v
Downstream MCP Server (MCP ClientSession)
```

The gateway uses the existing security engine:

1. Downstream `tools/list` is fetched through the official MCP client SDK.
2. Each tool is evaluated by `evaluate_tool_manifest()`.
3. `ALLOW` tools are exposed upstream and pinned in SQLite.
4. `HOLD` and `BLOCK` tools are withheld from the upstream tool list.
5. A call to a held or blocked name returns an MCP `CallToolResult` with `isError: true`.
6. Allowed calls are forwarded with `ClientSession.call_tool()`.
7. Returned content is passed through `sanitize_mcp_response()` before being returned upstream.
8. Downstream tool errors are returned as valid MCP error results.

The Web/HTML UI is not in this protocol path. `cli_launcher.html` only generates a command.

## Run the gateway

From the repository root with the virtual environment active:

```powershell
cd C:\Users\acer\OneDrive\Desktop\megathon\TrustGate
.\.venv\Scripts\Activate.ps1
python trustgate/main.py gateway `
  --target "python servers/calculator.py" `
  --name calculator `
  --publisher trustgate-demo `
  --db trustgate.db
```

Configure an MCP client such as Claude Desktop or another MCP client to launch the same command instead of launching the downstream server directly. The client communicates with TrustGate over stdio; TrustGate launches the configured `--target` downstream command.

For a poisoned manifest after a clean tool has been pinned in the same database:

```powershell
python trustgate/main.py gateway `
  --target "python servers/calculator_poisoned.py" `
  --name calculator `
  --publisher trustgate-demo `
  --db trustgate.db
```

The poisoned tool will be omitted from `tools/list`, and a direct call to it returns an MCP tool error.

## Configuration

The downstream adapter accepts:

- `--target`: downstream command; no server is hardcoded.
- `--name`: identity used for registry and fingerprint records.
- `--publisher`: publisher identity used by registry checks.
- `--cwd`: optional downstream working directory.
- `--db`: SQLite trust vault and audit log path.
- `--use-llm`: enables semantic scanning; it defaults on when `OPENROUTER_API_KEY` is set.

The gateway forwards `OPENROUTER_API_KEY` and `OPENROUTER_MODEL` across the process boundary when present.
