# Optional n8n Integration

TrustGate does not require n8n. The adapter is isolated in
`trustgate/integrations/n8n.py` and uses Python's standard library only.

## Configuration

Set the webhook URL in the environment; never put credentials in source files:

```powershell
$env:N8N_WEBHOOK_URL = "https://your-n8n-host/webhook/trustgate"
$env:N8N_WEBHOOK_TOKEN = "<token-if-your-webhook-requires-one>"
```

`N8N_WEBHOOK_TOKEN` is optional. TrustGate sends only structured audit metadata:
source, event ID, timestamp, event type, server, risk score, decision, and an
allowlisted metadata subset. Raw event detail, API keys, tokens, and private
content are not forwarded. Delivery runs in a daemon thread and failures never
change local enforcement or block MCP traffic.

When `N8N_WEBHOOK_URL` is unset, TrustGate behaves exactly as before and does not
attempt any network request.

## Run the real scenario rehearsal

Use one database for TrustGate and the Web UI:

```powershell
python demo_scenarios.py --db demo.db
python trustgate/main.py web --db demo.db --port 8765
```

To exercise the semantic tier when an OpenRouter key is configured:

```powershell
python demo_scenarios.py --db demo.db --use-llm
```

The rehearsal uses the real `servers/calculator.py`, `calculator_v2.py`, and
`calculator_poisoned.py` MCP servers, plus the isolated demo-only
`demo_servers/suspicious.py` server, and the real `MCPGateway`. It records actual
TrustGate events for:

1. Clean calculator: deterministic `ALLOW`, downstream call succeeds.
2. Suspicious demo description: detection, `HOLD`, `ALLOW_ONCE`, downstream call
   succeeds without replacing a baseline.
3. Poisoned calculator: `BLOCK`, tool is not exposed and downstream receives no call.
4. Benign calculator version change: `HOLD`, `APPROVE_UPDATE`, new fingerprint becomes baseline.

The same SQLite events are visible in the terminal output and Web UI. If the n8n
URL is configured, the same committed audit events are posted to that webhook.

## What is tested

The repository test `tests/test_n8n_integration.py` starts a local HTTP mock
webhook and verifies the exact payload shape, optional disabled behavior, and
secret-field filtering. This proves the TrustGate adapter and transport shape.

A hosted n8n instance, n8n workflow behavior, TLS configuration, and production
credential management are not tested here. Do not treat those as verified
compatibility claims until the configured endpoint has been exercised with this
rehearsal.
