"""Tests for the optional n8n webhook adapter using a local mock endpoint."""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import unittest
from unittest.mock import patch

from trustgate.integrations.n8n import build_payload, emit_event


class _MockHandler(BaseHTTPRequestHandler):
    payload = None
    headers_seen = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _MockHandler.payload = json.loads(self.rfile.read(length))
        _MockHandler.headers_seen = dict(self.headers)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args):
        return


class TestN8NIntegration(unittest.TestCase):
    def test_unconfigured_is_inert(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(emit_event("calculator", "BLOCK", 80, "BLOCK", "secret detail", "now", 1))

    def test_payload_allowlists_audit_metadata(self):
        payload = build_payload(
            "calculator", "BLOCK", 80, "BLOCK",
            json.dumps({"request_id": "r1", "api_key": "do-not-send", "triggered_rules": ["regex"]}),
            "now", 7,
        )
        encoded = json.dumps(payload)
        self.assertIn("r1", encoded)
        self.assertIn("triggered_rules", encoded)
        self.assertNotIn("do-not-send", encoded)
        self.assertNotIn("api_key", encoded)

    def test_configured_local_webhook_receives_real_event_shape(self):
        server = HTTPServer(("127.0.0.1", 0), _MockHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/webhook"
            with patch.dict(os.environ, {"N8N_WEBHOOK_URL": url}, clear=True):
                self.assertTrue(emit_event(
                    "calculator", "POLICY_DECISION", 42, "HOLD",
                    json.dumps({"request_id": "r2", "severity": "medium", "llm_probability": 0.8}),
                    "2026-09-11T00:00:00Z", 9,
                ))
            thread.join(timeout=2)
            self.assertEqual(_MockHandler.payload["event_type"], "POLICY_DECISION")
            self.assertEqual(_MockHandler.payload["risk_score"], 42)
            self.assertEqual(_MockHandler.payload["metadata"]["request_id"], "r2")
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
