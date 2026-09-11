"""Focused tests for the separate Web UI state and approval API."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from trustgate.storage.database import init_db, log_event, save_approval, save_tool
from trustgate.web_dashboard import snapshot


class TestWebDashboard(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "web.db")
        init_db(self.db_path)
        save_tool("calculator", "calculate", "a" * 64, {"name": "calculate"}, db_path=self.db_path)
        log_event("calculator", "POLICY_DECISION", 42, "HOLD", json.dumps({"tool": "calculate", "severity": "medium"}), db_path=self.db_path)
        save_approval(
            {
                "request_id": "approval-1",
                "timestamp": "2026-09-11T00:00:00+00:00",
                "server": "calculator",
                "tool": "calculate",
                "risk_score": 42,
                "severity": "medium",
                "reason": "Review required",
                "evidence": ["fingerprint change"],
                "old_hash": "old",
                "new_hash": "new",
                "fingerprint_change": True,
            },
            db_path=self.db_path,
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_snapshot_uses_real_database_state(self):
        state = snapshot(self.db_path)
        self.assertEqual(state["counts"]["servers"], 1)
        self.assertEqual(state["counts"]["tools"], 1)
        self.assertEqual(state["counts"]["pending"], 1)
        self.assertEqual(state["approvals"][0]["risk_score"], 42)
        self.assertEqual(state["approvals"][0]["old_hash"], "old")
        self.assertEqual(state["fingerprint_changes"], [])

    def test_web_html_contains_live_dashboard_sections(self):
        from trustgate.web_dashboard import HTML
        for label in ("TRUSTGATE", "Pending Approvals", "Recent Threats", "Fingerprint Changes", "Audit History"):
            self.assertIn(label, HTML)


if __name__ == "__main__":
    unittest.main()
