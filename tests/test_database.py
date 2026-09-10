"""Tests for Stage 9 SQLite Vault and Audit Event Log."""

import os
import tempfile
import unittest
from trustgate.storage.database import (
    delete_tool,
    get_connection,
    get_events,
    get_tool,
    init_db,
    list_tools,
    log_event,
    save_tool,
)


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_trustgate.db")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_init_db_creates_tables(self):
        # DoD: init_db() creates tools and events tables
        init_db(self.db_path)
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row["name"] for row in cursor.fetchall()]
            self.assertIn("tools", tables)
            self.assertIn("events", tables)
        finally:
            conn.close()

    def test_row_survives_process_restart(self):
        # DoD: a row survives a process restart (simulated by closing connection and reconnecting)
        init_db(self.db_path)
        manifest = {"name": "calculate", "description": "Do math"}
        save_tool("calculator", "calculate", "hash_abc_123", manifest, db_path=self.db_path)

        # Disconnect and open a fresh connection
        retrieved = get_tool("calculator", "calculate", db_path=self.db_path)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["server"], "calculator")
        self.assertEqual(retrieved["tool"], "calculate")
        self.assertEqual(retrieved["fingerprint"], "hash_abc_123")
        self.assertEqual(retrieved["manifest"]["description"], "Do math")

    def test_audit_event_logging(self):
        init_db(self.db_path)
        event_id = log_event(
            server="calculator",
            event_type="MUTATION_CHECK",
            risk=60,
            decision="BLOCK",
            detail="Fingerprint mismatch detected and prompt injection flagged",
            db_path=self.db_path,
        )
        self.assertGreater(event_id, 0)

        events = get_events(server="calculator", db_path=self.db_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["decision"], "BLOCK")
        self.assertEqual(events[0]["risk"], 60)

    def test_list_and_delete_tools(self):
        init_db(self.db_path)
        save_tool("calc", "add", "h1", {}, db_path=self.db_path)
        save_tool("calc", "sub", "h2", {}, db_path=self.db_path)
        save_tool("docs", "search", "h3", {}, db_path=self.db_path)

        tools = list_tools(server="calc", db_path=self.db_path)
        self.assertEqual(len(tools), 2)

        deleted = delete_tool("calc", "add", db_path=self.db_path)
        self.assertTrue(deleted)
        self.assertIsNone(get_tool("calc", "add", db_path=self.db_path))


if __name__ == "__main__":
    unittest.main()
