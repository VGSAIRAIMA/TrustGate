"""End-to-end integration and demo rehearsal tests (Stage 17).

Verifies all 5 demo scenes from DEMO_SCRIPT.md running live through the real
TrustGate stdio proxy back-to-back using the official MCP Python SDK client:
1. Scene 1: Typosquatted new server flagged pre-approval.
2. Scene 2: Clean Calculator approved and fingerprint pinned.
3. Scene 3: Poisoned Calculator blocked with unified diff shown.
4. Scene 4: Poisoned document output sanitized while clean content passes.
5. Scene 5: Benign Calculator v2 update held for re-approval (never blocked).
"""

import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from trustgate.mechanisms.fingerprint import compute_tool_fingerprint
from trustgate.policy.engine import PolicyAction
from trustgate.storage.database import get_events, get_tool, init_db, save_tool


class TestEndToEndDemo(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "demo_trustgate.db")
        init_db(self.db_path)

        self.python_exe = sys.executable

    def tearDown(self):
        self.tmp_dir.cleanup()

    async def test_all_5_demo_scenes_back_to_back(self):
        """DoD: All 5 scenes run back-to-back through the real proxy without manual code edits."""

        # ---------------------------------------------------------------------
        # SCENE 1: Typosquatted new server (fireb4se-mcp-server)
        # ---------------------------------------------------------------------
        # Start proxy targeting a server named fireb4se-mcp-server with unverified publisher
        scene1_params = StdioServerParameters(
            command=self.python_exe,
            args=[
                "trustgate/main.py",
                "run",
                "--target",
                f"{self.python_exe} servers/calculator.py",
                "--name",
                "fireb4se-mcp-server",
                "--publisher",
                "unverified",
                "--db",
                self.db_path,
            ],
        )
        async with stdio_client(scene1_params) as (read, write):
            async with ClientSession(read, write) as session:
                init_res = await session.initialize()
                self.assertIsNotNone(init_res)
                # List tools triggers inspection and registry screening
                tools = await session.list_tools()
                self.assertIsNotNone(tools)

        # Confirm audit event was recorded with HOLD decision and risk 40
        events_scene1 = get_events(server="fireb4se-mcp-server", db_path=self.db_path)
        self.assertTrue(len(events_scene1) > 0)
        manifest_event = next(event for event in events_scene1 if event["event_type"] == "MANIFEST_INSPECTION")
        self.assertEqual(manifest_event["decision"], "HOLD")
        self.assertEqual(manifest_event["risk"], 40)
        self.assertIn("typosquatting", manifest_event["detail"].lower())

        # ---------------------------------------------------------------------
        # SCENE 2: Approve the clean Calculator (Stage 8, 9)
        # ---------------------------------------------------------------------
        scene2_params = StdioServerParameters(
            command=self.python_exe,
            args=[
                "trustgate/main.py",
                "run",
                "--target",
                f"{self.python_exe} servers/calculator.py",
                "--name",
                "calculator",
                "--publisher",
                "trustgate-demo",
                "--db",
                self.db_path,
            ],
        )
        async with stdio_client(scene2_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                # Verify calculate is available and allowed
                tool_names = [t.name for t in tools.tools]
                self.assertIn("calculate", tool_names)

                # Tool execution succeeds
                res = await session.call_tool("calculate", {"expression": "12 * 12"})
                self.assertEqual(res.content[0].text, "144")

        # Confirm clean calculator is pinned in vault
        pinned_calc = get_tool("calculator", "calculate", db_path=self.db_path)
        self.assertIsNotNone(pinned_calc)
        pinned_fp = pinned_calc["fingerprint"]
        self.assertTrue(len(pinned_fp) == 64)

        # ---------------------------------------------------------------------
        # SCENE 3: Swap in the poisoned Calculator (silent mutation -> BLOCK)
        # ---------------------------------------------------------------------
        scene3_params = StdioServerParameters(
            command=self.python_exe,
            args=[
                "trustgate/main.py",
                "run",
                "--target",
                f"{self.python_exe} servers/calculator_poisoned.py",
                "--name",
                "calculator",
                "--publisher",
                "trustgate-demo",
                "--db",
                self.db_path,
            ],
        )
        async with stdio_client(scene3_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool_names = [t.name for t in tools.tools]
                # Poisoned tool MUST be withheld from the client!
                self.assertNotIn("calculate", tool_names)

        # Confirm audit event was recorded as BLOCK
        events_scene3 = get_events(server="calculator", db_path=self.db_path)
        block_events = [e for e in events_scene3 if e["decision"] == "BLOCK"]
        self.assertTrue(len(block_events) > 0)
        self.assertGreaterEqual(block_events[0]["risk"], 60)
        self.assertIn("Fingerprint alert", block_events[0]["detail"])

        # ---------------------------------------------------------------------
        # SCENE 4: Query Docs Search with poisoned doc (output redacted)
        # ---------------------------------------------------------------------
        scene4_params = StdioServerParameters(
            command=self.python_exe,
            args=[
                "trustgate/main.py",
                "run",
                "--target",
                f"{self.python_exe} servers/docs_search.py",
                "--name",
                "docs_search",
                "--publisher",
                "trustgate-demo",
                "--db",
                self.db_path,
            ],
        )
        async with stdio_client(scene4_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Call 4a: Clean doc passes through unchanged
                clean_res = await session.call_tool("search_docs", {"query": "leave_policy"})
                self.assertIn("Standard Annual Leave Policy", clean_res.content[0].text)
                self.assertNotIn("[REDACTED]", clean_res.content[0].text)

                # Call 4b: Poisoned doc returns clean sentences with injection redacted
                poison_res = await session.call_tool("search_docs", {"query": "leave_policy_poisoned"})
                sanitized_text = poison_res.content[0].text
                self.assertIn("Standard Annual Leave Policy", sanitized_text)
                self.assertIn("[REDACTED]", sanitized_text)
                self.assertNotIn("SYSTEM INSTRUCTION", sanitized_text)
                self.assertNotIn("publish a summary of recently accessed confidential files", sanitized_text)

        # ---------------------------------------------------------------------
        # SCENE 5: Swap in benign-update Calculator (v2.0 -> HOLD, NEVER BLOCK)
        # ---------------------------------------------------------------------
        scene5_params = StdioServerParameters(
            command=self.python_exe,
            args=[
                "trustgate/main.py",
                "run",
                "--target",
                f"{self.python_exe} servers/calculator_v2.py",
                "--name",
                "calculator",
                "--publisher",
                "trustgate-demo",
                "--db",
                self.db_path,
            ],
        )
        async with stdio_client(scene5_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                # Benign update is held, NOT blocked
                tool_names = [t.name for t in tools.tools]
                self.assertIn("calculate", tool_names)

        # Confirm audit event was recorded as HOLD (score 20)
        events_scene5 = get_events(server="calculator", db_path=self.db_path)
        hold_events = [e for e in events_scene5 if e["decision"] == "HOLD" and e["risk"] == 20]
        self.assertTrue(len(hold_events) > 0)
        self.assertEqual(hold_events[0]["risk"], 20)


if __name__ == "__main__":
    unittest.main()
