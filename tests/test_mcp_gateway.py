"""Protocol-level tests for the MCP-compatible TrustGate gateway."""

import os
import sys
import tempfile
import unittest
import asyncio
from types import SimpleNamespace

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from trustgate.mechanisms.fingerprint import compute_tool_fingerprint
from trustgate.proxy.adapter import DownstreamConfig
from trustgate.proxy.gateway import MCPGateway
from trustgate.storage.database import init_db, save_tool


class TestMCPGateway(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "gateway.db")
        init_db(self.db_path)
        self.python_exe = sys.executable

    def tearDown(self):
        self.tmp_dir.cleanup()

    def gateway_params(self, target: str, *extra: str) -> StdioServerParameters:
        return StdioServerParameters(
            command=self.python_exe,
            args=[
                "trustgate/main.py",
                "gateway",
                "--target",
                target,
                "--name",
                "calculator",
                "--publisher",
                "trustgate-demo",
                "--db",
                self.db_path,
                *extra,
            ],
        )

    def test_gateway_protocol_flow(self):
        asyncio.run(self._test_gateway_protocol_flow())

    async def _test_gateway_protocol_flow(self):
        params = self.gateway_params(f"{self.python_exe} servers/calculator.py")
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init_result = await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool("calculate", {"expression": "6 * 7"})
                error_result = await session.call_tool("calculate", {"expression": "1 / 0"})

        self.assertEqual(init_result.server_info.name, "TrustGate Gateway")
        self.assertEqual([tool.name for tool in tools.tools], ["calculate"])
        self.assertEqual(result.content[0].text, "42")
        self.assertFalse(result.is_error)
        self.assertTrue(error_result.is_error)
        self.assertIn("Error executing tool calculate", error_result.content[0].text)

        clean_manifest = {
            "name": "calculate",
            "description": "Calculate the result of a mathematical expression.",
            "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}}},
        }
        save_tool(
            "calculator",
            "calculate",
            compute_tool_fingerprint(clean_manifest),
            clean_manifest,
            db_path=self.db_path,
        )
        blocked_gateway = MCPGateway(
            downstream=DownstreamConfig(target=f"{self.python_exe} servers/calculator_poisoned.py"),
            server_name="calculator",
            db_path=self.db_path,
        )
        blocked_gateway.blocked_tools.add("calculate")
        blocked_result = await blocked_gateway.call_tool(None, SimpleNamespace(name="calculate", arguments={}))
        self.assertTrue(blocked_result.is_error)
        self.assertIn("BLOCKED", blocked_result.content[0].text)
        held_gateway = MCPGateway(
            downstream=DownstreamConfig(target=f"{self.python_exe} servers/calculator.py"),
            server_name="calculator",
            db_path=self.db_path,
        )
        held_gateway.held_tools.add("calculate")
        held_result = await held_gateway.call_tool(None, SimpleNamespace(name="calculate", arguments={}))
        self.assertTrue(held_result.is_error)
        self.assertIn("HELD", held_result.content[0].text)



if __name__ == "__main__":
    unittest.main()
