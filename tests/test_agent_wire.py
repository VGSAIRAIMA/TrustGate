"""End-to-end verification for Stage 5: Wire into agent config.

Uses the official MCP Python SDK client to connect to TrustGate proxy
configured in front of servers/calculator.py, verifying full tool discovery
and execution end-to-end.
"""

import asyncio
import os
import sys
import tempfile
import unittest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


class TestAgentWire(unittest.IsolatedAsyncioTestCase):
    async def test_agent_end_to_end_proxy(self):
        with tempfile.TemporaryDirectory() as folder:
            server_params = StdioServerParameters(
                command=sys.executable,
                args=[
                    "trustgate/main.py",
                    "run",
                    "--target",
                    f"{sys.executable} servers/calculator.py",
                    "--db",
                    os.path.join(folder, "wire.db"),
                    "--publisher",
                    "trustgate-demo",
                ],
            )

            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # 1. Initialize
                    init_res = await session.initialize()
                    self.assertEqual(init_res.server_info.name, "calculator")

                    # 2. List tools
                    tools = await session.list_tools()
                    tool_names = [t.name for t in tools.tools]
                    self.assertIn("calculate", tool_names)

                    # 3. Call tool
                    res = await session.call_tool("calculate", {"expression": "25 * 4"})
                    self.assertEqual(len(res.content), 1)
                    self.assertEqual(res.content[0].text, "100")


if __name__ == "__main__":
    unittest.main()
