"""Tests for Stage 6 message parser."""

import unittest
from trustgate.proxy.parser import parse_message, MessageKind


class TestMessageParser(unittest.TestCase):
    def test_tool_list_request(self):
        raw = '{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}'
        msg = parse_message(raw)
        self.assertEqual(msg.kind, MessageKind.TOOL_LIST)
        self.assertEqual(msg, MessageKind.TOOL_LIST)
        self.assertEqual(msg, "TOOL_LIST")
        self.assertTrue(msg.is_tool_list)

    def test_tool_list_response(self):
        raw = (
            '{"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "calculate", '
            '"description": "Calculate expression.", "inputSchema": {}}]}}'
        )
        msg = parse_message(raw)
        self.assertEqual(msg.kind, MessageKind.TOOL_LIST)
        self.assertTrue(msg.is_tool_list)
        tools = msg.get_tools()
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["name"], "calculate")

    def test_tool_call(self):
        raw = (
            '{"jsonrpc": "2.0", "id": 3, "method": "tools/call", '
            '"params": {"name": "calculate", "arguments": {"expression": "99 * 3"}}}'
        )
        msg = parse_message(raw)
        self.assertEqual(msg.kind, MessageKind.TOOL_CALL)
        self.assertEqual(msg, MessageKind.TOOL_CALL)
        self.assertTrue(msg.is_tool_call)
        name, args = msg.get_tool_call_info()
        self.assertEqual(name, "calculate")
        self.assertEqual(args, {"expression": "99 * 3"})

    def test_response(self):
        # Tool call response
        raw = '{"jsonrpc": "2.0", "id": 3, "result": {"content": [{"text": "297", "type": "text"}], "isError": false}}'
        msg = parse_message(raw)
        self.assertEqual(msg.kind, MessageKind.RESPONSE)
        self.assertEqual(msg, MessageKind.RESPONSE)
        self.assertTrue(msg.is_response)
        self.assertEqual(msg.get_output_text(), "297")

        # Initialize response
        raw_init = '{"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "calculator"}}}'
        msg_init = parse_message(raw_init)
        self.assertEqual(msg_init.kind, MessageKind.RESPONSE)

    def test_error_jsonrpc(self):
        raw = '{"jsonrpc": "2.0", "id": 4, "error": {"code": -32601, "message": "Method not found"}}'
        msg = parse_message(raw)
        self.assertEqual(msg.kind, MessageKind.ERROR)
        self.assertEqual(msg, MessageKind.ERROR)
        self.assertTrue(msg.is_error)

    def test_error_tool_execution(self):
        raw = '{"jsonrpc": "2.0", "id": 5, "result": {"content": [{"text": "ZeroDivisionError", "type": "text"}], "isError": true}}'
        msg = parse_message(raw)
        self.assertEqual(msg.kind, MessageKind.ERROR)
        self.assertEqual(msg, MessageKind.ERROR)
        self.assertTrue(msg.is_error)

    def test_unknown_notification(self):
        raw = '{"jsonrpc": "2.0", "method": "notifications/initialized"}'
        msg = parse_message(raw)
        self.assertEqual(msg.kind, MessageKind.UNKNOWN)
        self.assertEqual(msg, MessageKind.UNKNOWN)
        self.assertTrue(msg.is_unknown)

    def test_unknown_malformed(self):
        raw = "not a valid json string"
        msg = parse_message(raw)
        self.assertEqual(msg.kind, MessageKind.UNKNOWN)
        self.assertTrue(msg.is_unknown)


if __name__ == "__main__":
    unittest.main()
