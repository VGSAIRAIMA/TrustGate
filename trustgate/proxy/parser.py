"""TrustGate message parser for classifying MCP JSON-RPC messages.

Labels messages into canonical kinds:
- TOOL_LIST: tools/list request or tools manifest response
- TOOL_CALL: tools/call invocation
- RESPONSE: general result responses
- ERROR: JSON-RPC errors or tool call execution failures
- UNKNOWN: unparseable text, notifications, or unhandled message types
"""

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any


class MessageKind(str, Enum):
    TOOL_LIST = "TOOL_LIST"
    TOOL_CALL = "TOOL_CALL"
    RESPONSE = "RESPONSE"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass
class ParsedMessage:
    kind: MessageKind
    data: dict[str, Any] | None = None
    raw: str = ""

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, (MessageKind, str)):
            return self.kind == other
        if isinstance(other, ParsedMessage):
            return self.kind == other.kind and self.data == other.data
        return False

    @property
    def is_tool_list(self) -> bool:
        return self.kind == MessageKind.TOOL_LIST

    @property
    def is_tool_call(self) -> bool:
        return self.kind == MessageKind.TOOL_CALL

    @property
    def is_response(self) -> bool:
        return self.kind == MessageKind.RESPONSE

    @property
    def is_error(self) -> bool:
        return self.kind == MessageKind.ERROR

    @property
    def is_unknown(self) -> bool:
        return self.kind == MessageKind.UNKNOWN

    def get_tools(self) -> list[dict[str, Any]]:
        """Extract tool definitions list if message is a tool manifest."""
        if self.data and "result" in self.data and isinstance(self.data["result"], dict):
            return self.data["result"].get("tools", [])
        return []

    def get_tool_call_info(self) -> tuple[str | None, dict[str, Any]]:
        """Extract tool name and arguments if message is a tool call."""
        if self.data and "params" in self.data and isinstance(self.data["params"], dict):
            params = self.data["params"]
            return params.get("name"), params.get("arguments", {})
        return None, {}

    def get_output_text(self) -> str:
        """Extract text content from a tool call response."""
        if not self.data or "result" not in self.data or not isinstance(self.data["result"], dict):
            return ""
        result = self.data["result"]
        content = result.get("content", [])
        texts = []
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    texts.append(item.get("text", ""))
        return "\n".join(texts)


def parse_message(raw: str | bytes | dict[str, Any]) -> ParsedMessage:
    """Parse and classify a raw MCP message into a ParsedMessage."""
    raw_str = ""
    data: dict[str, Any] | None = None

    if isinstance(raw, bytes):
        try:
            raw_str = raw.decode("utf-8")
        except UnicodeDecodeError:
            return ParsedMessage(kind=MessageKind.UNKNOWN, raw=repr(raw))
    elif isinstance(raw, str):
        raw_str = raw
    elif isinstance(raw, dict):
        data = raw
        raw_str = json.dumps(raw)
    else:
        return ParsedMessage(kind=MessageKind.UNKNOWN, raw=str(raw))

    if data is None:
        try:
            parsed = json.loads(raw_str)
            if isinstance(parsed, dict):
                data = parsed
            else:
                return ParsedMessage(kind=MessageKind.UNKNOWN, raw=raw_str)
        except Exception:
            return ParsedMessage(kind=MessageKind.UNKNOWN, raw=raw_str)

    # 1. Check for explicit JSON-RPC error
    if data.get("error") is not None:
        return ParsedMessage(kind=MessageKind.ERROR, data=data, raw=raw_str)

    # 2. Check for tool execution isError
    res = data.get("result")
    if isinstance(res, dict) and res.get("isError") is True:
        return ParsedMessage(kind=MessageKind.ERROR, data=data, raw=raw_str)

    # 3. Check for tool list (request or manifest response)
    method = data.get("method")
    if method == "tools/list":
        return ParsedMessage(kind=MessageKind.TOOL_LIST, data=data, raw=raw_str)
    if isinstance(res, dict) and "tools" in res and isinstance(res["tools"], list):
        return ParsedMessage(kind=MessageKind.TOOL_LIST, data=data, raw=raw_str)

    # 4. Check for tool call
    if method == "tools/call":
        return ParsedMessage(kind=MessageKind.TOOL_CALL, data=data, raw=raw_str)

    # 5. Check for generic response
    if "result" in data:
        return ParsedMessage(kind=MessageKind.RESPONSE, data=data, raw=raw_str)

    # 6. Default to UNKNOWN (e.g. notifications, non-tool requests)
    return ParsedMessage(kind=MessageKind.UNKNOWN, data=data, raw=raw_str)
