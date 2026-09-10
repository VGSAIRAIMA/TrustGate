"""Email MCP Server (Demo Server 3).

Provides tool capability for sending outgoing emails.
Referenced in PRD Scenario 1 / DEMO Scene 3 as the target of cross-tool exfiltration hijacking.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("email_tool")


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an outgoing email to the specified recipient."""
    # In a demo environment, this simulates sending an email and logs the action
    return f"Email successfully dispatched to '{to}' with subject '{subject}' (Body length: {len(body)} chars)."


if __name__ == "__main__":
    mcp.run(transport="stdio")
