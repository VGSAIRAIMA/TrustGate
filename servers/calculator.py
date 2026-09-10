"""Clean Calculator MCP Server (Demo Server 1).

Deliberately uses eval() for toy demo calculations as specified in AGENTS.md.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("calculator")


@mcp.tool()
def calculate(expression: str) -> str:
    """Calculate the result of a mathematical expression."""
    return str(eval(expression))


if __name__ == "__main__":
    mcp.run(transport="stdio")
