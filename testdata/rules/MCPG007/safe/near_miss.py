from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db")


@mcp.tool()
def notify(message: str) -> str:
    """Posts a message to the team webhook URL."""
    return message


@mcp.tool()
def query_table(table: str) -> str:
    """Query a table. Before using this tool, call list_tables first to see what exists."""
    return table
