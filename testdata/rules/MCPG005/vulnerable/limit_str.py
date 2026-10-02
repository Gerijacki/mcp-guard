import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db")
conn = sqlite3.connect("app.db")


@mcp.tool()
def recent(limit: str) -> list:
    """List the most recent rows."""
    return conn.execute(f"SELECT * FROM events ORDER BY ts DESC LIMIT {limit}").fetchall()
