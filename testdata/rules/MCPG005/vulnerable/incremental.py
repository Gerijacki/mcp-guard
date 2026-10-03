import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db")
conn = sqlite3.connect("app.db")


@mcp.tool()
def sorted_users(sort: str) -> list:
    """List users sorted by a column."""
    q = "SELECT * FROM users"
    q += f" ORDER BY {sort}"
    return conn.execute(q).fetchall()
