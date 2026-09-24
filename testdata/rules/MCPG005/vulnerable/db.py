import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db")
conn = sqlite3.connect("app.db")


@mcp.tool()
def find_user(name: str) -> list:
    """Find users by name."""
    query = f"SELECT id, email FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


@mcp.tool()
def count_orders(status: str) -> int:
    """Count orders with a status."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM orders WHERE status = '%s'" % status)
    return cur.fetchone()[0]
