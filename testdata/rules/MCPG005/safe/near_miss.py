import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db")
TABLE = "users"
SORTABLE = {"name", "created_at"}
conn = sqlite3.connect("app.db")


@mcp.tool()
def get_user(user_id: str) -> list:
    """Fetch a user by id."""
    return conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (user_id,)).fetchall()


@mcp.tool()
def list_users(limit: str) -> list:
    """List users."""
    n = int(limit)
    return conn.execute(f"SELECT * FROM users LIMIT {n}").fetchall()


@mcp.tool()
def sorted_users(sort: str) -> list:
    """List users sorted by a column."""
    if sort not in SORTABLE:
        raise ValueError("bad column")
    q = "SELECT * FROM users"
    q += f" ORDER BY {sort}"
    return conn.execute(q).fetchall()
