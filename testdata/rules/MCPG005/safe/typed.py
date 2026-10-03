import sqlite3
from typing import Literal, Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db")
conn = sqlite3.connect("app.db")


@mcp.tool()
def recent(limit: int, offset: Optional[int] = None) -> list:
    """List the most recent rows. The schema guarantees both values are integers."""
    return conn.execute(f"SELECT * FROM events ORDER BY ts DESC LIMIT {limit} OFFSET {offset or 0}").fetchall()


@mcp.tool()
def by_status(status: Literal["open", "closed"]) -> list:
    """List tickets with one of two statuses."""
    return conn.execute(f"SELECT * FROM tickets WHERE status = '{status}'").fetchall()
