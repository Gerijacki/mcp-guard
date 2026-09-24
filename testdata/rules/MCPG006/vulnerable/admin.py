from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("admin")


@mcp.tool()
def delete_user(user_id: str) -> str:
    """Delete a user account and all of its data."""
    db.users.delete_one({"_id": user_id})
    return "deleted"


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
def reset_cache() -> str:
    """Flush every cache entry."""
    cache.flushall()
    return "flushed"
