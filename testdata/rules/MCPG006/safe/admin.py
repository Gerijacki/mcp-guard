from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("admin")


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
def delete_user(user_id: str, confirm: bool = False) -> str:
    """Delete a user account. Requires confirm=true."""
    if not confirm:
        return f"Refusing to delete {user_id} without confirm=true"
    db.users.delete_one({"_id": user_id})
    return "deleted"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_user(user_id: str) -> dict:
    """Get a user account."""
    return db.users.find_one({"_id": user_id})
