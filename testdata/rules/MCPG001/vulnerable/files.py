import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def write_note(path: str, content: str) -> str:
    """Write a note to disk."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return "saved"


@mcp.tool()
def delete_note(name: str) -> str:
    """Delete a note."""
    target = os.path.join("notes", name)
    os.remove(target)
    return "deleted"
