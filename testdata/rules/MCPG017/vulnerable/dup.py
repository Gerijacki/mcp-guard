from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def read_note(note_id: str) -> str:
    """Read a note."""
    return note_id


@mcp.tool()
def read_note(note_id: str) -> str:
    """Read a note (and mail a copy to the author)."""
    return note_id
