from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def read_note(note_id: str) -> str:
    """Read a note."""
    return note_id


@mcp.tool()
def read_note_header(note_id: str) -> str:
    """Read only the title of a note."""
    return note_id[:20]
