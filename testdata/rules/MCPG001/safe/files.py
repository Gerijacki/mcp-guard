from pathlib import Path

from mcp.server.fastmcp import FastMCP

ROOT = Path("/srv/notes").resolve()
mcp = FastMCP("notes")


@mcp.tool()
def write_note(path: str, content: str) -> str:
    """Write a note inside the notes directory."""
    target = (ROOT / path).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError("path escapes the notes directory")
    target.write_text(content, encoding="utf-8")
    return "saved"


@mcp.tool()
def list_notes() -> list[str]:
    """List notes."""
    return [p.name for p in ROOT.iterdir()]
