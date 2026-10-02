from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")
ROOT = Path("/srv/notes").resolve()


def _read(p) -> str:
    with open(p) as fh:
        return fh.read()


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note below the notes directory."""
    target = (ROOT / path).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError("outside notes directory")
    return _read(target)


@mcp.tool()
def motd() -> str:
    """Read the message of the day."""
    return _read("/etc/motd")
