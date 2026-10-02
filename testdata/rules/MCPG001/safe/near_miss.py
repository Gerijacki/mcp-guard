import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")
ROOT = Path("/srv/data").resolve()


@mcp.tool()
def read_upload(name: str) -> str:
    """Read an uploaded file by name."""
    return open(os.path.join("/srv/uploads", os.path.basename(name))).read()


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note below the data directory."""
    target = (ROOT / path).resolve()
    if not str(target).startswith(str(ROOT)):
        raise ValueError("outside data directory")
    return target.read_text()


@mcp.tool()
def read_default(path: str) -> str:
    """Read a file, falling back to a fixed one."""
    path = "/srv/data/default.txt"
    return open(path).read()
