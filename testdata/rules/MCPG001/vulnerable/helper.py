from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")


def _read(p: str) -> str:
    with open(p) as fh:
        return fh.read()


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note."""
    return _read(path)
