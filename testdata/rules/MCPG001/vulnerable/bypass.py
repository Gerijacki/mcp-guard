from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.tool()
def read_data(path: str) -> str:
    """Read a data file."""
    if not path.startswith("/srv/data"):
        raise ValueError("outside data directory")
    return open(path).read()


@mcp.tool()
def read_lines(path: str) -> str:
    """Read a file without comment lines."""
    out = []
    for line in open(path):
        if line.startswith("#"):
            continue
        out.append(line)
    return "".join(out)
