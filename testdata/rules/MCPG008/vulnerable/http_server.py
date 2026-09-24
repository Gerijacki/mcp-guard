from mcp.server.fastmcp import FastMCP

mcp = FastMCP("remote", host="0.0.0.0", port=8000)


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello {name}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
