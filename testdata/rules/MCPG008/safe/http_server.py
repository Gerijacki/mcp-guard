from mcp.server.fastmcp import FastMCP

mcp = FastMCP("local", host="127.0.0.1", port=8000)


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello {name}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
