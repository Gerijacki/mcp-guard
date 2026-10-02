import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("web")


@mcp.tool()
def get_issue(url: str) -> str:
    """Return an issue body."""
    resp = httpx.get(url)
    data = resp.json()
    body = data["body"]
    return body


@mcp.tool()
def get_raw(url: str) -> str:
    """Return a page as text."""
    return httpx.get(url).text
