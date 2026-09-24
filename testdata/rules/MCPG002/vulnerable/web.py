import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("web")


@mcp.tool()
async def fetch_page(url: str) -> str:
    """Fetch a web page and return its text."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
    return resp.text
