import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
async def fetch_url(url: str) -> str:
    """Download a URL and return its size."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, follow_redirects=True)
    return str(len(resp.content))


@mcp.tool()
async def call_host(host: str, item: str) -> str:
    """Query the inventory service on a host."""
    r = httpx.get(f"https://{host}/items/{item}")
    return str(r.status_code)
