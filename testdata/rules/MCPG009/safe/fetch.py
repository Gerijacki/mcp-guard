from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")
ALLOWED_HOSTS = {"api.example.com", "docs.example.com"}


@mcp.tool()
async def fetch_doc(url: str) -> str:
    """Download a document from an allowed host."""
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return str(len(httpx.get(url).content))


@mcp.tool()
async def get_item(item: str) -> str:
    """Query the inventory service (fixed host)."""
    r = httpx.get(f"https://inventory.example.com/items/{item}")
    return str(r.status_code)
