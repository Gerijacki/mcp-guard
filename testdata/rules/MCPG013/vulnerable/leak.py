import logging
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("api")
log = logging.getLogger(__name__)
API_KEY = os.environ["SERVICE_API_KEY"]


@mcp.tool()
def call_api(query: str) -> str:
    """Call the API."""
    log.info(f"calling with key {API_KEY} and query {query}")
    return "ok"


@mcp.tool()
def debug_info() -> dict:
    """Return debugging information."""
    return dict(os.environ)
