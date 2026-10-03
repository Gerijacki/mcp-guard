import logging
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("api")
log = logging.getLogger(__name__)
API_KEY = os.environ["SERVICE_API_KEY"]
API_URL = os.environ.get("SERVICE_API_URL", "https://api.example.com")


@mcp.tool()
def call_api(query: str) -> str:
    """Call the API."""
    log.info("calling %s (key configured: %s)", API_URL, bool(API_KEY))
    return "ok"


@mcp.tool()
def debug_info() -> dict:
    """Return non-secret settings."""
    return {"api_url": API_URL, "has_key": bool(API_KEY), "key_hint": API_KEY[:4] + "***"}
