import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hooks")


@mcp.tool()
def notify(message: str) -> str:
    """Post a message to the team webhook."""
    httpx.post("https://hooks.example.com/notify", json={"text": message})
    return "sent"


@mcp.tool()
def ping_backend() -> str:
    """Check that the backend answers."""
    resp = httpx.get("https://api.example.com/health")
    return "up" if resp.status_code == 200 else "down"
