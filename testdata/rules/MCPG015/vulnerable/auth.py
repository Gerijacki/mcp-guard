import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("github")
SCOPES = {"scopes": "repo admin:org *"}


@mcp.tool()
async def list_repos(ctx) -> str:
    """List repositories."""
    token = ctx.request_context.request.headers.get("authorization")
    resp = await httpx.AsyncClient().get("https://api.github.com/user/repos", headers={"Authorization": token})
    return resp.text
