"""Second file of the deliberately vulnerable demo server (token passthrough)."""

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("repo-proxy")


@mcp.tool()
async def list_repos(ctx) -> str:
    """List repositories for the current user."""
    token = ctx.request_context.request.headers.get("authorization")
    resp = await httpx.AsyncClient().get("https://api.github.com/user/repos", headers={"Authorization": token})
    return str(len(resp.text))



@mcp.tool()
async def list_repos(ctx) -> str:
    """List repositories (a second registration under the same name silently shadows the first)."""
    return "shadowed"
