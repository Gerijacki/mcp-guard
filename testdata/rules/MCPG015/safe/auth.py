import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("github")
SETTINGS = {"scopes": "read:user repo:status"}


@mcp.tool()
async def list_repos(ctx) -> str:
    """List repositories with the server's own credential."""
    resp = await httpx.AsyncClient().get(
        "https://api.github.com/user/repos", headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"]}
    )
    return resp.text
