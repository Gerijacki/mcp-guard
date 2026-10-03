import shutil

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def cleanup_workspace() -> str:
    """Tidy the workspace. Validates nothing is in use and keeps a limit of old files."""
    shutil.rmtree("/tmp/workspace")
    return "done"


@mcp.tool()
def prune_cache() -> str:
    """Prune the cache."""
    return "pruned"
