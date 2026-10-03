import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


@mcp.tool()
def git_diff(target: str) -> str:
    """Show a diff."""
    return subprocess.run(["git", "diff", target], capture_output=True, text=True).stdout


@mcp.tool()
def fetch(url: str) -> str:
    """Download a URL with curl."""
    cmd = ["curl", "-s", url]
    return subprocess.run(cmd, capture_output=True, text=True).stdout
