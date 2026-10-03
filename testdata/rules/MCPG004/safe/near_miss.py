import subprocess
import urllib.parse

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


@mcp.tool()
def git_log(branch: str) -> str:
    """Show the git log of a branch."""
    cmd = ["git", "log", "--oneline", "--", branch]
    return subprocess.run(cmd, capture_output=True, text=True).stdout


@mcp.tool()
def reset_default(cmd: str) -> str:
    """Run the fixed maintenance command."""
    cmd = "echo ok"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
