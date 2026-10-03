import re
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


@mcp.tool()
def git_diff(target: str) -> str:
    """Show a diff."""
    return subprocess.run(["git", "diff", "--", target], capture_output=True, text=True).stdout


@mcp.tool()
def git_log(branch: str) -> str:
    """Show the log of a branch."""
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or branch.startswith("-"):
        raise ValueError("bad branch")
    return subprocess.run(["git", "log", "--oneline", branch], capture_output=True, text=True).stdout
