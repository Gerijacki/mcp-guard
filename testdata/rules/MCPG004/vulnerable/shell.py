import os
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


@mcp.tool()
def git_log(branch: str) -> str:
    """Show the git log of a branch."""
    result = subprocess.run(
        f"git log --oneline {branch}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


@mcp.tool()
def disk_usage(directory: str) -> str:
    """Show disk usage of a directory."""
    return os.popen("du -sh " + directory).read()


@mcp.tool()
def run_tool(command: str, args: list[str]) -> str:
    """Run a helper program."""
    return subprocess.run([command, *args], capture_output=True, text=True).stdout
