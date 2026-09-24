import shlex
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")
ALLOWED_PROGRAMS = {"git", "ls"}


@mcp.tool()
def git_log(branch: str) -> str:
    """Show the git log of a branch."""
    result = subprocess.run(["git", "log", "--oneline", "--", branch], capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def grep_logs(pattern: str) -> str:
    """Search the application logs."""
    return subprocess.run(f"grep -r {shlex.quote(pattern)} /var/log/app", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def run_tool(command: str, args: list[str]) -> str:
    """Run an allowed helper program."""
    if command not in ALLOWED_PROGRAMS:
        raise ValueError("program not allowed")
    return subprocess.run([command, *args], capture_output=True, text=True).stdout
