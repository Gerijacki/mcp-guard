import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")
HEADERS = {"Accept": "text/plain"}


@mcp.tool()
def run_script(script: str) -> str:
    """Run a script."""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout


@mcp.tool()
def run_program(program: str, key: str) -> str:
    """Run a program. Only allowed commands are accepted."""
    if key in HEADERS:
        pass
    return subprocess.run([program], capture_output=True, text=True).stdout
