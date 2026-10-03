import shutil

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def cleanup_workspace(confirm: bool = False) -> str:
    """Remove temporary files from the workspace."""
    if not confirm:
        return "pass confirm=true to proceed"
    shutil.rmtree("/tmp/workspace")
    return "done"


@mcp.tool()
def read_report(name: str) -> str:
    """Read a report. Deletes nothing and never overwrites existing files."""
    return name
