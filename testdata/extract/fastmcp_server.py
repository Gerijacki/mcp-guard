from typing import Annotated

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

mcp = FastMCP("files")


@mcp.tool()
def read_file(path: str, ctx: Context) -> str:
    """Read a text file.

    Returns the file content.
    """
    with open(path) as fh:
        return fh.read()


@mcp.tool(
    name="delete_file",
    description="Delete a file from disk",
    annotations=ToolAnnotations(destructiveHint=True),
)
async def remove(self, target: Annotated[str, Field(description="File to delete")]) -> str:
    import os

    os.remove(target)
    return "ok"


@mcp.tool
def ping() -> str: return "pong"


def summarize(text: str, max_words: int = 50) -> str:
    """Summarize text."""
    return " ".join(text.split()[:max_words])


mcp.add_tool(summarize, name="summarize_text")
