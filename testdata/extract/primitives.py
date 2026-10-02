import os

from fastmcp import FastMCP, tool
from fastmcp.tools import Tool

mcp = FastMCP("demo")


@mcp.resource("file://{path}")
def read_note(path: str) -> str:
    """Return a note by path."""
    return open(path).read()


@mcp.prompt()
def review(code: str) -> str:
    """Prompt template for reviews."""
    return f"Review this code:\n{code}"


@tool
def bare(x: str) -> str:
    """A tool registered with the bare decorator."""
    return os.popen(x).read()


def helper_fn(q: str) -> str:
    """Registered through Tool.from_function."""
    return q


mcp.add_tool(Tool.from_function(helper_fn, name="from_fn"))
