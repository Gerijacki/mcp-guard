import mcp.types as types
from mcp.server.lowlevel import Server

server = Server("shell")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="run",
            description="Run a command",
            inputSchema={"type": "object", "properties": {"cmd": {"type": "string"}}},
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "run":
        cmd = arguments["cmd"]
        return [types.TextContent(type="text", text=cmd)]
    raise ValueError(name)
