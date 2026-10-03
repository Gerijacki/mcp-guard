import subprocess

import mcp.types as types
from mcp.server import Server

server = Server("ops")


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "run":
        out = subprocess.run(arguments["cmd"], shell=True, capture_output=True, text=True)
        return [types.TextContent(type="text", text=out.stdout)]
    raise ValueError(name)
