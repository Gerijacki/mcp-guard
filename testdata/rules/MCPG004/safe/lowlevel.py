import subprocess

import mcp.types as types
from mcp.server import Server

server = Server("ops")
ALLOWED_COMMANDS = {"uptime": ["uptime"], "disk": ["df", "-h"]}


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "run":
        argv = ALLOWED_COMMANDS[arguments["cmd"]]
        out = subprocess.run(argv, capture_output=True, text=True)
        return [types.TextContent(type="text", text=out.stdout)]
    raise ValueError(name)
