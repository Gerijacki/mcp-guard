import importlib
import json

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("loader")
ALLOWED_PLUGINS = {"csv_export", "json_export"}


@mcp.tool()
def load_state(blob: str) -> str:
    """Restore a saved state (JSON)."""
    return str(json.loads(blob))


@mcp.tool()
def load_config(text: str) -> str:
    """Parse a YAML config."""
    return str(yaml.safe_load(text))


@mcp.tool()
def run_plugin(name: str) -> str:
    """Run an allowed plugin."""
    if name not in ALLOWED_PLUGINS:
        raise ValueError("unknown plugin")
    return importlib.import_module("plugins." + name).run()
