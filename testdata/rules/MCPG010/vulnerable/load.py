import importlib
import pickle

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("loader")


@mcp.tool()
def load_state(blob: bytes) -> str:
    """Restore a saved state."""
    return str(pickle.loads(blob))


@mcp.tool()
def load_config(text: str) -> str:
    """Parse a YAML config."""
    return str(yaml.load(text, Loader=yaml.Loader))


@mcp.tool()
def run_plugin(name: str) -> str:
    """Run a plugin by module name."""
    return importlib.import_module(name).run()
