# MCPG010: unsafe-deserialization

**Default severity:** critical (high for dynamic imports) · **CWE:** [CWE-502](https://cwe.mitre.org/data/definitions/502.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html) · **OWASP:** [MCP05, LLM05, ASI05](../owasp.md)

A model-controlled value is passed to a deserializer that can build arbitrary objects, or decides which module is loaded. `pickle.loads`, `marshal`, `yaml.load` without `SafeLoader`, `torch.load`, `numpy.load(allow_pickle=True)`, `importlib.import_module(name)` and `require(name)` all run attacker-chosen code.

## Vulnerable

```python
@mcp.tool()
def load_state(blob: bytes) -> str:
    return str(pickle.loads(blob))

@mcp.tool()
def run_plugin(name: str) -> str:
    return importlib.import_module(name).run()
```

## Fixed

```python
@mcp.tool()
def load_state(blob: str) -> str:
    return str(json.loads(blob))

PLUGINS = {"csv": "plugins.csv", "json": "plugins.json"}

@mcp.tool()
def run_plugin(name: str) -> str:
    return importlib.import_module(PLUGINS[name]).run()
```

Use `yaml.safe_load`, `torch.load(..., weights_only=True)` and `numpy.load` without `allow_pickle`.

## How it is detected

A tainted parameter reaches the first argument of the listed Python, TypeScript or Go sinks. `yaml.load` with a `SafeLoader`, `torch.load(weights_only=True)`, `numpy.load` without `allow_pickle=True` and `require("literal")` are not reported. A handler that checks the value against an `ALLOWED_*` set or restricts the unpickler is skipped.
