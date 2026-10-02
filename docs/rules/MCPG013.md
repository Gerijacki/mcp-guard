# MCPG013: secret-in-logs-or-output

**Default severity:** medium (high when returned to the model) · **CWE:** [CWE-532](https://cwe.mitre.org/data/definitions/532.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html) · **OWASP:** [MCP01, LLM02, ASI03](../owasp.md)

A credential read from the environment (`API_KEY = os.environ["…"]`, `process.env.TOKEN`, `os.Getenv`) is printed, logged or returned from a tool, or the whole environment is dumped. Logs reach third parties, stdout is the protocol channel on stdio servers, and anything a tool returns enters the model's context, where a prompt injection can ask for it.

## Vulnerable

```python
API_KEY = os.environ["SERVICE_API_KEY"]

@mcp.tool()
def call_api(query: str) -> str:
    log.info(f"calling with key {API_KEY}")
```

## Fixed

```python
log.info("calling (key configured: %s)", bool(API_KEY))
```

Log only presence or a masked prefix, and return an allowlist of non-secret settings instead of `os.environ`.

## How it is detected

Variables assigned from environment reads whose variable or key name looks like a credential, plus tool arguments named like one (these only count when logged: echoing back what the model supplied is not a leak), reaching a logging call, `print`/`console.log`/`fmt.Print`, or a `return`. Statements that mask, compare or measure the value (`bool(key)`, `key[:4]`, `len(key)`, `key != ""`) are ignored.
