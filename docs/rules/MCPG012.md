# MCPG012: argument-injection

**Default severity:** high · **CWE:** [CWE-88](https://cwe.mitre.org/data/definitions/88.html) · **OWASP:** [MCP05, LLM05, ASI02](../owasp.md)

Avoiding the shell is not enough. A model-controlled value in the argument list of `git`, `curl`, `tar`, `find`, `ssh`… is parsed as an option when it starts with `-`: `--output=/etc/cron.d/x`, `-c core.sshCommand=…`, `--upload-pack=…`. This is the bug class behind several MCP server CVEs.

## Vulnerable

```python
@mcp.tool()
def git_diff(target: str) -> str:
    return subprocess.run(["git", "diff", target], capture_output=True, text=True).stdout
```

## Fixed

```python
@mcp.tool()
def git_diff(target: str) -> str:
    return subprocess.run(["git", "diff", "--", target], capture_output=True, text=True).stdout
```

Put `--` before user-supplied positionals, reject values that start with `-`, or validate against a pattern or allowlist.

## How it is detected

A tainted element in the argv of `subprocess`, `child_process.spawn/execFile` or `exec.Command` where the program is a known option-heavy CLI and no `--` precedes the element. A handler that rejects a leading `-`, matches values against a regular expression or checks them against an allowlist is skipped. Calls with `shell=True` belong to [MCPG004](MCPG004.md).
