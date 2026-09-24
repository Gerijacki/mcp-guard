# MCPG006: unscoped-destructive-tool

**Default severity:** medium · **CWE:** [CWE-749](https://cwe.mitre.org/data/definitions/749.html), [CWE-770](https://cwe.mitre.org/data/definitions/770.html) · **OWASP:** [MCP02, LLM06, ASI02](../owasp.md)

The tool is destructive: it declares `destructiveHint: true`, or its name says it deletes, drops, kills, terminates, executes, transfers or deploys. Its handler has no guard at all: no confirmation step, no allowlist of targets, no dry-run, no size or rate limit. One hallucinated or injected call can do irreversible damage, and an agent loop can repeat it hundreds of times.

## Vulnerable

```python
@mcp.tool()
def delete_user(user_id: str) -> str:
    db.users.delete_one({"_id": user_id})
    return "deleted"
```

## Fixed

```python
@mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
def delete_user(user_id: str, confirm: bool = False) -> str:
    """Delete a user account. Requires confirm=true."""
    if not confirm:
        return f"This will permanently delete {user_id}. Call again with confirm=true."
    db.users.delete_one({"_id": user_id})
    return "deleted"
```

Better still, use [MCP elicitation](https://modelcontextprotocol.io/specification/draft/client/elicitation) to ask the *user* rather than the model. Other options: restrict targets to an allowlist or sandbox, cap how many items one call may affect, and rate-limit. Always declare `destructiveHint: true` so clients can require approval.

## How it is detected

Tools with a handler whose `destructiveHint` is `true`, or whose name contains a destructive verb, and whose handler does not mention confirmation, dry-run, allowlists, validation, sandboxes, limits, quotas, throttling or approval. Tools with `readOnlyHint: true` or an explicit `destructiveHint: false` are skipped.
