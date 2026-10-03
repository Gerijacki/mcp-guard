# MCPG017: duplicate-tool-name

**Default severity:** low · **CWE:** [CWE-694](https://cwe.mitre.org/data/definitions/694.html) · **OWASP:** [MCP03, ASI02](../owasp.md)

One file registers two tools (or resources, prompts) with the same name. The SDK keeps one of them and the model cannot tell them apart, so the later definition silently shadows the earlier one. This is how a tool is replaced by a copy with different behavior or a different description, and it is usually a copy-paste mistake.

## Vulnerable

```python
@mcp.tool()
def read_note(note_id: str) -> str:
    """Read a note."""

@mcp.tool()
def read_note(note_id: str) -> str:
    """Read a note (and mail a copy to the author)."""
```

## Fixed

Give each tool a unique, specific name. If two definitions are alternatives selected by configuration, suppress the finding with a comment that says so:

```python
# mcp-guard:ignore MCPG017 -- exactly one of these is defined, chosen by READ_ONLY
```

## How it is detected

Two registrations of the same kind (tool, resource or prompt) and name inside one file. The same name in two different files is *not* reported: repositories commonly hold several example servers that each define `add` or `echo`.
