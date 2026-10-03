# MCPG016: definition-changed-since-lock

**Default severity:** high (medium for parameter changes, low for new tools) · **CWE:** [CWE-494](https://cwe.mitre.org/data/definitions/494.html), [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) · **OWASP:** [MCP03, LLM03, ASI04](../owasp.md)

A *rug pull*: a tool is published with a harmless description, reviewed and approved, and later its description is changed to carry instructions for the model. People read a description once; the model reads it every session. The same applies to a client-config entry whose package version, command or URL changes after review.

This rule is **off unless you give it a lock file**. The lock records a fingerprint of everything the model reads about each tool (name, description, parameter descriptions, parameter names, annotations) and of how each client-config server is launched (command, args, URL). Handler code, environment variables and headers are not part of it.

## Workflow

```sh
mcp-guard lock .                      # writes mcp-guard.lock; commit it
mcp-guard scan . --lock mcp-guard.lock   # or set `lock: mcp-guard.lock` in .mcp-guard.yaml
```

When a description changes, the scan reports it (with the previous text), the change is reviewed like code, and the lock is regenerated in the same pull request.

| Change | Severity |
|---|---|
| Description or parameter descriptions changed | high |
| Parameters or annotations changed | medium |
| A client-config server launches differently | high |
| A new tool or server that is not in the lock | low / medium |

## How it is detected

Each tool (and resource, prompt) and server of a scanned file is looked up by `path#name` in the lock; the text and shape hashes are compared. Paths are relative to the scanned directory, so the lock must be generated and checked from the same root. Removed tools are not reported.
