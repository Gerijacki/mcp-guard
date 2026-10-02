# MCPG011: unpinned-or-risky-server-launch

**Default severity:** medium (low for unpinned versions, high for remote scripts and privileged containers) · **CWE:** [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html) · **OWASP:** [MCP04, LLM03, ASI04](../owasp.md)

This rule reads MCP **client configs** (`mcp.json`, `claude_desktop_config.json`, `.vscode/mcp.json`…). It flags servers launched in a way that cannot be reviewed or pinned:

- `npx`/`bunx`/`pnpm dlx`/`uvx`/`pipx run` without a version, or at `@latest`.
- `docker run` with no tag or `:latest` (a `@sha256:` digest is fine).
- `bash -c "curl … | sh"` and similar remote scripts.
- Containers started with `--privileged`, `--cap-add=ALL`, the Docker socket, the host root, or the host PID/IPC namespace (and `--network host`, at medium).
- Remote servers reached over plain `http://` (loopback is fine).

## Vulnerable

```json
{ "mcpServers": { "search": { "command": "npx", "args": ["-y", "some-search-mcp"] } } }
```

## Fixed

```json
{ "mcpServers": { "search": { "command": "npx", "args": ["-y", "some-search-mcp@1.4.2"] } } }
```

Update the pin on purpose, after reading the changelog, instead of on every launch.

## How it is detected

The extracted `command`, `args` and `url` of each server entry. Local paths, `file:` and git references are not reported. Secrets placed in `args` or in the URL are reported by [MCPG003](MCPG003.md).
