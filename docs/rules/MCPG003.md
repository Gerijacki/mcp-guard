# MCPG003: hardcoded-secret

**Default severity:** critical (known formats, config credentials), high (generic matches) · **CWE:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-312](https://cwe.mitre.org/data/definitions/312.html) · **OWASP:** [MCP01, LLM02, ASI03](../owasp.md)

An API key, token, password or private key is written in clear text in server source code, an MCP client configuration or an env file. MCP configs are copied between machines, pasted into READMEs and issues, and committed to dotfiles repos. MCP servers usually hold broad credentials (GitHub, cloud, databases, Slack), so a leaked key gives an attacker the same power as the agent.

## Vulnerable

```json
{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_live_token_pasted_here" }
    }
  }
}
```

## Fixed

Reference the environment or let the client prompt for the secret:

```json
"env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${env:GITHUB_TOKEN}" }
```

```jsonc
// VS Code .vscode/mcp.json
"inputs": [{ "type": "promptString", "id": "github_token", "password": true }],
"servers": { "github": { "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${input:github_token}" } } }
```

In server code, read credentials from the environment or a secret manager at startup. **Rotate any secret that was committed**: removing it from the latest commit does not remove it from git history.

## How it is detected

- **Known formats:** Anthropic, OpenAI, GitHub, GitLab, AWS, Slack, Stripe, Google, Hugging Face, npm, Notion, Linear, SendGrid keys and PEM private keys.
- **Connection strings** with an embedded password (`postgresql://user:pass@host`), ignoring local-development hosts and default passwords.
- **Authorization headers** with literal bearer/basic tokens.
- **MCP client configs:** any high-entropy literal in a server's `env` or `headers`, whatever the variable is called.
- **Generic assignments** such as `api_key = "..."` or `"SECRET": "..."`, filtered by entropy, character mix and a placeholder list (`your-key-here`, `${VAR}`, `<token>`, `changeme`, …).

Snippets in reports are redacted. Files named like `*.example`, `*.sample` or `*.template` are only checked for known formats, and test files are skipped unless `--include-tests` is set.
