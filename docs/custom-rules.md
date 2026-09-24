# Custom rules

Custom rules let you encode organization-specific policies ("tools must not call our internal admin API", "never log tool arguments") without changing mcp-guard's code. They run next to the built-in rules and appear in every output format.

Load them with `--rules <file-or-directory>` (repeatable) or from `.mcp-guard.yaml`:

```yaml
rules:
  - .mcp-guard/rules/   # every *.yml / *.yaml inside, recursively
```

## Format

```yaml
rules:
  - id: ACME001                      # required, 3-32 chars: A-Z 0-9 - _ (MCPG* is reserved)
    name: no-admin-api               # optional, defaults to the lower-cased id
    severity: high                   # critical | high | medium | low | info (default: medium)
    scope: tool-body                 # file (default) | tool-body | tool-description
    languages: [python, typescript]  # optional: python, typescript/javascript, go, json, yaml, toml, env
    pattern: 'admin\.internal\.acme\.com'   # Go regular expression (RE2 syntax)
    requires-tainted-input: false    # tool-body only: the statement must use tool input
    unless: ['readonly=True']        # optional: skip matches whose text also matches any of these
    message: "Tool {tool} calls the internal admin API"
    description: Longer explanation shown by `mcp-guard rules explain` and in SARIF.
    remediation: What to do instead.
    cwe: [CWE-284]
    owasp: [MCP02:2025, ASI02:2026]  # optional: OWASP MCP/LLM/Agentic Top 10 ids (docs/owasp.md)
    help-url: https://wiki.acme.example/security/mcp
```

### Scopes

| Scope | Matched against | `{tool}` | `{param}` |
|---|---|---|---|
| `file` | every line of every file of the selected languages | empty | empty |
| `tool-body` | each statement (multi-line calls joined, comments removed) inside MCP tool handlers | tool name | the tainted identifier, when there is one |
| `tool-description` | the tool description plus its parameter descriptions | tool name | empty |

## Examples

Flag tools that send model-controlled URLs to `requests.delete`:

```yaml
rules:
  - id: ACME002
    severity: high
    scope: tool-body
    languages: [python]
    pattern: '\brequests\.delete\s*\('
    requires-tainted-input: true
    message: "Tool {tool} sends an HTTP DELETE to a model-controlled target ({param})"
```

Require a link to your internal review in every tool description:

```yaml
rules:
  - id: ACME003
    severity: low
    scope: tool-description
    pattern: '^'
    unless: ['Reviewed: SEC-\d+']
    message: "Tool {tool} has no security review reference"
```

Check your rules with `mcp-guard rules list --rules path/to/rules` and `mcp-guard rules explain ACME002 --rules path/to/rules`.
