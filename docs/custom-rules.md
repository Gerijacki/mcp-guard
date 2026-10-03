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
    scope: tool-body                 # file (default) | tool-body | tool-description | tool-name | tool-body-absent | config-server
    languages: [python, typescript]  # optional: python, typescript/javascript, go, json, yaml, toml, env
    pattern: 'admin\.internal\.acme\.com'   # Go regular expression (RE2 syntax)
    requires-tainted-input: false    # tool-body only: the statement must use tool input
    sanitizers: ['\bsanitize\(']     # tool-body + requires-tainted-input: assignments from these stop carrying tool input
    tools: '^(delete|drop)_'         # tool-* scopes: only tools whose name matches
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
| `tool-name` | the tool name, e.g. for naming policies | tool name | empty |
| `tool-body-absent` | tools whose handler does **not** match the pattern ("every tool must call `audit_log`"); reported at the tool declaration | tool name | empty |
| `config-server` | `command args… url` of every server in MCP client configs (`mcp.json`…) | server name | empty |

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

Require every destructive tool to write an audit record:

```yaml
rules:
  - id: ACME004
    severity: medium
    scope: tool-body-absent
    tools: '^(delete|drop|remove)_'
    pattern: '\baudit_log\s*\('
    message: "Tool {tool} does not call audit_log()"
```

Forbid launching servers with auto-confirmed installs in client configs:

```yaml
rules:
  - id: ACME005
    scope: config-server
    pattern: '\bnpx\s+(-y|--yes)\b'
    message: "Server {tool} auto-installs packages on launch"
```

## Teaching the built-in rules your helpers

The built-in taint rules (MCPG001, 004, 005, 009, 010 and 012) cannot know that your `safe_join()` confines a path or that `storage.read()` touches the file system. Add them in `.mcp-guard.yaml`:

```yaml
extend:
  MCPG001:
    sanitizers: ['\bsafe_join\s*\(']      # assignments from these stop being tainted, and a handler mentioning one is considered guarded
    sinks: ['\bstorage\.read\s*\(']      # extra operations that must not receive a tool parameter
  MCPG004:
    sanitizers: ['\bquote_arg\s*\(']
```

Patterns are Go regular expressions. Extra sinks are reported with the rule's usual message and a medium-to-critical severity matching the rule.

Check your rules with `mcp-guard rules list --rules path/to/rules` and `mcp-guard rules explain ACME002 --rules path/to/rules`.
