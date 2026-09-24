# Architecture

mcp-guard is a static analyzer. It never runs the scanned server. The design goals, in order: **low false positives**, **single static binary** (pure Go, no cgo, one dependency: `gopkg.in/yaml.v3`), **fast enough for pre-commit**, and **easy to extend**.

## Pipeline

```
cli ──> config ──> scanner.Scan
                     │ walk files (skip deps, build output, tests, --ignore globs, binaries, >1 MiB)
                     │ per file, in parallel:
                     │   source.NewFile      content + line index + language
                     │   extract.Extract     MCP tools / client-config servers
                     │   rules[*].Check      findings
                     │   suppress            inline "mcp-guard:ignore"
                     └ postprocess           severity overrides, min severity, dedupe, fingerprint, sort
                   ──> report.Write (text | json | sarif)  ──> exit code from --fail-on
```

## Packages

| Package | Responsibility |
|---|---|
| `cmd/mcp-guard` | `main`: calls `cli.Run` and exits with its code. |
| `internal/cli` | Subcommands (`scan`, `rules`, `version`), flag parsing (flags may follow the path), config/flag precedence, exit codes. |
| `internal/config` | `.mcp-guard.yaml` loading, with unknown keys rejected. |
| `internal/source` | `File` (content, lines, tools, servers), `Tool`, `Language`, and a **small language-aware lexer**: skipping strings/comments, bracket matching, splitting call arguments, parsing string literals (escapes, concatenation, Python prefixes), grouping lines into statements. |
| `internal/extract` | Finds MCP tools per language and SDK, and servers in MCP client JSON configs. |
| `internal/rules` | `Rule` interface, the built-in rules (`mcpgNNN_*.go`), taint-lite helper, YAML custom rules. |
| `internal/scanner` | File walking, parallel execution, ignores, suppression, post-processing. |
| `internal/report` | Text (colored when stdout is a TTY), JSON, SARIF 2.1.0 (GitHub code scanning compatible). |
| `internal/finding` | `Finding`, `Severity`, fingerprints, sorting. |

## Tool extraction

`source.Tool` is the central abstraction that makes the rules MCP-aware:

```go
type Tool struct {
    Name, Description string
    ParamDescriptions []string          // shown to the model too
    Params            []string          // identifiers in the handler holding model input
    Annotations       map[string]string // "destructivehint" -> "true"
    Line, DescriptionLine int
    BodyFrom, BodyTo      int           // handler body byte range
    Dispatcher            bool          // low-level call_tool handler
}
```

| SDK / framework | Recognized patterns |
|---|---|
| Python SDK / FastMCP | `@x.tool(...)` decorators, `x.add_tool(fn, ...)`, low-level `@server.call_tool()` (dispatcher) and `types.Tool(name=..., description=...)` |
| TypeScript SDK | `server.tool(name, [desc], [schema], handler)`, `server.registerTool(name, config, handler)`, `setRequestHandler(CallToolRequestSchema, ...)`, `{ name, description, inputSchema }` objects |
| mark3labs/mcp-go | `mcp.NewTool(...)` with `WithDescription`/`WithString`/`With*HintAnnotation`, `s.AddTool(tool, handler)` with inline or named handlers |
| Official Go SDK | `mcp.AddTool(server, &mcp.Tool{Name, Description}, handler)` |

Handlers referenced by name are resolved within the same file. `Params` excludes framework-injected values (`ctx: Context`, `context.Context`).

## Taint-lite

Rules that need dataflow (MCPG001, 004, 005 and custom `requires-tainted-input` rules) use `walkTaint` (`internal/rules/taint.go`):

1. The tool's `Params` start as tainted.
2. Statements of the handler body are visited **in order**. Each rule inspects a statement with the current taint set (sink matching).
3. Assignments (`x = ...`, `const {a, b} = ...`, `a, err := ...`, `for x in ...`) whose right-hand side mentions a tainted identifier taint the left-hand side, unless the right-hand side calls a rule-specific **sanitizer**, in which case the target becomes clean.

Identifier matching ignores attribute access, so `os.path` does not match a parameter called `path`.

### Known limitations (by design, for now)

- **Intra-procedural:** flows through helper functions in other files are not followed, and a helper is only recognized as a sanitizer if its name matches.
- **Flow-insensitive to branches:** a check in one `if` branch counts for the whole handler (favoring fewer false positives).
- **Heuristic parsing:** unusual formatting (e.g. a return type containing `{` before a TS arrow body) can make extraction miss a tool.
- **No cross-file config for MCPG008:** auth configured in another module is not seen.

The planned upgrade path is a proper AST (tree-sitter via a pure-Go runtime, or per-language parsers) behind the same `extract` → `Tool` interface, so rules would not need to change.

## Adding a built-in rule

1. Create `internal/rules/mcpgNNN_<name>.go` implementing `Rule` (`Meta()` + `Check()`), and register it in `Builtin()` in `rules.go`.
2. Add fixtures under `testdata/rules/MCPGNNN/{vulnerable,safe}/`, ideally one per language, and pin the expected counts in `wantCounts` in `rules_test.go`.
3. Add `docs/rules/MCPGNNN.md` and a row in the README rules table.
4. Run the scanner against a few real MCP server repositories and check for false positives before merging.

## Output stability

- `Finding.Fingerprint` hashes rule, file, tool, snippet and message (not the line number), so it survives unrelated edits. It is exported as SARIF `partialFingerprints`.
- The JSON field names and SARIF rule IDs are part of the public interface: changing them is a breaking change.
