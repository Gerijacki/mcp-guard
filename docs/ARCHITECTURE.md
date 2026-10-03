# Architecture

mcp-guard is a static analyzer. It never runs the scanned server. The design goals, in order: **low false positives**, **single static binary** (pure Go, no cgo, one dependency: `gopkg.in/yaml.v3`), **fast enough for pre-commit**, and **easy to extend**.

## Pipeline

```
cli ──> config ──> scanner.Scan
                     │ walk files (skip deps, build output, tests, --ignore globs, binaries, >1 MiB)
                     │ phase 1, parallel:  source.NewFile + extract.Extract (tools, funcs, servers)
                     │                      then an index of function definitions across files
                     │ phase 2, parallel:  rules[*].Check per file (+ calls into other files noted),
                     │                      suppress  (inline "mcp-guard:ignore" comments)
                     │ phase 3, rounds:    helpers defined in other files, one defining file at a time
                     └ postprocess          severity overrides, min severity, dedupe, fingerprints, sort
                   ──> baseline filter ──> report.Write (text | json | sarif | markdown | github) ──> exit code
```

The three phases make the result independent of scheduling: every decision that could depend on which worker runs first (which tool a shared helper is credited to, which duplicate is dropped) is taken on sorted input. Trees larger than `MaxIndexBytes` (256 MiB) skip the index and run phases 1 and 2 file by file in a streaming fashion. A panic or timeout in an extractor or rule skips only that file, with a warning.

## Packages

| Package | Responsibility |
|---|---|
| `cmd/mcp-guard` | `main`: calls `cli.Run` and exits with its code. |
| `internal/cli` | Subcommands (`scan`, `tools`, `lock`, `rules`, `version`), flag parsing (flags may follow the path), config/flag precedence, `--baseline`, `--changed-since`, exit codes. |
| `internal/config` | `.mcp-guard.yaml` loading (unknown keys rejected), discovery up to the git root, path overrides, rule extensions. |
| `internal/baseline` | Baseline files: accepted findings by fingerprint. |
| `internal/lock` | Lock files: hashes of tool definitions and server launch commands (MCPG016). |
| `internal/source` | `File` (content, lines, tools, servers), `Tool`, `Language`, and a **small language-aware lexer**: skipping strings/comments, bracket matching, splitting call arguments, parsing string literals (escapes, concatenation, Python prefixes), grouping lines into statements. |
| `internal/extract` | Finds MCP tools, resources and prompts per language and SDK, the functions defined in each file (helpers), and servers in MCP client configs (JSON/JSONC, YAML, TOML). |
| `internal/rules` | `Rule` interface, the built-in rules (`mcpgNNN_*.go`), the taint-lite engine (`taint.go`), helper summaries (`helpers.go`), `extend:` support, YAML custom rules. |
| `internal/scanner` | File walking, the three-phase parallel pipeline, the cross-file function index, ignores, suppression comments, post-processing. |
| `internal/report` | Text (colored when stdout is a TTY), JSON, SARIF 2.1.0 (GitHub code scanning compatible), Markdown, GitHub workflow annotations. |
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
    Kind                  string        // "" tool, "resource" or "prompt"
    FixedParams           []string      // int/float/bool/Literal/enum parameters: validated by the schema, never tainted
    Receiver              string        // the server object it was registered on ("mcp", "server")
}
```

`File.Funcs` lists every function defined in the file (name, parameters, body range). It is what makes helper summaries possible.

| SDK / framework | Recognized patterns |
|---|---|
| Python SDK / FastMCP | `@x.tool(...)` (and bare `@tool`) decorators, `@x.resource(...)`, `@x.prompt()`, `x.add_tool(fn, ...)`, `Tool.from_function(fn)`, low-level `@server.call_tool()` (dispatcher) and `types.Tool(name=..., description=...)` |
| TypeScript SDK | `server.tool(name, [desc], [schema], handler)`, `server.registerTool(name, config, handler)`, the `resource`/`prompt` variants, `setRequestHandler(CallToolRequestSchema, ...)`, `{ name, description, inputSchema }` objects, fastmcp's `addTool({ ..., execute })` |
| mark3labs/mcp-go | `mcp.NewTool(...)` with `WithDescription`/`WithString`/`With*HintAnnotation`, `s.AddTool(tool, handler)`, `AddPrompt`, `AddResource` with inline or named handlers |
| Official Go SDK | `mcp.AddTool(server, &mcp.Tool{Name, Description}, handler)` |

Handlers referenced by name are resolved within the same file. `Params` excludes framework-injected values (`ctx: Context`, `context.Context`). Registrations are located in the *skeleton* of the file (comments and string contents blanked), so example code inside docstrings or template strings is not mistaken for a tool.

## Taint-lite

Rules that need dataflow (MCPG001, 004, 005, 009, 010, 012 and custom `requires-tainted-input` rules) use `walkTaint` (`internal/rules/taint.go`):

1. The tool's `Params` start as tainted.
2. Statements of the handler body are visited **in order**. Each rule inspects a statement with the current taint set (sink matching).
3. Assignments (`x = ...`, `const {a, b} = ...`, `a, err := ...`, `for x in ...`, `with f() as x`, `d["k"] = ...`, `self.x = ...`, `xs.append(...)`) whose right-hand side mentions a tainted identifier taint the left-hand side, unless the right-hand side calls a rule-specific **sanitizer**, in which case the target becomes clean. A clean overwrite at the top level of the handler (`cmd = "ls"`) also clears the taint; inside a branch it does not, because it may not run.

Identifier matching ignores attribute access, so `os.path` does not match a parameter called `path`.

Guard evidence (a path check, an allowlist, `shlex.quote`) is searched in the handler's *code*: comments and a leading docstring are removed first, so prose such as "validates the path" cannot silence a finding.

### Helper summaries (`internal/rules/helpers.go`)

A tool that hands a tainted value to a helper is analyzed *through* the helper: for each call whose arguments are tainted, a synthetic view of the helper (its body, with the receiving parameters tainted, plus the caller's guard code) is run through the same rules, so the finding lands on the real sink and the tool is shown as `tool (via helper)`. Same-file helpers are resolved directly. A function defined in another file is followed only when exactly one definition of that name exists in the scan and the caller shows it knows that file (an import mentioning the module for Python/TypeScript, the same directory for Go). A value that was checked in the caller (membership test, regex match, `startswith`…) is not followed. Depth is limited to three calls.

### Known limitations (by design, for now)

- **Name-based resolution:** helpers are matched by name, not by import graph or types. Ambiguous names are skipped, which favors precision over recall. Methods called through other receivers, aliases (`from x import f as g`) and dynamic dispatch are not followed.
- **Flow-insensitive to branches:** a check in one `if` branch counts for the whole handler (favoring fewer false positives).
- **Heuristic parsing:** unusual formatting (e.g. a return type containing `{` before a TS arrow body) can make extraction miss a tool.
- **No cross-file config for MCPG008:** auth configured in another module is not seen.
- **Static descriptions only:** a description built at runtime (f-strings, constants from another module) is invisible to MCPG007 and MCPG016.

The planned upgrade path is a proper AST (tree-sitter via a pure-Go runtime, or per-language parsers) behind the same `extract` → `Tool` interface, so rules would not need to change.

## Adding a built-in rule

1. Create `internal/rules/mcpgNNN_<name>.go` implementing `Rule` (`Meta()` + `Check()`), and register it in `Builtin()` in `rules.go`. A taint-based rule should also implement `ToolChecker` (`CheckTools`) and iterate `taintBodies(f)` so that helper summaries apply, and add a cheap `containsAny` pre-filter at the top of `Check`.
2. Add fixtures under `testdata/rules/MCPGNNN/{vulnerable,safe}/`, ideally one per language, and pin the expected counts in `wantCounts` in `rules_test.go`.
3. Add `docs/rules/MCPGNNN.md` and a row in the README rules table.
4. Run `go run ./tools/accuracy` (the pinned real-world corpus in `benchmark/corpus.yaml`) and review any change in findings before updating the expectations with `-update`.

## Quality gates

| Gate | Where | Catches |
|---|---|---|
| Fixture tests | `internal/rules/rules_test.go` | exact finding counts per vulnerable/safe fixture |
| Metamorphic tests | `internal/rules/metamorphic_test.go` | findings that change under comments, blank lines, CRLF or renamed parameters; non-idempotent rules |
| Golden files | `internal/extract` and `internal/report` (`-update` to refresh) | any change in what is extracted or in the text/JSON/SARIF/Markdown/GitHub output; SARIF conformance is checked structurally |
| End-to-end | `cmd/mcp-guard/main_test.go` | the built binary: exit codes, every rule firing on the example server, the repo scanning clean |
| Accuracy benchmark | `tools/accuracy`, `benchmark/corpus.yaml`, CI job `accuracy` | new false positives or lost detections on real MCP repositories at pinned commits; every finding is labelled tp/fp and the per-rule precision is gated |
| SDK drift canary | `.github/workflows/canary.yml` (weekly) | SDKs changing their registration API (extracted tools drop on default branches), a broken published Action |
| Fuzzing | `FuzzAnalyze`, CI job `fuzz` | panics, invalid positions, non-idempotent rules, and findings that change when a comment line is added |
| Pathological inputs | `TestPathologicalInputs` | super-linear behavior on 1 MiB adversarial files |
| Per-file time budget and panic recovery | `scanner.Options.FileTimeout` | anything the above missed: the file is skipped with a warning (and `--strict` can turn that into a failure) |

## Output stability

- `Finding.Fingerprint` hashes rule, file, tool, snippet and message (not the line number), so it survives unrelated edits; identical findings repeated in one file get an occurrence index. It is exported as SARIF `partialFingerprints` and used by baselines.
- The JSON field names and SARIF rule IDs are part of the public interface: changing them is a breaking change.
