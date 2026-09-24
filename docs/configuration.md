# Configuration

mcp-guard works with zero configuration. Everything below is optional.

## Precedence

1. Command-line flags
2. The config file (`--config`, or `.mcp-guard.yaml` / `.mcp-guard.yml` in the scanned directory)
3. Built-in defaults

List-valued settings (`disable`, `ignore`, `rules`) from the config file and flags are **combined**.

## `.mcp-guard.yaml` reference

```yaml
# Exit with code 1 when a finding has at least this severity.
# critical | high | medium | low | info | none           (default: high)
fail-on: high

# Hide findings below this severity. "info" also shows quality hints such as
# tools without a description.                            (default: low)
min-severity: low

# Rules to turn off entirely.
disable:
  - MCPG006

# Change the severity of every finding of a rule.
severity:
  MCPG002: low
  MCPG008: high

# Paths to skip, relative to the scanned directory (glob syntax below).
ignore:
  - examples/
  - "**/generated/**"
  - "*.min.js"

# Also scan test files and directories (skipped by default).   (default: false)
include-tests: false

# Custom rule files or directories, relative to this config file.
rules:
  - .mcp-guard/rules/
```

Unknown keys are rejected, so a typo like `fail_on` fails loudly instead of being silently ignored.

## Command-line flags

`mcp-guard scan [path] [flags]`. Flags may come before or after the path.

| Flag | Default | Description |
|---|---|---|
| `--format`, `-f` | `text` | `text`, `json` or `sarif` |
| `--output`, `-o` | stdout | Write the report to a file (colors are disabled) |
| `--fail-on` | `high` | Minimum severity that makes the exit code 1, or `none` |
| `--min-severity` | `low` | Hide findings below this severity |
| `--disable` | | Rule IDs to disable, comma-separated, repeatable |
| `--ignore` | | Glob to skip, repeatable |
| `--rules` | | Custom rule file or directory, repeatable |
| `--include-tests` | `false` | Also scan tests |
| `--config` | auto | Config file path |
| `--no-color` | `false` | Disable ANSI colors (also honored: the `NO_COLOR` environment variable) |

Other commands: `mcp-guard rules [list]`, `mcp-guard rules explain <ID>` (both accept `--rules` to include custom rules), and `mcp-guard version`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage or runtime error (bad flag, unreadable path, invalid config or custom rule) |

## What gets scanned

- **Languages:** Python (`.py`), TypeScript/JavaScript (`.ts .tsx .mts .cts .js .jsx .mjs .cjs`), Go (`.go`), JSON/JSONC (MCP client configs and any other JSON), YAML, TOML and `.env` files (secrets).
- **Always skipped:**
  - directories: `.git`, `node_modules`, `vendor`, virtualenvs, `dist`, `build`, caches…
  - lockfiles, `*.min.js`, `*.d.ts`
  - binary files and files over 1 MiB
- **Skipped unless `--include-tests`:**
  - directories: `test/`, `tests/`, `__tests__/`, `testdata/`, `fixtures/`, `spec/`, `e2e/`, `__mocks__/`
  - files: `*_test.go`, `test_*.py`, `*_test.py`, `conftest.py`, `*.test.ts`, `*.spec.js`…
- Each file has a 10-second analysis budget. A file that exceeds it is skipped with a warning on stderr instead of hanging the scan.

## Glob syntax (`ignore`, `--ignore`)

| Pattern | Matches |
|---|---|
| `examples` / `examples/` | the `examples` directory (at any depth) and everything inside it |
| `*.gen.ts` | files with that suffix at any depth |
| `src/*.py` | `.py` files directly inside `src/` |
| `src/**/*.py` | `.py` files anywhere under `src/` |
| `**/fixtures/**` | anything under any `fixtures` directory |

A pattern without `/` matches a name at any depth. A pattern with `/` is anchored at the scanned directory.

## Inline suppression

Add `mcp-guard:ignore` in a comment on the reported line or the line above. Optionally list the rule IDs it applies to (recommended) and a reason:

```python
# mcp-guard:ignore MCPG004 -- runs in a disposable sandbox container
subprocess.run(cmd, shell=True)
```

```ts
const html = await fetch(url); // mcp-guard:ignore MCPG002
```

Without rule IDs, all findings on that line are suppressed. Rule IDs must follow the marker directly; other upper-case words are treated as IDs too.

## Custom rules

See [custom-rules.md](custom-rules.md).
