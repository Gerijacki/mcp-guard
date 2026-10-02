# Configuration

mcp-guard works with zero configuration. Everything below is optional.

## Precedence

1. Command-line flags
2. The config file (`--config`, or `.mcp-guard.yaml` / `.mcp-guard.yml` in the scanned directory; inside a git repository the parent directories are searched up to the repository root). Globs in `ignore` and `overrides` are always relative to the *scanned* directory, even when the config file was found in a parent
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

# Turn rules off for part of the tree (globs as in `ignore`).
overrides:
  - path: "scripts/**"
    disable: [MCPG006, MCPG013]

# Teach the built-in taint rules your own sinks and sanitizers (see custom-rules.md).
extend:
  MCPG001:
    sanitizers: ['\bsafe_join\s*\(']

# Lock file checked by MCPG016, relative to this config file (see `mcp-guard lock`).
lock: mcp-guard.lock

# Inline suppressions need a reason / are reported when they stop suppressing anything.
require-ignore-reason: false
warn-unused-ignores: false
```

Unknown keys are rejected, so a typo like `fail_on` fails loudly instead of being silently ignored.

## Command-line flags

`mcp-guard scan [path] [flags]`. Flags may come before or after the path.

| Flag | Default | Description |
|---|---|---|
| `--format`, `-f` | `text` | `text`, `json`, `sarif`, `markdown` or `github` (GitHub Actions workflow annotations) |
| `--output`, `-o` | stdout | Write the report to a file (colors are disabled) |
| `--also` | | Another report from the same scan, `format=path`, repeatable (e.g. `--also sarif=out.sarif`) |
| `--fail-on` | `high` | Minimum severity that makes the exit code 1, or `none` |
| `--min-severity` | `low` | Hide findings below this severity |
| `--disable` | | Rule IDs to disable, comma-separated, repeatable |
| `--ignore` | | Glob to skip, repeatable |
| `--rules` | | Custom rule file or directory, repeatable |
| `--include-tests` | `false` | Also scan tests |
| `--baseline` | | Hide findings that are in this baseline file |
| `--write-baseline` | | Write all current findings to a baseline file, exit 0 |
| `--changed-since` | | Scan only files changed since a git ref, plus untracked files |
| `--lock` | | Lock file for MCPG016 |
| `--strict` | `false` | Exit 2 when a file could not be analyzed (unreadable, timed out, internal error) |
| `--require-ignore-reason`, `--warn-unused-ignores` | `false` | See *Inline suppression* |
| `--workers` | CPUs | Files analyzed in parallel |
| `--max-file-size` | 1048576 | Skip larger files (bytes) |
| `--timeout` | `10s` | Analysis budget per file |
| `--config` | auto | Config file path |
| `--no-color` | `false` | Disable ANSI colors (also honored: the `NO_COLOR` environment variable) |

Other commands: `mcp-guard rules [list]`, `mcp-guard rules explain <ID>` (both accept `--rules` to include custom rules), `mcp-guard tools [path]` (what the extractors found: tools, parameters, handler lines, client-config servers; `-f json` too), `mcp-guard lock [path]` (see MCPG016) and `mcp-guard version`.

## Baselines

To adopt mcp-guard on an existing project without fixing everything first:

```sh
mcp-guard scan . --write-baseline mcp-guard.baseline.json   # accept today's findings
mcp-guard scan . --baseline mcp-guard.baseline.json         # CI: fails only on new ones
```

Findings are matched by fingerprint (rule, file, tool, snippet, message; not the line number), so unrelated edits do not resurrect them. Repeated identical lines in one file get distinct fingerprints. The scan reports how many baseline entries no longer occur; refresh the file when you fix things.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage or runtime error (bad flag, unreadable path, invalid config or custom rule), or with `--strict` a file that could not be analyzed |

## What gets scanned

- **Languages:** Python (`.py`), TypeScript/JavaScript (`.ts .tsx .mts .cts .js .jsx .mjs .cjs`), Go (`.go`), JSON/JSONC (MCP client configs and any other JSON), YAML, TOML and `.env` files (secrets).
- **Always skipped:**
  - directories: `.git`, `node_modules`, `vendor`, virtualenvs, `dist`, `build`, caches…
  - lockfiles, `*.min.js`, `*.d.ts`
  - binary files and files over 1 MiB
- **Skipped unless `--include-tests`:**
  - directories: `test/`, `tests/`, `__tests__/`, `testdata/`, `fixtures/`, `spec/`, `e2e/`, `__mocks__/`
  - files: `*_test.go`, `test_*.py`, `*_test.py`, `conftest.py`, `*.test.ts`, `*.spec.js`…
- Each file has a 10-second analysis budget. A file that exceeds it, cannot be read, or makes an extractor fail is skipped with a warning (stderr, and the `warnings` list of the JSON report and the SARIF invocation) instead of hanging or aborting the scan. The report says how many files were skipped and why; `--strict` turns that into exit code 2.
- Source trees up to 256 MiB are analyzed with cross-file helper resolution; larger ones are analyzed file by file (with a warning).

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

Add `mcp-guard:ignore` in a **comment** on the reported line or the line above (the same text inside a string literal does nothing). Optionally list the rule IDs it applies to (recommended) and a reason:

```python
# mcp-guard:ignore MCPG004 -- runs in a disposable sandbox container
subprocess.run(cmd, shell=True)
```

```ts
const html = await fetch(url); // mcp-guard:ignore MCPG002
```

Without rule IDs, all findings on that line are suppressed. Rule IDs must follow the marker directly; other upper-case words are treated as IDs too.

Other forms: `mcp-guard:ignore-next-line MCPG004` (only the following line) and `mcp-guard:ignore-file MCPG006 -- demo server` (the whole file). The reason is whatever follows `--` (or the words after the IDs). With `require-ignore-reason: true` a suppression without one is not honored and a warning is printed; with `warn-unused-ignores: true` suppressions that no longer suppress anything are reported, so they do not rot.

## Custom rules

See [custom-rules.md](custom-rules.md).
