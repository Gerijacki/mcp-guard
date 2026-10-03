# CLAUDE.md

Guidance for AI coding assistants (Claude Code and similar) working on this repository. Humans: see README.md and CONTRIBUTING.md.

## What this is

`mcp-guard` is an open-source Go CLI that statically scans MCP (Model Context Protocol) servers written in Python, TypeScript/JavaScript and Go, plus MCP client JSON configs, for security issues. It is distributed as a single static binary and a GitHub Action. It outputs text, JSON or SARIF 2.1.0. The goal is real adoption by MCP server authors, so **precision beats recall**: every new heuristic must be checked against real repositories for false positives.

This is a public repository. Never add personal information, real credentials (even revoked ones) or internal URLs.

## Commands

```sh
go build ./...                                   # compile
go test ./...                                    # all tests (fast, no network)
go vet ./...
gofmt -l .                                       # must print nothing
go run ./cmd/mcp-guard scan examples/vulnerable-server   # demo: exits 1 with findings for every rule except MCPG016 (which needs `--lock`)
go run ./cmd/mcp-guard scan . --fail-on none     # dogfood: the repo itself (tests/testdata are skipped by default)
go run ./cmd/mcp-guard tools .                   # what the extractors found (first thing to check for a missed finding)
go test ./internal/report ./internal/extract -update   # refresh golden files after an intended output/extraction change
```

## Architecture (read docs/ARCHITECTURE.md for detail)

`cli` → `config` → `scanner.Scan` (phase 1: `source.NewFile` → `extract.Extract` fills `File.Tools` / `File.Funcs` / `File.Servers`; phase 2: each `rules.Rule.Check` + inline suppression; phase 3: helpers defined in other files) → post-processing → baseline filter → `report.Write`.

- `internal/source`: `File`, `Tool`, `Language` and the tiny lexer (`MatchClose`, `SplitArgs`, `ParseStringLiteral`, `StatementsIn`, `ContainsIdent`). No dependencies on other internal packages.
- `internal/extract`: one file per language (`python.go`, `typescript.go`, `golang.go`) plus `config.go`. Tool bodies are byte ranges (`BodyFrom`/`BodyTo`), always set via `File.SetBody`.
- `internal/rules`: `mcpgNNN_*.go` built-ins, `taint.go` (`walkTaint`: in-order statements, assignment propagation, sanitizer kills), `helpers.go` (helper summaries, same-file and cross-file), `extend.go` (`extend:` config), `custom.go` (YAML rules).
- `internal/scanner`: the 3-phase pipeline, `index.go` (cross-file function index), `suppress.go` (comment-only suppressions). Anything that depends on scheduling must be decided on sorted input: results must not change with `--workers`.
- Rule IDs `MCPG001`–`MCPG017` are public API (SARIF, suppressions, configs). Never renumber them.

## Conventions

- Pure Go, no cgo. The only third-party dependency is `gopkg.in/yaml.v3`. Ask before adding another.
- Keep the Go directive at `go 1.23` for compatibility. `min`/`max` builtins are fine.
- Every rule change needs fixtures in `testdata/rules/<ID>/{vulnerable,safe}/` and an updated exact count in `wantCounts` (`internal/rules/rules_test.go`). Safe fixtures should be near-misses done correctly. Taint-based rules iterate `taintBodies(f)` (tools + helper views) and have a `containsAny` pre-filter; guard evidence is looked up in `f.CodeText(t)` (comments and docstring removed), never in `f.BodyText(t)`.
- Put secret-format tests in Go code with runtime string concatenation (`TestKnownSecretFormats`), never as literal tokens in fixtures, so GitHub push protection and secret scanners are not triggered.
- Snippets are untrusted input: always build them with `snippet()`, which escapes control and invisible characters.
- Messages: one sentence, name the tool and the tainted identifier, and state the vulnerability class.
- Every built-in rule carries CWE and OWASP ids (`Meta.OWASP`, format `MCP05:2025`, `LLM01:2025`, `ASI02:2026`; `TestBuiltinOWASPMapping`). Keep `docs/owasp.md` in sync.
- Update `docs/rules/<ID>.md` and the README rules table when behavior changes.

## Validation against real servers

`go run ./tools/accuracy` scans the public MCP repositories pinned in `benchmark/corpus.yaml` and fails if extracted tools or findings change, if a finding has no label, or if per-rule precision (tp/(tp+fp) over the labels) drops below `min-precision` (CI job `accuracy`). When a heuristic change moves the numbers, inspect every new or missing finding. Only then refresh the expectations with `-update` (new findings are written as `label: todo`; set each to `tp` or `fp` with a note), and justify the change in the commit message. Today every labelled finding is a true positive: keep precision that high. A rule that is noisy on real repositories must be narrowed, not accepted (MCPG017 was cut to single files for that reason). `.github/workflows/canary.yml` runs `-latest` weekly against default branches to detect SDK API drift, and it tests the published Action.

Robustness: `FuzzAnalyze` (CI job `fuzz`) and `TestPathologicalInputs` (skipped with `-short`; CI runs it without `-race`) guard the lexer/extractors against panics and super-linear blowups.

## CI, release and distribution

- `.github/workflows/ci.yml` runs on every push/PR:
  - tests on Linux/macOS/Windows with stable Go, plus Go 1.23 (the `go.mod` minimum)
  - golangci-lint (`.golangci.yml`), govulncheck, `goreleaser check`
  - **dogfood**: the Action from source (`uses: ./`, `version: source`). The repo must scan clean, and `examples/vulnerable-server` must fail with every rule except MCPG016 present in its SARIF.
- `codeql.yml`: CodeQL for Go. `dependabot.yml`: weekly updates for gomod and actions.
- **Release:** push a `vX.Y.Z` tag. `release.yml` runs GoReleaser (`.goreleaser.yaml`), then attests build provenance for the archives, checksums and image (`actions/attest-build-provenance`). SPDX SBOMs come from syft. GoReleaser produces:
  - binaries and archives `mcp-guard_<os>_<arch>` (names must stay stable: `action.yml`, `install.sh` and `install.ps1` depend on them)
  - `checksums.txt`
  - multi-arch GHCR image `ghcr.io/gerijacki/mcp-guard` (`dockers_v2` + `Dockerfile`)

  It then moves the major tag (`v0`) and smoke-tests `install.sh` and the image. Never re-tag a published version; ship a patch release instead.
- **Demo:** `demo/demo.tape` (VHS) is rendered by `demo.yml` (manual trigger or changes under `demo/`) into `docs/demo.gif`, which the workflow commits. Re-run it after changing output formatting.
- Distribution entry points: `install.sh` / `install.ps1` (verify checksums, fail closed), `.pre-commit-hooks.yaml`, `Dockerfile`, `action.yml`.
- Validate locally before pushing: `gofmt -l .`, `go vet ./...`, `go test ./...`, `golangci-lint run`, `goreleaser check`.

## Roadmap ideas (not yet implemented)

- A real parser behind the extractors (tree-sitter via a pure-Go runtime, or per-language parsers) for exact scoping, imports and aliases; name-based helper resolution would then become import-based.
- More SDKs and languages (Java, Kotlin, C#, Rust).
- DNS-rebinding / Origin-validation checks for local HTTP servers.
- Scanning installed third-party servers (npm/PyPI package or Docker image) before adding them to a client.
