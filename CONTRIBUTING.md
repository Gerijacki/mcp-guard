# Contributing to mcp-guard

Thanks for helping make MCP servers safer. Contributions of every size are welcome: false-positive reports, new detections, support for more frameworks, docs.

## Reporting false positives and missed detections

These are the most valuable issues. Please include:

- a minimal code snippet (or a link to the public repository and line),
- the output of `mcp-guard version` and the command you ran,
- what you expected and why.

## Development

Requirements: Go 1.23 or newer. No other tools are needed.

```sh
go test ./...                              # unit + fixture tests (add -short to skip slow ones)
go vet ./...
go run ./tools/accuracy                    # real-world accuracy benchmark (clones repos)
go test ./internal/rules -run '^$' -fuzz FuzzAnalyze -fuzztime 60s   # fuzzing
go run ./cmd/mcp-guard scan examples/vulnerable-server
```

Project layout and design are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Adding or changing a rule

1. Implement it in `internal/rules/` (one file per rule) and register it in `Builtin()`.
2. Add `vulnerable` **and** `safe` fixtures under `testdata/rules/<ID>/`, covering Python, TypeScript and Go where the rule applies. Safe fixtures should be realistic near-misses (the correct way to do the same thing), not unrelated code.
3. Pin the expected finding count for each vulnerable fixture in `internal/rules/rules_test.go`.
4. Document it in `docs/rules/<ID>.md` and the README table.
5. Run the real-world accuracy benchmark: `go run ./tools/accuracy`. It scans public MCP repositories pinned in `benchmark/corpus.yaml` and fails when the number of extracted tools or findings changes. If the change is an intended improvement, review every new or missing finding, then run `go run ./tools/accuracy -update` and explain the difference in the pull request. New corpus entries (popular MCP servers) are welcome.

Never commit real credentials, not even revoked ones. Tests for known secret formats build tokens at runtime (see `TestKnownSecretFormats`).

### Style

- Match the surrounding code; run `gofmt`.
- Keep the binary dependency-free apart from `gopkg.in/yaml.v3`, and avoid cgo.
- Prefer precision over recall: a noisy security linter gets uninstalled.

## Commit messages and pull requests

Use short imperative subjects ("Add MCPG009 for SSRF in fetch tools"). One logical change per pull request; include tests.

By contributing you agree that your contributions are licensed under the MIT License.
