## What and why

<!-- What does this change and why is it needed? Link issues with "Fixes #123". -->

## Checklist

- [ ] `go test ./...`, `go vet ./...` and `gofmt -l .` are clean
- [ ] Rule changes include `vulnerable` **and** `safe` fixtures and updated counts in `internal/rules/rules_test.go`
- [ ] Rule changes were checked against at least one real MCP server repository for false positives (mention results below)
- [ ] Docs updated (`docs/rules/`, README) if behavior changed
- [ ] No real credentials or personal data in fixtures

## False-positive check

<!-- e.g. "Scanned modelcontextprotocol/servers and mark3labs/mcp-go: 0 new findings" -->
