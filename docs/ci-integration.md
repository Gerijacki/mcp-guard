# CI integration

mcp-guard is built for CI: it is fast, deterministic, needs no network or API keys, returns meaningful exit codes and writes SARIF.

## GitHub Actions

```yaml
name: mcp-guard
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write # needed only for upload-sarif

jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Gerijacki/mcp-guard@v0
        with:
          fail-on: high
```

What the Action does:

1. downloads the release binary for the runner (Linux, macOS, Windows; x64 or ARM64),
2. writes a SARIF report and uploads it to **code scanning**, so findings appear as pull request annotations and under *Security → Code scanning*,
3. runs the scan again for a readable log, adds a summary to the job page, and fails the step according to `fail-on`.

### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | File or directory to scan |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info` or `none` |
| `min-severity` | `low` | Hide findings below this severity |
| `upload-sarif` | `true` | Upload to code scanning (needs `security-events: write`; not available to pull requests from forks) |
| `sarif-file` | `mcp-guard.sarif` | Where the SARIF report is written (also exposed as the `sarif-file` output) |
| `args` | | Extra flags, e.g. `--disable MCPG006 --include-tests` |
| `version` | `latest` | Release tag such as `v0.1.0`, `latest`, or `source` (build the action's checkout, which needs `actions/setup-go`) |

Pin `version` (e.g. `v0.1.0`) if you want fully reproducible builds. The Action itself is referenced by the major tag `@v0`.

### Private repositories without GitHub Advanced Security

Code scanning uploads need GitHub Advanced Security on private repositories. Set `upload-sarif: "false"`; the log and the job summary still show every finding.

## GitLab CI

```yaml
mcp-guard:
  image:
    name: ghcr.io/gerijacki/mcp-guard:latest
    entrypoint: [""]
  script:
    - mcp-guard scan . --format sarif -o gl-mcp-guard.sarif --fail-on none
    - mcp-guard scan . --fail-on high
  artifacts:
    when: always
    paths: [gl-mcp-guard.sarif]
```

## Any other CI (Jenkins, CircleCI, Azure Pipelines, Buildkite, …)

```sh
curl -sSfL https://raw.githubusercontent.com/Gerijacki/mcp-guard/main/install.sh | BIN_DIR=. sh
./mcp-guard scan . --fail-on high
```

or with Docker:

```sh
docker run --rm -v "$PWD:/src" ghcr.io/gerijacki/mcp-guard:0.1.1 scan . --fail-on high
```

## pre-commit

See [installation.md](installation.md#pre-commit).

## Adopting it on an existing project

Turning on a new security check should not block every pull request on day one:

1. **Observe:** run with `--fail-on none` and review the findings in code scanning.
2. **Triage:** fix real issues. For accepted risks, add `mcp-guard:ignore <ID> -- reason` comments or tune `.mcp-guard.yaml` (`disable`, `severity`, `ignore`). Please report false positives.
3. **Enforce:** switch to `--fail-on critical`, then `high` once the backlog is clear.

## Scanning third-party MCP servers before you install them

Tool descriptions of servers you install end up in your agent's context. Scan them first:

```sh
git clone --depth 1 https://github.com/some-org/some-mcp-server /tmp/some-mcp-server
mcp-guard scan /tmp/some-mcp-server --min-severity medium
```

Pay particular attention to **MCPG007 (tool poisoning)**, and pin the version you reviewed in your client config.
