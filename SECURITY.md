# Security policy

## Reporting a vulnerability in mcp-guard

Please **do not open a public issue** for vulnerabilities in mcp-guard itself, for example a crafted repository that makes the scanner crash, hang, write outside its output path, or inject content into reports.

Report it privately through [GitHub Security Advisories](https://github.com/Gerijacki/mcp-guard/security/advisories/new). You should get an acknowledgement within a few days, and we will coordinate a fix and disclosure timeline with you.

## Scope

- In scope: the `mcp-guard` binary, its GitHub Action and release artifacts.
- Out of scope: vulnerabilities in the MCP servers that mcp-guard scans (report those to their maintainers) and missed detections (open a regular issue, since those are feature requests).

## Release integrity

Release archives, checksums and the container image have signed build provenance (verify with `gh attestation verify`) and SPDX SBOMs. See [docs/installation.md](docs/installation.md#verifying-releases). The scanner treats scanned repositories as untrusted input: each file has an analysis time budget, report snippets escape control and invisible characters, and the lexer, extractors and rules are fuzzed in CI.

## Supported versions

Only the latest release receives security fixes.
