# Installation

mcp-guard is a single static binary with no runtime dependencies. Pick whichever method fits your workflow.

| Method | Command | Updates |
|---|---|---|
| Install script (Linux, macOS) | `curl -sSfL https://raw.githubusercontent.com/Gerijacki/mcp-guard/main/install.sh \| sh` | re-run the script |
| Install script (Windows) | `irm https://raw.githubusercontent.com/Gerijacki/mcp-guard/main/install.ps1 \| iex` | re-run the script |
| Go toolchain | `go install github.com/Gerijacki/mcp-guard/cmd/mcp-guard@latest` | re-run with `@latest` |
| Docker | `docker run --rm -v "$PWD:/src" ghcr.io/gerijacki/mcp-guard` | `docker pull` |
| Prebuilt binaries | [GitHub releases](https://github.com/Gerijacki/mcp-guard/releases) | manual |
| GitHub Action | `uses: Gerijacki/mcp-guard@v0` | follows the `v0` tag |
| pre-commit | see below | `pre-commit autoupdate` |

Check the installation with `mcp-guard version`.

## Install script

`install.sh` detects your OS (Linux/macOS) and architecture (amd64/arm64), downloads the matching release archive, **verifies its SHA-256 against the release's `checksums.txt`**, and installs the binary.

```sh
# latest release into /usr/local/bin (or ~/.local/bin when /usr/local/bin is not writable)
curl -sSfL https://raw.githubusercontent.com/Gerijacki/mcp-guard/main/install.sh | sh

# a specific version into a specific directory
curl -sSfL https://raw.githubusercontent.com/Gerijacki/mcp-guard/main/install.sh | MCP_GUARD_VERSION=v0.1.1 BIN_DIR="$HOME/bin" sh
```

If you prefer not to pipe to a shell, download `install.sh`, read it, then run it.

On Windows, `install.ps1` does the same (checksum included), installs to `%LOCALAPPDATA%\mcp-guard\bin` and adds that folder to your user `PATH`. It accepts the same `MCP_GUARD_VERSION` and `BIN_DIR` environment variables.

## Docker

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to GitHub Container Registry on every release. They are based on `distroless/static` and run as a non-root user.

| Tag | Meaning |
|---|---|
| `latest` | newest release |
| `0.1.1` | exact version (recommended for CI) |
| `v0` | newest release of the major version |

```sh
# scan the current directory (mounted at /src, the default working directory)
docker run --rm -v "$PWD:/src" ghcr.io/gerijacki/mcp-guard

# any other command or flag
docker run --rm -v "$PWD:/src" ghcr.io/gerijacki/mcp-guard scan . --format json
docker run --rm ghcr.io/gerijacki/mcp-guard rules
```

The container user is non-root. To write a report file into the mounted directory, run it as your own user: `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" ghcr.io/gerijacki/mcp-guard scan . --format sarif -o mcp-guard.sarif`.

## Prebuilt binaries

Every [release](https://github.com/Gerijacki/mcp-guard/releases) ships archives named `mcp-guard_<os>_<arch>.tar.gz` (`.zip` on Windows) for Linux, macOS and Windows on amd64 and arm64, plus `checksums.txt`.

```sh
curl -sSfLO https://github.com/Gerijacki/mcp-guard/releases/latest/download/mcp-guard_linux_amd64.tar.gz
curl -sSfLO https://github.com/Gerijacki/mcp-guard/releases/latest/download/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar -xzf mcp-guard_linux_amd64.tar.gz mcp-guard && sudo mv mcp-guard /usr/local/bin/
```

## Verifying releases

Every release archive, `checksums.txt` and the container image carry **signed build provenance** (SLSA provenance, signed with Sigstore through GitHub artifact attestations), so you can check that a binary was built by this repository's release workflow from a specific commit:

```sh
gh attestation verify mcp-guard_linux_amd64.tar.gz --repo Gerijacki/mcp-guard
gh attestation verify oci://ghcr.io/gerijacki/mcp-guard:0.1.1 --repo Gerijacki/mcp-guard
```

Each archive also ships an SPDX **SBOM** (`mcp-guard_<os>_<arch>.<ext>.sbom.json`). The only third-party Go module is `gopkg.in/yaml.v3`.

## pre-commit

With the [pre-commit](https://pre-commit.com) framework, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Gerijacki/mcp-guard
    rev: v0.1.1
    hooks:
      - id: mcp-guard          # builds from source (needs Go)
      # - id: mcp-guard-docker # or: runs the container image (needs Docker)
        args: [--fail-on, high]
```

The hook scans the whole repository on each commit, which takes well under a second for typical MCP servers.

## From source

```sh
git clone https://github.com/Gerijacki/mcp-guard && cd mcp-guard
go build -o mcp-guard ./cmd/mcp-guard     # Go 1.23+
```
