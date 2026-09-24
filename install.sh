#!/bin/sh
# Install mcp-guard from GitHub releases.
#
#   curl -sSfL https://raw.githubusercontent.com/Gerijacki/mcp-guard/main/install.sh | sh
#
# Environment variables:
#   MCP_GUARD_VERSION  release tag to install, e.g. v0.1.0 (default: latest)
#   BIN_DIR            install directory (default: /usr/local/bin if writable, else ~/.local/bin)
#
# The download is verified against the release's checksums.txt before installing.
set -eu

REPO="Gerijacki/mcp-guard"
VERSION="${MCP_GUARD_VERSION:-latest}"

log() { printf '%s\n' "mcp-guard: $*" >&2; }
fail() { log "error: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required"; }
need uname
need tar
need mktemp

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS '$(uname -s)'; on Windows use install.ps1 or download a release zip" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported architecture '$(uname -m)'" ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -sSfL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q "$1" -O "$2"; }
else
  fail "curl or wget is required"
fi

if [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi
asset="mcp-guard_${os}_${arch}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

log "downloading $asset ($VERSION)"
fetch "$base/$asset" "$tmp/$asset" || fail "download failed: $base/$asset"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || fail "download failed: $base/checksums.txt"

expected="$(grep " $asset\$" "$tmp/checksums.txt" | cut -d ' ' -f 1)"
[ -n "$expected" ] || fail "no checksum for $asset in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | cut -d ' ' -f 1)"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$asset" | cut -d ' ' -f 1)"
else
  fail "sha256sum or shasum is required to verify the download"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for $asset (expected $expected, got $actual)"

tar -xzf "$tmp/$asset" -C "$tmp" mcp-guard

if [ -z "${BIN_DIR:-}" ]; then
  if [ -w /usr/local/bin ]; then BIN_DIR=/usr/local/bin; else BIN_DIR="$HOME/.local/bin"; fi
fi
mkdir -p "$BIN_DIR"
install -m 0755 "$tmp/mcp-guard" "$BIN_DIR/mcp-guard" 2>/dev/null || {
  cp "$tmp/mcp-guard" "$BIN_DIR/mcp-guard" && chmod 0755 "$BIN_DIR/mcp-guard"
}

log "installed $("$BIN_DIR/mcp-guard" version) to $BIN_DIR/mcp-guard"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) log "note: $BIN_DIR is not in your PATH" ;;
esac
