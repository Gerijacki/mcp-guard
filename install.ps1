# Install mcp-guard on Windows from GitHub releases.
#
#   irm https://raw.githubusercontent.com/Gerijacki/mcp-guard/main/install.ps1 | iex
#
# Environment variables:
#   MCP_GUARD_VERSION  release tag to install, e.g. v0.1.0 (default: latest)
#   BIN_DIR            install directory (default: $env:LOCALAPPDATA\mcp-guard\bin)
#
# The download is verified against the release's checksums.txt before installing.
$ErrorActionPreference = 'Stop'

$repo = 'Gerijacki/mcp-guard'
$version = if ($env:MCP_GUARD_VERSION) { $env:MCP_GUARD_VERSION } else { 'latest' }
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$asset = "mcp-guard_windows_$arch.zip"
$base = if ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$version" }
$binDir = if ($env:BIN_DIR) { $env:BIN_DIR } else { Join-Path $env:LOCALAPPDATA 'mcp-guard\bin' }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mcp-guard-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    Write-Host "mcp-guard: downloading $asset ($version)"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt')

    $line = Get-Content (Join-Path $tmp 'checksums.txt') | Where-Object { $_ -match " $([regex]::Escape($asset))$" }
    if (-not $line) { throw "no checksum for $asset in checksums.txt" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
    if ($expected -ne $actual) { throw "checksum mismatch for $asset (expected $expected, got $actual)" }

    Expand-Archive -Force -Path (Join-Path $tmp $asset) -DestinationPath $tmp
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    Copy-Item -Force (Join-Path $tmp 'mcp-guard.exe') (Join-Path $binDir 'mcp-guard.exe')
    Write-Host "mcp-guard: installed $(& (Join-Path $binDir 'mcp-guard.exe') version) to $binDir"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $binDir) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$binDir", 'User')
        Write-Host "mcp-guard: added $binDir to your user PATH (restart the terminal)"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
