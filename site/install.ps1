# cmail installer for Windows (PowerShell 5.1+).
#
#   irm https://tigwyk.github.io/cmail/install.ps1 | iex
#
# Or review first: download this file, read it, then run:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Options:
#   -InstallDir <dir>   install somewhere else (default %USERPROFILE%\.cmail\bin)
#   -Version <x.y.z>    install a specific release (default: latest)
#
# Verifies the SHA-256 of the downloaded archive against the release's
# SHA256SUMS.txt before installing anything. No admin required: installs to a
# user directory and updates the USER PATH only. Uninstall = delete the
# install dir and remove it from PATH.

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:USERPROFILE\.cmail\bin",
    [string]$Version = ''
)

$ErrorActionPreference = 'Stop'
$repo = 'tigwyk/cmail'

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

function Fail($msg) { Write-Host "install failed: $msg" -ForegroundColor Red; exit 1 }

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Fail "no Windows build for architecture '$env:PROCESSOR_ARCHITECTURE' (only x86_64 is published)."
}

# --- resolve version ---------------------------------------------------------
if (-not $Version) {
    Write-Host 'resolving latest release...'
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'cmail-install' }
        $Version = $rel.tag_name.TrimStart('v')
    } catch { Fail "could not query latest release: $($_.Exception.Message)" }
}
Write-Host "installing cmail v$Version"

$assetName = "cmail-v$Version-x86_64-pc-windows-msvc.zip"
$base = "https://github.com/$repo/releases/download/v$Version"
$zipUrl = "$base/$assetName"
$sumsUrl = "$base/SHA256SUMS.txt"

# --- download + verify -------------------------------------------------------
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("cmail-install-" + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "downloading $assetName ..."
    try { Invoke-WebRequest -Uri $zipUrl -OutFile (Join-Path $tmp $assetName) -UseBasicParsing }
    catch { Fail "download failed: $($_.Exception.Message)" }

    Write-Host 'verifying sha256 ...'
    try { Invoke-WebRequest -Uri $sumsUrl -OutFile (Join-Path $tmp 'SHA256SUMS.txt') -UseBasicParsing }
    catch { Fail "could not download SHA256SUMS.txt: $($_.Exception.Message)" }

    $expected = $null
    foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS.txt')) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+)$') {
            if ($Matches[2].Trim() -eq $assetName) { $expected = $Matches[1].ToLower(); break }
        }
    }
    if (-not $expected) { Fail "SHA256SUMS.txt has no entry for $assetName" }

    $actual = (Get-FileHash (Join-Path $tmp $assetName) -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) { Fail "sha256 mismatch (expected $expected, got $actual)" }
    Write-Host 'sha256 ok'

    # --- extract + install ---------------------------------------------------
    Expand-Archive -Path (Join-Path $tmp $assetName) -DestinationPath (Join-Path $tmp 'x') -Force
    $exes = Get-ChildItem -Path (Join-Path $tmp 'x') -Recurse -Include 'cmail.exe', 'cmail-relayd.exe'
    if (-not ($exes | Where-Object Name -eq 'cmail.exe')) { Fail 'archive did not contain cmail.exe' }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    foreach ($exe in $exes) { Copy-Item $exe.FullName -Destination $InstallDir -Force }
    Write-Host "installed to $InstallDir"

    # --- user PATH (idempotent) ---------------------------------------------
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @(); if ($userPath) { $parts = $userPath.Split(';') | Where-Object { $_ -ne '' } }
    $already = $parts | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') }
    if (-not $already) {
        $newPath = ($parts + $InstallDir) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "added $InstallDir to your user PATH"
    } else {
        Write-Host 'user PATH already contains the install dir'
    }

    Write-Host ''
    Write-Host 'done. open a NEW terminal (so PATH refreshes), then:' -ForegroundColor Green
    Write-Host '  cmail --version'
    Write-Host '  cmail init --name <your-agent>'
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
