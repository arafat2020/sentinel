# Sentinel Windows Installer
# Requires: Windows 10+, PowerShell 5.1+, Administrator privileges
# Usage:
#   powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/arafat2020/sentinel/main/install.ps1 | iex"

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$REPO   = "arafat2020/sentinel"
$ASSET  = "sentinel-windows-amd64.exe"
$DEST   = "$env:ProgramFiles\Sentinel"

function Write-Step([string]$msg) { Write-Host "  ==> $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "  [ok] $msg" -ForegroundColor Green }
function Write-Fail([string]$msg) { Write-Host "  [!!] $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  Sentinel Installer for Windows" -ForegroundColor White
Write-Host "  ================================" -ForegroundColor DarkGray
Write-Host ""

# --- 1. Fetch latest release metadata ---
Write-Step "Fetching latest release from GitHub..."
$headers = @{ Accept = "application/vnd.github.v3+json"; "User-Agent" = "sentinel-installer" }
try {
    $release = Invoke-RestMethod `
        -Uri "https://api.github.com/repos/$REPO/releases/latest" `
        -Headers $headers
} catch {
    Write-Fail "Could not reach GitHub API: $_"
}

$version = $release.tag_name
Write-Ok "Latest release: $version"

# --- 2. Locate the Windows asset ---
$asset = $release.assets | Where-Object { $_.name -eq $ASSET }
if (-not $asset) {
    Write-Fail "Asset '$ASSET' not found in release $version. Has the release workflow run?"
}

$checksumsAsset = $release.assets | Where-Object { $_.name -eq "checksums.txt" }

# --- 3. Create installation directory ---
Write-Step "Installing to $DEST ..."
New-Item -ItemType Directory -Force -Path $DEST | Out-Null
$exePath = Join-Path $DEST "sentinel.exe"

# --- 4. Download binary ---
Write-Step "Downloading $ASSET ($([math]::Round($asset.size / 1MB, 1)) MB)..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $exePath -UseBasicParsing

# --- 5. Verify SHA-256 checksum ---
if ($checksumsAsset) {
    Write-Step "Verifying checksum..."
    $checksumsTmp = Join-Path $env:TEMP "sentinel-checksums.txt"
    Invoke-WebRequest -Uri $checksumsAsset.browser_download_url -OutFile $checksumsTmp -UseBasicParsing

    $line = Get-Content $checksumsTmp | Where-Object { $_ -match [regex]::Escape($ASSET) }
    if ($line) {
        $expected = ($line -split "\s+")[0].ToLower()
        $actual   = (Get-FileHash $exePath -Algorithm SHA256).Hash.ToLower()
        if ($expected -ne $actual) {
            Remove-Item $exePath -Force -ErrorAction SilentlyContinue
            Write-Fail "Checksum mismatch!`n  expected: $expected`n  got:      $actual"
        }
        Write-Ok "Checksum verified ($expected)"
    }
    Remove-Item $checksumsTmp -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "  [--] No checksums.txt in this release; skipping verification." -ForegroundColor Yellow
}

# --- 6. Add to system PATH (machine-wide) ---
$machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($machinePath -notlike "*$DEST*") {
    Write-Step "Adding $DEST to system PATH..."
    [Environment]::SetEnvironmentVariable("PATH", "$machinePath;$DEST", "Machine")
    Write-Ok "PATH updated — restart your terminal to use 'sentinel' from anywhere."
} else {
    Write-Ok "$DEST already in PATH."
}

# --- 7. Check Npcap ---
Write-Host ""
$npcap = Get-ItemProperty "HKLM:\SOFTWARE\Npcap" -ErrorAction SilentlyContinue
if (-not $npcap) {
    Write-Host "  [!] Npcap is NOT installed." -ForegroundColor Yellow
    Write-Host "      DNS telemetry requires Npcap with 'WinPcap API-compatible Mode'." -ForegroundColor Yellow
    Write-Host "      Download: https://npcap.com/#download" -ForegroundColor Yellow
} else {
    Write-Ok "Npcap detected."
}

# --- Done ---
Write-Host ""
Write-Host "  Sentinel $version installed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "  Run (elevated terminal required):" -ForegroundColor White
Write-Host "    sentinel.exe" -ForegroundColor Cyan
Write-Host ""
