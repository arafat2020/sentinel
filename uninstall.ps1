# Sentinel Windows Uninstaller
# Requires: Windows 10+, PowerShell 5.1+, Administrator privileges
# Usage:
#   powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/arafat2020/sentinel/main/uninstall.ps1 | iex"
# Skip confirmation:
#   $env:SENTINEL_ASSUME_YES='1'; irm https://raw.githubusercontent.com/arafat2020/sentinel/main/uninstall.ps1 | iex

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$DEST    = "$env:ProgramFiles\Sentinel"
$EXE     = Join-Path $DEST "sentinel.exe"

function Write-Step([string]$msg) { Write-Host "  ==> $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "  [ok] $msg" -ForegroundColor Green }
function Write-Fail([string]$msg) { Write-Host "  [!!] $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  Sentinel Uninstaller for Windows" -ForegroundColor White
Write-Host "  ==================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  This will stop any running sentinel.exe and remove:" -ForegroundColor White
Write-Host "    $DEST" -ForegroundColor Cyan
Write-Host "  It will also drop that directory from the system PATH." -ForegroundColor White
Write-Host "  Npcap and Sentinel data files (e.g. sentinel.db) are left untouched." -ForegroundColor DarkGray
Write-Host ""

$assumeYes = $env:SENTINEL_ASSUME_YES -eq "1"
if (-not $assumeYes) {
    $ans = "N"
    try {
        $ans = Read-Host "  Continue? [y/N]"
    } catch {
        Write-Fail "No terminal available; set `$env:SENTINEL_ASSUME_YES='1' to confirm removal."
    }
    if ($ans -notmatch '^[yY](es)?$') {
        Write-Host "  Uninstall cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# --- 1. Stop running processes ---
$procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
if ($procs) {
    Write-Step "Stopping running sentinel.exe process(es)..."
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Write-Ok "Stopped."
}

# --- 2. Remove install directory ---
if (Test-Path $DEST) {
    Write-Step "Removing $DEST ..."
    Remove-Item -LiteralPath $DEST -Recurse -Force
    Write-Ok "Removed $DEST"
} elseif (Test-Path $EXE) {
    Write-Step "Removing $EXE ..."
    Remove-Item -LiteralPath $EXE -Force
    Write-Ok "Removed $EXE"
} else {
    Write-Host "  [--] No Sentinel install found at $DEST" -ForegroundColor Yellow
}

# --- 3. Remove from system PATH ---
$machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($machinePath -and ($machinePath -split ";" | Where-Object { $_ -eq $DEST })) {
    Write-Step "Removing $DEST from system PATH..."
    $newPath = ($machinePath -split ";" | Where-Object { $_ -and $_ -ne $DEST }) -join ";"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
    Write-Ok "PATH updated — restart your terminal for the change to take effect."
} else {
    Write-Ok "$DEST was not in the system PATH."
}

Write-Host ""
Write-Host "  Sentinel binary removed." -ForegroundColor Green
Write-Host "  Npcap and data files were preserved." -ForegroundColor DarkGray
Write-Host ""
