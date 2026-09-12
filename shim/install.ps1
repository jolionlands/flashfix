# Install / uninstall the FlashNetwork shim for Flash Studio.
#
#   pwsh -File install.ps1            # install (needs admin)
#   pwsh -File install.ps1 -Uninstall # restore the original DLL
#
# What it does:
#   1. backs up the pristine FlashNetwork.dll as FlashNetwork_orig.dll
#   2. copies flashnet_shim.dll over FlashNetwork.dll
#   3. Flash Studio then loads the shim, which forwards 129 exports to the
#      original and injects the printers from Orca-Flashforge.conf into
#      fnet_getLanDevList.

param(
    [switch]$Uninstall,
    [string]$AppDir = "$env:ProgramFiles\Flashforge\Flash Studio Desktop",
    [string]$ShimDll = "$PSScriptRoot\flashnet_shim.dll"
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this from an elevated PowerShell (right-click -> Run as Administrator)."
    }
}

Assert-Admin

$target = Join-Path $AppDir 'FlashNetwork.dll'
$orig   = Join-Path $AppDir 'FlashNetwork_orig.dll'
$backup = Join-Path $AppDir 'FlashNetwork.dll.vanilla'

if (-not (Test-Path $AppDir))  { throw "App dir not found: $AppDir" }

function Stop-App {
    Get-Process 'flash studio' -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  stopping flash studio (pid $($_.Id))"
        Stop-Process -Id $_.Id -Force
    }
    Start-Sleep -Seconds 2
}

function Get-Sha($p) {
    if (-not (Test-Path $p)) { return $null }
    (Get-FileHash $p -Algorithm SHA256).Hash
}

if ($Uninstall) {
    Write-Host "== uninstalling FlashNetwork shim =="
    if (-not (Test-Path $orig)) {
        Write-Host "  no FlashNetwork_orig.dll found -- nothing to restore."
        exit 0
    }
    Stop-App
    $src = if (Test-Path $backup) { $backup } else { $orig }
    Write-Host "  restoring from $(Split-Path $src -Leaf)"
    Copy-Item $src $target -Force
    Remove-Item $orig -ErrorAction SilentlyContinue
    Write-Host "  done. Flash Studio is using the original FlashNetwork.dll again."
    exit 0
}

Write-Host "== installing FlashNetwork shim =="

if (-not (Test-Path $ShimDll)) {
    throw "shim not built: $ShimDll  (run shim\build.bat first)"
}

# Detect whether the shim is already installed (idempotent re-run).
$cur   = Get-Sha $target
$shimH = Get-Sha $ShimDll
if ($cur -eq $shimH) {
    Write-Host "  shim already installed and current."
    exit 0
}

Stop-App

if (-not (Test-Path $orig)) {
    # first install: preserve the pristine DLL
    Write-Host "  preserving original -> FlashNetwork_orig.dll"
    Copy-Item $target $orig -Force
    Copy-Item $target $backup -Force
} else {
    Write-Host "  FlashNetwork_orig.dll already present (kept)"
}

if ((Get-Sha $target) -ne (Get-Sha $orig)) {
    Write-Host "  NOTE: live DLL differed from the saved original; refreshing backup."
    Copy-Item $target $backup -Force
}

Write-Host "  installing shim -> FlashNetwork.dll"
Copy-Item $ShimDll $target -Force

Write-Host "  verifying..."
$ok = (Get-Sha $target) -eq (Get-Sha $ShimDll)
if (-not $ok) { throw "verification failed: installed DLL hash mismatch" }

Write-Host ""
Write-Host "  Installed. Restart Flash Studio."
Write-Host "  The Device tab should now show your printers as usable."
Write-Host "  Uninstall with:  pwsh -File install.ps1 -Uninstall"
