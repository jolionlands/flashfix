# Verify the shim is installed, loaded, and returning our printers.
#   pwsh -File verify.ps1
$ErrorActionPreference = 'Continue'
$AppDir = "$env:ProgramFiles\Flashforge\Flash Studio Desktop"

Write-Host "== FlashNetwork shim status =="

$live   = Join-Path $AppDir 'FlashNetwork.dll'
$orig   = Join-Path $AppDir 'FlashNetwork_orig.dll'
$shim   = Join-Path $PSScriptRoot 'flashnet_shim.dll'

foreach ($p in @($live, $orig, $shim)) {
    if (Test-Path $p) {
        $h = (Get-FileHash $p -Algorithm SHA256).Hash.Substring(0,16)
        Write-Host ("  {0,-24} {1,10} bytes  sha={2}" -f (Split-Path $p -Leaf), (Get-Item $p).Length, $h)
    } else {
        Write-Host ("  {0,-24} MISSING" -f (Split-Path $p -Leaf))
    }
}

$liveH = if (Test-Path $live) { (Get-FileHash $live -Algorithm SHA256).Hash } else { '' }
$shimH = if (Test-Path $shim) { (Get-FileHash $shim -Algorithm SHA256).Hash } else { '' }
$installed = ($liveH -ne '' -and $liveH -eq $shimH)
Write-Host ""
Write-Host ("  shim installed : {0}" -f $installed)

$proc = Get-Process 'flash studio' -ErrorAction SilentlyContinue
if ($proc) {
    $mods = $proc.Modules | Where-Object { $_.ModuleName -like 'FlashNetwork*' } |
            Select-Object -ExpandProperty ModuleName
    Write-Host ("  app running    : pid {0}" -f $proc.Id)
    Write-Host ("  loaded modules : {0}" -f ($mods -join ', '))
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
             Where-Object { $_.OwningProcess -eq $proc.Id -and $_.RemoteAddress -like '192.168.*' }
    if ($conns) {
        Write-Host "  printer conns  :"
        $conns | ForEach-Object {
            Write-Host ("     {0}:{1} -> {2}:{3}  {4}" -f $_.LocalAddress, $_.LocalPort,
                        $_.RemoteAddress, $_.RemotePort, $_.State)
        }
    } else {
        Write-Host "  printer conns  : none right now (open the Device tab)"
    }
} else {
    Write-Host "  app running    : no"
}
