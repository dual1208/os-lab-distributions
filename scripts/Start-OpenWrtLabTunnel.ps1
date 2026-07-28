[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$LocalPort = 8443
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $repoRoot '.state'
$stateFile = Join-Path $stateDir 'openwrt-lab-2.json'
$pidFile = Join-Path $stateDir 'luci-tunnel.pid'
if (-not (Test-Path -LiteralPath $stateFile)) {
    throw 'Private openwrt-lab-2 state is missing; provision the lab first.'
}

$listener = Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue
if ($listener) {
    throw "Local TCP port $LocalPort is already in use."
}

$state = Get-Content -Raw -LiteralPath $stateFile | ConvertFrom-Json
$publicIp = ($state.networks.v4 | Where-Object type -eq 'public' | Select-Object -First 1).ip_address
if (-not $publicIp) {
    throw 'Lab state contains no public IPv4 address.'
}

$sshArgs = @(
    '-N',
    '-o', 'ExitOnForwardFailure=yes',
    '-o', 'ServerAliveInterval=30',
    '-o', 'ServerAliveCountMax=3',
    '-L', "${LocalPort}:127.0.0.1:18443",
    "root@$publicIp"
)
$process = Start-Process -FilePath 'ssh.exe' -ArgumentList $sshArgs -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
if ($process.HasExited) {
    throw 'SSH tunnel exited before the local forward became ready.'
}
$process.Id | Set-Content -LiteralPath $pidFile
Write-Host "LuCI tunnel is ready at https://127.0.0.1:$LocalPort/"
Write-Host "Stop it with .\scripts\Stop-OpenWrtLabTunnel.ps1"

