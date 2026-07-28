$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$stateFile = Join-Path $repoRoot '.state\openwrt-lab-2.json'
$state = Get-Content -Raw -LiteralPath $stateFile | ConvertFrom-Json
$publicIp = ($state.networks.v4 | Where-Object type -eq 'public' | Select-Object -First 1).ip_address
if (-not $publicIp) {
    throw 'Lab state contains no public IPv4 address.'
}
$password = ssh -o LogLevel=ERROR "root@$publicIp" 'cat /etc/openwrt-lab/admin.secret'
if ($LASTEXITCODE -ne 0 -or -not $password) {
    throw 'Could not retrieve the lab password.'
}
$password | Set-Clipboard
Write-Host 'The LuCI root password is now on the Windows clipboard.'

