$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $repoRoot '.state\luci-tunnel.pid'
if (-not (Test-Path -LiteralPath $pidFile)) {
    Write-Host 'No recorded LuCI tunnel is running.'
    return
}

$tunnelPid = [int](Get-Content -Raw -LiteralPath $pidFile)
$process = Get-Process -Id $tunnelPid -ErrorAction SilentlyContinue
if ($process -and $process.ProcessName -ne 'ssh') {
    throw "PID $tunnelPid is not ssh; refusing to stop it."
}
if ($process) {
    Stop-Process -Id $tunnelPid
    Wait-Process -Id $tunnelPid -Timeout 5 -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $pidFile
Write-Host 'LuCI tunnel stopped.'

