[CmdletBinding()]
param(
    [ValidateSet('smoke', 'full')]
    [string]$Mode = 'smoke'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$state = Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.state\openwrt-lab-2.json') | ConvertFrom-Json
$labIp = ($state.networks.v4 | Where-Object type -eq 'public' | Select-Object -First 1).ip_address
if (-not $labIp) { throw 'The lab host has no recorded public IPv4 address.' }
$trials = if ($Mode -eq 'full') { 30 } else { 5 }
$durations = [System.Collections.Generic.List[int]]::new()

for ($trial = 1; $trial -le $trials; $trial++) {
    & ssh "root@$labIp" 'set -eu; rm -f /run/campus-link/relay-recovery.ready /run/campus-link/relay-recovery.result; systemd-run --quiet --collect --unit=campus-link-relay-recovery-watch --property=RuntimeMaxSec=40 /usr/local/libexec/campus-link-test-relay-recovery-watch'
    if ($LASTEXITCODE -ne 0) { throw "Could not arm relay recovery trial $trial." }
    $armed = $false
    for ($wait = 0; $wait -lt 15; $wait++) {
        & ssh "root@$labIp" 'test -f /run/campus-link/relay-recovery.ready' 2>$null
        if ($LASTEXITCODE -eq 0) { $armed = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $armed) { throw "Relay recovery trial $trial did not arm." }
    & ssh gz 'systemctl restart campus-link-relay.service; systemctl is-active --quiet campus-link-relay.service'
    if ($LASTEXITCODE -ne 0) { throw "Relay restart failed in trial $trial." }
    $line = $null
    for ($wait = 0; $wait -lt 35; $wait++) {
        $candidate = & ssh "root@$labIp" 'cat /run/campus-link/relay-recovery.result 2>/dev/null || true'
        if ($candidate) { $line = $candidate; break }
        Start-Sleep -Seconds 1
    }
    if ($line -notmatch '^recovery_ms=(\d+) route_withdrawn=0 traffic_interruptions=0 direct_preserved=1 relay_data_delta=0 control_recovered=1$') {
        throw "Relay recovery trial $trial failed: $line"
    }
    $duration = [int]$Matches[1]
    if ($duration -gt 30000) { throw "Relay recovery trial $trial exceeded 30 seconds." }
    $durations.Add($duration)
    Start-Sleep -Seconds 2
}

$ordered = $durations | Sort-Object
$p95Index = [Math]::Min($ordered.Count - 1, [Math]::Ceiling($ordered.Count * 0.95) - 1)
$mean = [Math]::Round(($durations | Measure-Object -Average).Average)
Write-Host "PASS trials=$trials min_ms=$($ordered[0]) mean_ms=$mean p95_ms=$($ordered[$p95Index]) max_ms=$($ordered[-1])"
