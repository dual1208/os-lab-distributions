[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $repoRoot '.state'
$outputDir = Join-Path $repoRoot 'out\router-lab-release'
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

$items = @(
    [pscustomobject]@{
        HostName = 'openwrt-lab'
        FileName = 'openwrt-25.12.5-e8450-ubi-dae2-go1.26.4.tar.zst'
    },
    [pscustomobject]@{
        HostName = 'openwrt-lab-2'
        FileName = 'openwrt-25.12.5-x86-64-router-lab.tar.zst'
    }
)

foreach ($item in $items) {
    $state = Get-Content -Raw -LiteralPath (Join-Path $stateDir "$($item.HostName).json") | ConvertFrom-Json
    $publicIp = ($state.networks.v4 | Where-Object type -eq 'public' | Select-Object -First 1).ip_address
    if (-not $publicIp) { throw "No private-state address for $($item.HostName)" }
    foreach ($suffix in @('', '.sha256')) {
        $name = "$($item.FileName)$suffix"
        & scp.exe -q -o LogLevel=ERROR "root@${publicIp}:/srv/openwrt-lab/release/$name" $outputDir
        if ($LASTEXITCODE -ne 0) { throw "SCP failed for $name" }
    }

    $expectedLine = Get-Content -Raw -LiteralPath (Join-Path $outputDir "$($item.FileName).sha256")
    if ($expectedLine -notmatch '^([0-9a-f]{64})\s+') {
        throw "Invalid remote SHA-256 record for $($item.FileName)"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $outputDir $item.FileName)).Hash.ToLowerInvariant()
    if ($actual -ne $Matches[1]) {
        throw "SHA-256 mismatch for $($item.FileName)"
    }
}

$releaseNotes = Join-Path $repoRoot 'RELEASE-NOTES-openwrt-dae-lab.md'
Copy-Item -LiteralPath $releaseNotes -Destination (Join-Path $outputDir 'RELEASE-NOTES.md') -Force
$payloadNames = @($items.FileName) + @('RELEASE-NOTES.md')
$sumLines = foreach ($name in $payloadNames) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $outputDir $name)).Hash.ToLowerInvariant()
    "$hash  $name"
}
$sumLines | Set-Content -LiteralPath (Join-Path $outputDir 'SHA256SUMS')
Write-Host "Verified release staging: $outputDir"

