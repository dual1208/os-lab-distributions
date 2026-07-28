[CmdletBinding()]
param(
    [string]$Tag = 'openwrt-25.12.5-dae2-lab-20260728'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$releaseDir = Join-Path $repoRoot 'out\router-lab-release'
$required = @(
    'openwrt-25.12.5-e8450-ubi-dae2-go1.26.4.tar.zst',
    'openwrt-25.12.5-x86-64-router-lab.tar.zst',
    'RELEASE-NOTES.md',
    'SHA256SUMS'
)
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $releaseDir $name))) {
        throw "Missing verified release payload: $name"
    }
}

gh release view $Tag --repo dual1208/os-lab-distributions *> $null
if ($LASTEXITCODE -eq 0) {
    throw "Release already exists; refusing to overwrite: $Tag"
}

$assets = @($required | ForEach-Object { Join-Path $releaseDir $_ })
& gh release create $Tag @assets `
    --repo dual1208/os-lab-distributions `
    --target main `
    --title 'OpenWrt 25.12.5 E8450 dae 2.0.0 + two-router lab' `
    --notes-file (Join-Path $releaseDir 'RELEASE-NOTES.md') `
    --prerelease
if ($LASTEXITCODE -ne 0) { throw 'GitHub release creation failed.' }

$release = gh release view $Tag --repo dual1208/os-lab-distributions --json url,isPrerelease,assets | ConvertFrom-Json
if (-not $release.isPrerelease -or @($release.assets).Count -ne $required.Count) {
    throw 'Published release shape does not match the verified four-asset contract.'
}
Write-Host $release.url

