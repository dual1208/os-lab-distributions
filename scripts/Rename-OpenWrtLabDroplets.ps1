[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$mapping = @(Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'cloud\droplet-role-map.json') |
    ConvertFrom-Json)
if ($mapping.Count -ne 3) {
    throw 'Expected exactly three role mappings.'
}

$inventory = @(doctl compute droplet list -o json | ConvertFrom-Json)
foreach ($entry in $mapping) {
    $stateFile = Join-Path $repoRoot ".state\$($entry.state_name).json"
    if (-not (Test-Path -LiteralPath $stateFile)) {
        throw "Missing private state for $($entry.state_name)."
    }
    $state = Get-Content -Raw -LiteralPath $stateFile | ConvertFrom-Json
    if ($state.name -ne $entry.state_name -or -not $state.id) {
        throw "Provisioning record mismatch for $($entry.state_name)."
    }
    $live = @($inventory | Where-Object { [long]$_.id -eq [long]$state.id })
    if ($live.Count -ne 1 -or
        $live[0].name -notin @($entry.state_name, $entry.provider_name) -or
        $live[0].size_slug -ne 's-4vcpu-8gb-intel' -or
        $live[0].region.slug -ne 'sfo3' -or
        $live[0].status -ne 'active') {
        throw "Live identity or plan mismatch for $($entry.state_name)."
    }
    $collision = @($inventory | Where-Object {
        $_.name -eq $entry.provider_name -and [long]$_.id -ne [long]$state.id
    })
    if ($collision.Count -ne 0) {
        throw "Provider-name collision for $($entry.provider_name)."
    }
    if ($live[0].name -eq $entry.provider_name) {
        continue
    }
    if ($PSCmdlet.ShouldProcess($entry.provider_name, 'Rename exact recorded DigitalOcean Droplet')) {
        doctl compute droplet-action rename $state.id `
            --droplet-name $entry.provider_name --wait --no-header | Out-Null
    }
}

if ($WhatIfPreference) {
    Write-Host 'Preflight passed for all three exact recorded Droplets.'
    return
}

foreach ($entry in $mapping) {
    $state = Get-Content -Raw -LiteralPath (
        Join-Path $repoRoot ".state\$($entry.state_name).json") | ConvertFrom-Json
    $live = @(doctl compute droplet get $state.id -o json | ConvertFrom-Json)
    if ($live.Count -ne 1 -or $live[0].name -ne $entry.provider_name -or
        $live[0].status -ne 'active') {
        throw "Rename did not converge for $($entry.provider_name)."
    }
}
Write-Host 'All three exact recorded Droplets have role-based names.'
