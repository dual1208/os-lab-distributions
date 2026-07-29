$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$mapping = @(Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'cloud\droplet-role-map.json') |
    ConvertFrom-Json)
if ($mapping.Count -ne 3) { throw 'Expected exactly three role mappings.' }
$hourly = 0.08333
foreach ($entry in $mapping) {
    $state = Get-Content -Raw -LiteralPath (
        Join-Path $repoRoot ".state\$($entry.state_name).json") | ConvertFrom-Json
    $live = @(doctl compute droplet get $state.id -o json | ConvertFrom-Json)
    if ($state.name -ne $entry.state_name -or $live.Count -ne 1 -or
        $live[0].name -ne $entry.provider_name) {
        throw "Cloud identity mismatch: $($entry.provider_name)"
    }
    [pscustomobject]@{
        Name = $entry.provider_name
        Role = $entry.role
        Status = $live[0].status
        Region = $live[0].region.slug
        VCPUs = $live[0].vcpus
        MemoryGiB = [math]::Round($live[0].memory / 1024, 1)
        DiskGiB = $live[0].disk
        HourlyUSD = $hourly
    }
}
Write-Host ('Combined live rate: ${0:N5}/hour' -f ($hourly * $mapping.Count))
