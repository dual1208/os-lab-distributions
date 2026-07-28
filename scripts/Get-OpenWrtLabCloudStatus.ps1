$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$names = @('openwrt-lab', 'openwrt-lab-2', 'openwrt-lab-3')
$hourly = 0.08333
foreach ($name in $names) {
    $state = Get-Content -Raw -LiteralPath (Join-Path $repoRoot ".state\$name.json") | ConvertFrom-Json
    $live = @(doctl compute droplet get $state.id -o json | ConvertFrom-Json)
    if ($live.Count -ne 1 -or $live[0].name -ne $name) {
        throw "Cloud identity mismatch: $name"
    }
    [pscustomobject]@{
        Name = $name
        Status = $live[0].status
        Region = $live[0].region.slug
        VCPUs = $live[0].vcpus
        MemoryGiB = [math]::Round($live[0].memory / 1024, 1)
        DiskGiB = $live[0].disk
        HourlyUSD = $hourly
    }
}
Write-Host ('Combined live rate: ${0:N5}/hour' -f ($hourly * $names.Count))
