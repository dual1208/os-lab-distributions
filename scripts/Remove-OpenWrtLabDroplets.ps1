[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$mapping = @(Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'cloud\droplet-role-map.json') |
    ConvertFrom-Json)
if ($mapping.Count -ne 3) { throw 'Expected exactly three role mappings.' }
$targets = foreach ($entry in $mapping) {
    $stateFile = Join-Path $repoRoot ".state\$($entry.state_name).json"
    if (-not (Test-Path -LiteralPath $stateFile)) {
        throw "Missing private state for $($entry.state_name); refusing broad discovery deletion."
    }
    $state = Get-Content -Raw -LiteralPath $stateFile | ConvertFrom-Json
    if ($state.name -ne $entry.state_name -or -not $state.id) {
        throw "State identity mismatch for $($entry.state_name)"
    }
    $live = @(doctl compute droplet get $state.id -o json | ConvertFrom-Json)
    if ($live.Count -ne 1 -or
        $live[0].name -notin @($entry.state_name, $entry.provider_name)) {
        throw "Live identity mismatch for $($entry.provider_name)"
    }
    [pscustomobject]@{ Name = $live[0].name; Id = [long]$state.id }
}

foreach ($target in $targets) {
    if ($PSCmdlet.ShouldProcess($target.Name, 'Destroy exact recorded DigitalOcean Droplet')) {
        doctl compute droplet delete $target.Id --force
    }
}

$deadline = (Get-Date).AddMinutes(2)
do {
    $liveIds = @(doctl compute droplet list -o json | ConvertFrom-Json | ForEach-Object { [long]$_.id })
    $remaining = @($targets | Where-Object Id -In $liveIds)
    if ($remaining.Count -eq 0) { break }
    Start-Sleep -Seconds 3
} while ((Get-Date) -lt $deadline)
if ($remaining.Count -ne 0) {
    throw 'Deletion requests were accepted but inventory has not converged.'
}
Write-Host 'All three exact lab droplets are absent. No other resource was targeted.'
