[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$expected = @('openwrt-lab', 'openwrt-lab-2')
$targets = foreach ($name in $expected) {
    $stateFile = Join-Path $repoRoot ".state\$name.json"
    if (-not (Test-Path -LiteralPath $stateFile)) {
        throw "Missing private state for $name; refusing broad discovery deletion."
    }
    $state = Get-Content -Raw -LiteralPath $stateFile | ConvertFrom-Json
    if ($state.name -ne $name -or -not $state.id) {
        throw "State identity mismatch for $name"
    }
    $live = @(doctl compute droplet get $state.id -o json | ConvertFrom-Json)
    if ($live.Count -ne 1 -or $live[0].name -ne $name) {
        throw "Live identity mismatch for $name"
    }
    [pscustomobject]@{ Name = $name; Id = [long]$state.id }
}

foreach ($target in $targets) {
    if ($PSCmdlet.ShouldProcess($target.Name, "Destroy exact DigitalOcean Droplet ID $($target.Id)")) {
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
Write-Host 'Both exact lab droplets are absent. Unrelated droplets were not targeted.'

