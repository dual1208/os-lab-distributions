[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [long]$DropletId,
    [string]$ExpectedName = 'debian-s-1vcpu-1gb-sfo2-01'
)

$ErrorActionPreference = 'Stop'
$target = @(doctl compute droplet get $DropletId -o json | ConvertFrom-Json)
if ($target.Count -ne 1) { throw 'Expected exactly one legacy droplet.' }
$item = $target[0]
$created = [datetimeoffset]$item.created_at
if ($item.name -ne $ExpectedName -or $item.vcpus -ne 1 -or
    $item.memory -ne 1024 -or $item.disk -ne 25 -or
    $created.UtcDateTime.Date -ne [datetime]'2026-01-01' -or
    @($item.volume_ids).Count -ne 0) {
    throw 'Legacy droplet identity or storage contract did not match; refusing deletion.'
}

if (-not $PSCmdlet.ShouldProcess($ExpectedName, "Destroy exact legacy Droplet ID $DropletId")) {
    return
}
doctl compute droplet delete $DropletId --force

$deadline = (Get-Date).AddMinutes(2)
do {
    $ids = @(doctl compute droplet list -o json | ConvertFrom-Json | ForEach-Object { [long]$_.id })
    if ($DropletId -notin $ids) {
        Write-Host 'The exact legacy droplet is absent; no volume was targeted.'
        return
    }
    Start-Sleep -Seconds 3
} while ((Get-Date) -lt $deadline)
throw 'Deletion was accepted but inventory did not converge before the deadline.'

