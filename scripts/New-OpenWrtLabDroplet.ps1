[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$SshKeyFingerprint,
    [string]$Name = 'openwrt-lab',
    [string]$Region = 'sfo3',
    [string]$Size = 's-4vcpu-8gb-intel',
    [string]$Image = 'ubuntu-24-04-x64'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $repoRoot '.state'
$stateFile = Join-Path $stateDir ("{0}.json" -f $Name)
$cloudInit = Join-Path $repoRoot 'cloud\cloud-init.yaml'

if (-not (Test-Path -LiteralPath $cloudInit)) {
    throw "Missing cloud-init contract: $cloudInit"
}

$existing = @(doctl compute droplet list -o json | ConvertFrom-Json |
    Where-Object name -eq $Name)
if ($existing.Count -ne 0) {
    throw "Refusing to create a duplicate droplet named $Name"
}

$available = @(doctl compute size list -o json | ConvertFrom-Json |
    Where-Object { $_.slug -eq $Size -and $_.available })
if ($available.Count -ne 1) {
    throw "Requested size is not currently available to this account: $Size"
}

New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$before = doctl compute droplet list -o json | ConvertFrom-Json |
    Select-Object id,name,status,region,size_slug
$before | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stateDir 'inventory-before.json')

foreach ($tag in @('os-lab', 'openwrt-build', 'temporary')) {
    doctl compute tag create $tag 2>$null | Out-Null
}

if (-not $PSCmdlet.ShouldProcess("$Name ($Size in $Region)", 'Create billable DigitalOcean Droplet')) {
    return
}

doctl compute droplet create $Name `
    --region $Region `
    --size $Size `
    --image $Image `
    --ssh-keys $SshKeyFingerprint `
    --tag-names 'os-lab,openwrt-build,temporary' `
    --user-data-file $cloudInit `
    --enable-monitoring `
    --wait `
    --format ID,Name,Status,Region,Memory,VCPUs,Disk | Out-Host

$created = @(doctl compute droplet list -o json | ConvertFrom-Json |
    Where-Object name -eq $Name)
if ($created.Count -ne 1 -or $created[0].status -ne 'active') {
    throw "Droplet creation did not converge to one active $Name instance"
}

$created[0] | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $stateFile
Write-Host "Private runtime state saved under ignored path: $stateFile"
