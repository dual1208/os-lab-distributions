[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$AliyunCli = 'aliyun'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$statePath = Join-Path $repoRoot '.state\campus-link-aliyun-rule.json'
$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
if (-not $state.authorized) { throw 'Private rule state is not marked authorized.' }
if (-not $PSCmdlet.ShouldProcess('the privately recorded campus-link UDP/443 /32 rule', 'RevokeSecurityGroup')) { return }

$revokeResponse = & $AliyunCli ecs RevokeSecurityGroup `
    --RegionId $state.region_id `
    --SecurityGroupId $state.security_group_id `
    --IpProtocol $state.ip_protocol `
    --PortRange $state.port_range `
    --SourceCidrIp $state.source_cidr `
    --NicType $state.nic_type `
    --Policy $state.policy
if ($LASTEXITCODE -ne 0) { throw 'RevokeSecurityGroup failed.' }

$raw = & $AliyunCli ecs DescribeSecurityGroupAttribute `
    --RegionId $state.region_id `
    --SecurityGroupId $state.security_group_id `
    --Direction ingress
if ($LASTEXITCODE -ne 0) { throw 'Post-revoke inspection failed.' }
$rules = @(($raw | ConvertFrom-Json).Permissions.Permission)
$matching = @($rules | Where-Object {
    $_.IpProtocol -eq 'UDP' -and $_.PortRange -eq $state.port_range -and
    $_.Policy -eq 'Accept' -and $_.NicType -eq $state.nic_type -and
    $_.SourceCidrIp -eq $state.source_cidr
})
if ($matching.Count -ne 0) { throw 'The exact rule is still present.' }
$state.authorized = $false
$state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8NoBOM
Write-Host 'The exact campus-link Aliyun UDP/443 ingress rule was revoked.'
