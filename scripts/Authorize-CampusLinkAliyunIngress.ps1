[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$AliyunCli = 'aliyun'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$lab = Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.state\openwrt-lab-2.json') | ConvertFrom-Json
$sourceIp = ($lab.networks.v4 | Where-Object type -eq 'public' | Select-Object -First 1).ip_address
if (-not $sourceIp) { throw 'The edge host has no recorded public IPv4 address.' }
$sourceCidr = "$sourceIp/32"

$region = (& ssh gz 'curl -fsS --max-time 3 http://100.100.100.200/latest/meta-data/region-id').Trim()
$instanceId = (& ssh gz 'curl -fsS --max-time 3 http://100.100.100.200/latest/meta-data/instance-id').Trim()
if ($LASTEXITCODE -ne 0 -or -not $region -or -not $instanceId) { throw 'gz metadata lookup failed.' }
$ids = '["' + $instanceId + '"]'
$instanceRaw = & $AliyunCli ecs DescribeInstances --RegionId $region --InstanceIds $ids --PageSize 10
if ($LASTEXITCODE -ne 0) { throw 'Exact ECS instance query failed.' }
$instances = @(($instanceRaw | ConvertFrom-Json).Instances.Instance)
if ($instances.Count -ne 1 -or $instances[0].InstanceId -ne $instanceId -or $instances[0].Status -ne 'Running') {
    throw 'gz metadata and ECS identity did not converge to one running instance.'
}
$hostName = ((& ssh -G gz | Select-String '^hostname ' | Select-Object -First 1) -split '\s+', 2)[1]
$targetIp = [System.Net.Dns]::GetHostAddresses($hostName) | Where-Object AddressFamily -eq InterNetwork | Select-Object -First 1
$reported = @($instances[0].PublicIpAddress.IpAddress) + @($instances[0].EipAddress.IpAddress)
if (-not $targetIp -or $targetIp.IPAddressToString -notin $reported) { throw 'ECS public address does not match ssh gz.' }
$groups = @($instances[0].SecurityGroupIds.SecurityGroupId)
if ($groups.Count -ne 1) { throw 'Expected exactly one attached security group.' }

$groupRaw = & $AliyunCli ecs DescribeSecurityGroupAttribute --RegionId $region --SecurityGroupId $groups[0] --Direction ingress
if ($LASTEXITCODE -ne 0) { throw 'Security-group inspection failed.' }
$rules = @(($groupRaw | ConvertFrom-Json).Permissions.Permission)
$tcp443 = @($rules | Where-Object { $_.IpProtocol -eq 'TCP' -and $_.PortRange -eq '443/443' -and $_.Policy -eq 'Accept' })
if ($tcp443.Count -ne 1 -or $tcp443[0].NicType -ne 'intranet') { throw 'TCP/443 rule is not the expected unique template.' }
$matching = @($rules | Where-Object {
    $_.IpProtocol -eq 'UDP' -and $_.PortRange -eq '443/443' -and
    $_.Policy -eq 'Accept' -and $_.NicType -eq 'intranet' -and
    $_.SourceCidrIp -eq $sourceCidr
})
if ($matching.Count -eq 1) {
    Write-Host 'The exact campus-link Aliyun UDP/443 /32 rule already exists.'
    return
}
if ($matching.Count -ne 0) { throw 'Duplicate exact UDP/443 rules exist.' }
if (-not $PSCmdlet.ShouldProcess('one UDP/443 rule scoped to the private-state edge /32', 'AuthorizeSecurityGroup')) { return }

$clientToken = [guid]::NewGuid().ToString()
$statePath = Join-Path $repoRoot '.state\campus-link-aliyun-rule.json'
[pscustomobject]@{
    region_id=$region; instance_id=$instanceId; security_group_id=$groups[0]
    source_cidr=$sourceCidr; ip_protocol='udp'; port_range='443/443'
    nic_type='intranet'; policy='accept'; priority=1
    description='campus-link-lab-udp443-20260728'; client_token=$clientToken
    pre_rule_count=$rules.Count; authorized=$false
} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8NoBOM

$authorizeResponse = & $AliyunCli ecs AuthorizeSecurityGroup `
    --RegionId $region --SecurityGroupId $groups[0] --IpProtocol udp `
    --PortRange 443/443 --SourceCidrIp $sourceCidr --NicType intranet `
    --Policy accept --Priority 1 --Description campus-link-lab-udp443-20260728 `
    --ClientToken $clientToken
if ($LASTEXITCODE -ne 0) { throw 'AuthorizeSecurityGroup failed.' }
Start-Sleep -Seconds 2
$afterRaw = & $AliyunCli ecs DescribeSecurityGroupAttribute --RegionId $region --SecurityGroupId $groups[0] --Direction ingress
if ($LASTEXITCODE -ne 0) { throw 'Post-authorization inspection failed.' }
$after = @(($afterRaw | ConvertFrom-Json).Permissions.Permission)
$matchingAfter = @($after | Where-Object {
    $_.IpProtocol -eq 'UDP' -and $_.PortRange -eq '443/443' -and
    $_.Policy -eq 'Accept' -and $_.NicType -eq 'intranet' -and
    $_.SourceCidrIp -eq $sourceCidr
})
if ($matchingAfter.Count -ne 1 -or $after.Count -ne ($rules.Count + 1)) { throw 'Exact rule did not converge.' }
$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
$state.authorized = $true
$state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8NoBOM
Write-Host 'The exact campus-link Aliyun UDP/443 /32 rule is authorized.'
