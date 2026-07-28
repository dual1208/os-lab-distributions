[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$state = Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.state\openwrt-lab-2.json') | ConvertFrom-Json
$labIp = ($state.networks.v4 | Where-Object type -eq 'public' | Select-Object -First 1).ip_address
if (-not $labIp) { throw 'The lab host has no recorded public IPv4 address.' }

$gzConfig = @{}
& ssh -G gz | ForEach-Object {
    $pair = $_ -split '\s+', 2
    if ($pair.Count -eq 2 -and -not $gzConfig.ContainsKey($pair[0])) {
        $gzConfig[$pair[0]] = $pair[1]
    }
}
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the gz SSH configuration.' }
$relayAddress = $gzConfig.hostname
if (-not $relayAddress -or $relayAddress -notmatch '^[A-Za-z0-9.-]+$') {
    throw 'The gz HostName is not a safe IPv4 address or DNS name for the edge configuration.'
}

& ssh gz 'set -eu; ! ss -H -ltn "sport = :443" | grep -q .; ! ss -H -lun "sport = :443" | grep -q .'
if ($LASTEXITCODE -ne 0) { throw 'gz TCP/443 or UDP/443 became occupied; deployment stopped.' }

$edgeCommand = "set -eu; export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/srv/openwrt-lab/repo; cd /srv/openwrt-lab/repo; git pull --ff-only; ./campus-link/scripts/install-edge-lab.sh /srv/openwrt-lab/repo '$relayAddress'"
& ssh "root@$labIp" $edgeCommand
if ($LASTEXITCODE -ne 0) { throw 'Edge build or installation failed.' }

$stage = Join-Path $repoRoot '.state\campus-link-relay-stage'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
$names = @('campus-link-relay','relay-control.crt','relay-control.key','control-ca.crt','campus-link-relay.service','install-relay.sh')
foreach ($name in $names) {
    $path = Join-Path $stage $name
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}
& scp "root@${labIp}:/srv/openwrt-lab/build/campus-link/campus-link-relay" (Join-Path $stage 'campus-link-relay')
& scp "root@${labIp}:/etc/campus-link/pki/relay-control.crt" (Join-Path $stage 'relay-control.crt')
& scp "root@${labIp}:/etc/campus-link/pki/relay-control.key" (Join-Path $stage 'relay-control.key')
& scp "root@${labIp}:/etc/campus-link/pki/control-ca.crt" (Join-Path $stage 'control-ca.crt')
if ($LASTEXITCODE -ne 0) { throw 'Could not retrieve the bounded relay payload.' }
Copy-Item -LiteralPath (Join-Path $repoRoot 'campus-link\systemd\campus-link-relay.service') -Destination (Join-Path $stage 'campus-link-relay.service')
Copy-Item -LiteralPath (Join-Path $repoRoot 'campus-link\scripts\install-relay.sh') -Destination (Join-Path $stage 'install-relay.sh')

& ssh gz 'set -eu; install -d -m 0700 /tmp/campus-link-stage; rm -f /tmp/campus-link-stage/campus-link-relay /tmp/campus-link-stage/relay-control.crt /tmp/campus-link-stage/relay-control.key /tmp/campus-link-stage/control-ca.crt /tmp/campus-link-stage/campus-link-relay.service /tmp/campus-link-stage/install-relay.sh'
foreach ($name in $names) {
    & scp (Join-Path $stage $name) "gz:/tmp/campus-link-stage/$name"
    if ($LASTEXITCODE -ne 0) { throw "Could not upload relay payload item: $name" }
}
& ssh gz 'set -eu; /bin/bash /tmp/campus-link-stage/install-relay.sh /tmp/campus-link-stage; rm -f /tmp/campus-link-stage/campus-link-relay /tmp/campus-link-stage/relay-control.crt /tmp/campus-link-stage/relay-control.key /tmp/campus-link-stage/control-ca.crt /tmp/campus-link-stage/campus-link-relay.service /tmp/campus-link-stage/install-relay.sh; rmdir /tmp/campus-link-stage'
if ($LASTEXITCODE -ne 0) { throw 'Relay installation failed.' }

& ssh "root@$labIp" 'systemctl start campus-link-external.target; /usr/local/libexec/campus-link-smoke-external'
if ($LASTEXITCODE -ne 0) { throw 'External campus-link smoke test failed.' }
Write-Host 'campus-link external relay lab deployed and smoke-tested.'
