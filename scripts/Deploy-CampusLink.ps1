[CmdletBinding()]
param(
    [string]$AliyunCli = 'aliyun'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$transactionId = [guid]::NewGuid().ToString('N')
$state = Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.state\openwrt-lab-2.json') | ConvertFrom-Json
$labIp = ($state.networks.v4 | Where-Object type -eq 'public' | Select-Object -First 1).ip_address
if (-not $labIp) { throw 'The lab host has no recorded public IPv4 address.' }

function Assert-NativeSuccess([string]$Message) {
    if ($LASTEXITCODE -ne 0) { throw $Message }
}

function Test-SafeRelayHost([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 253) { return $false }
    if ($Value.StartsWith('.') -or $Value.EndsWith('.') -or $Value.Contains('..')) { return $false }
    $parts = @($Value.Split('.'))
    if ($Value -match '^[0-9.]+$') {
        if ($parts.Count -ne 4) { return $false }
        foreach ($part in $parts) {
            $number = 0
            if ($part -notmatch '^(0|[1-9][0-9]{0,2})$' -or
                -not [int]::TryParse($part, [ref]$number) -or $number -gt 255) { return $false }
        }
        return $true
    }
    foreach ($part in $parts) {
        if ($part.Length -lt 1 -or $part.Length -gt 63 -or
            $part -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') { return $false }
    }
    return $true
}

if ($labIp -notmatch '^[0-9.]+$' -or -not (Test-SafeRelayHost $labIp)) {
    throw 'The recorded lab destination is not a canonical IPv4 address.'
}

$gzConfig = @{}
& ssh -G gz | ForEach-Object {
    $pair = $_ -split '\s+', 2
    if ($pair.Count -eq 2 -and -not $gzConfig.ContainsKey($pair[0])) { $gzConfig[$pair[0]] = $pair[1] }
}
Assert-NativeSuccess 'Could not resolve the gz SSH configuration.'
$relayAddress = $gzConfig.hostname
if (-not (Test-SafeRelayHost $relayAddress)) {
    throw 'The gz HostName is not a safe IPv4 address or DNS name for the edge configuration.'
}

& ssh gz 'set -eu; if systemctl is-active --quiet campus-link-relay.service; then exit 0; fi; ! ss -H -ltn "sport = :443" | grep -q .; ! ss -H -lun "sport = :443" | grep -q .'
Assert-NativeSuccess 'gz TCP/443 or UDP/443 is owned by another service.'

$names = @(
    'campus-link-relay', 'relay-control.crt', 'relay-control.key', 'control-ca.crt',
    'relay.json', 'campus-link-relay.service', 'install-relay.sh',
    'rollback-relay.sh', 'provision-relay-identity.sh', 'provision-relay-fault-access.sh',
    'relay-restart-authorized.sh', 'relay-restart-actuator.sh',
    'relay-restart-permit-authorize.sh',
    'VERSION', 'SOURCE_TREE.sha256', 'SOURCE_COMMIT', 'MANIFEST.sha256'
)
$releaseRoot = '/srv/openwrt-lab/build/campus-link/release'
$remoteStage = "/tmp/campus-link-stage-$transactionId"
$relayHostKeyTemp = "/run/campus-link-relay-host-key-$transactionId.pub"
$relayInputDir = "/run/campus-link-fault-input-$transactionId"
$relayFaultPublicTemp = "$relayInputDir/id_ed25519.pub"
$relayPermitPublicTemp = "$relayInputDir/permit_ed25519.pub.pem"
$edgePrepared = $false
$edgeInstallAttempted = $false
$relayPrepared = $false
$relayInstallAttempted = $false
$remoteStageCreated = $false
$relayInputDirCreated = $false

function Remove-RemoteStage {
    if (-not $remoteStageCreated) { return }
    $quotedNames = ($names | ForEach-Object { "'$remoteStage/$_'" }) -join ' '
    $null = & ssh gz "set -eu; rm -f -- $quotedNames; rmdir -- '$remoteStage'"
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove the bounded relay stage.' }
    $script:remoteStageCreated = $false
}

function Remove-RelayInputDirectory {
    if (-not $relayInputDirCreated) { return }
    $null = & ssh gz "set -eu; test -d '$relayInputDir' -a ! -L '$relayInputDir'; test `$(stat -c '%u:%g:%a' -- '$relayInputDir') = 0:0:700; rm -f -- '$relayFaultPublicTemp' '$relayPermitPublicTemp'; rmdir -- '$relayInputDir'"
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove the bounded relay authority-input directory.' }
    $script:relayInputDirCreated = $false
}

try {
    & scp -3 'gz:/etc/ssh/ssh_host_ed25519_key.pub' "root@${labIp}:$relayHostKeyTemp"
    Assert-NativeSuccess 'Could not transfer the trusted relay Ed25519 host public key.'
    $edgeCommand = "set -eu; trap 'rm -f -- `"$relayHostKeyTemp`" || :' EXIT; export CAMPUS_LINK_TRANSACTION_ID='$transactionId' CAMPUS_LINK_LAB_ONLY=1 GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/srv/openwrt-lab/repo; cd /srv/openwrt-lab/repo; git pull --ff-only; chmod 0600 '$relayHostKeyTemp'; ./campus-link/scripts/install-edge-lab.sh /srv/openwrt-lab/repo '$relayAddress' '$relayHostKeyTemp'"
    $edgeInstallAttempted = $true
    & ssh "root@$labIp" $edgeCommand
    Assert-NativeSuccess 'Edge build, preflight, or installation failed.'
    $edgePrepared = $true

    $edgeRestartEvidenceCommand = @'
set -eu
manifest=/srv/openwrt-lab/build/campus-link/release/MANIFEST.sha256
test -f "${manifest}" -a ! -L "${manifest}"
verify() {
  logical=$1
  installed=$2
  test -f "${installed}" -a ! -L "${installed}" -a -x "${installed}"
  lines=$(grep -F "  ${logical}" "${manifest}" || true)
  test "$(printf '%s\n' "${lines}" | grep -c .)" -eq 1
  test "${lines#*  }" = "${logical}"
  expected=${lines%% *}
  actual=$(sha256sum "${installed}" | awk '{print $1}')
  test "${actual}" = "${expected}"
  printf '%s\n' "${actual}"
}
verify scripts/relay-restart-driver.sh /usr/local/libexec/campus-link-relay-restart-driver
verify scripts/relay-restart-transport.sh /usr/local/libexec/campus-link-relay-restart-transport
'@
    $edgeRestartEvidence = @(& ssh "root@$labIp" $edgeRestartEvidenceCommand)
    Assert-NativeSuccess 'Could not verify the installed gate-local relay-restart authority.'
    if ($edgeRestartEvidence.Count -ne 2 -or
        @($edgeRestartEvidence | Where-Object { $_ -notmatch '^[a-f0-9]{64}$' }).Count -ne 0) {
        throw 'The installed gate-local relay-restart authority evidence is malformed.'
    }

    & ssh gz "set -eu; test ! -e '$remoteStage'; install -d -m 0700 '$remoteStage'"
    Assert-NativeSuccess 'Could not create a fresh bounded relay stage.'
    $remoteStageCreated = $true
    & ssh gz "set -eu; test ! -e '$relayInputDir'; install -d -m 0700 -o root -g root '$relayInputDir'"
    Assert-NativeSuccess 'Could not create a fresh bounded relay authority-input directory.'
    $relayInputDirCreated = $true
    $builderManifestRecord = & ssh "root@$labIp" "set -eu; sha256sum '$releaseRoot/MANIFEST.sha256'"
    Assert-NativeSuccess 'Could not hash the verified remote manifest.'
    $builderManifestHash = @($builderManifestRecord -split '\s+')[0]
    if ($builderManifestHash -notmatch '^[a-f0-9]{64}$') { throw 'The verified remote manifest hash is malformed.' }
    & scp -3 "root@${labIp}:$releaseRoot/bin/campus-link-relay" "gz:$remoteStage/campus-link-relay"
    Assert-NativeSuccess 'Could not retrieve the relay binary.'
    & scp -3 "root@${labIp}:$releaseRoot/VERSION" "gz:$remoteStage/VERSION"
    Assert-NativeSuccess 'Could not retrieve the relay version.'
    & scp -3 "root@${labIp}:$releaseRoot/SOURCE_TREE.sha256" "gz:$remoteStage/SOURCE_TREE.sha256"
    Assert-NativeSuccess 'Could not retrieve the source-tree binding.'
    & scp -3 "root@${labIp}:$releaseRoot/SOURCE_COMMIT" "gz:$remoteStage/SOURCE_COMMIT"
    Assert-NativeSuccess 'Could not retrieve the source commit binding.'
    & scp -3 "root@${labIp}:$releaseRoot/MANIFEST.sha256" "gz:$remoteStage/MANIFEST.sha256"
    Assert-NativeSuccess 'Could not retrieve the release manifest.'
    & scp -3 "root@${labIp}:$releaseRoot/config/relay.json" "gz:$remoteStage/relay.json"
    Assert-NativeSuccess 'Could not retrieve the public relay authorization.'
    & scp -3 "root@${labIp}:/etc/campus-link/pki/relay-control.crt" "gz:$remoteStage/relay-control.crt"
    Assert-NativeSuccess 'Could not retrieve the relay certificate.'
    & scp -3 "root@${labIp}:/etc/campus-link/pki/relay-control.key" "gz:$remoteStage/relay-control.key"
    Assert-NativeSuccess 'Could not retrieve the relay leaf key.'
    & scp -3 "root@${labIp}:/etc/campus-link/pki/control-ca.crt" "gz:$remoteStage/control-ca.crt"
    Assert-NativeSuccess 'Could not retrieve the public control root.'
    & scp -3 "root@${labIp}:$releaseRoot/systemd/campus-link-relay.service" "gz:$remoteStage/campus-link-relay.service"
    Assert-NativeSuccess 'Could not upload the relay service unit.'
    & scp -3 "root@${labIp}:$releaseRoot/scripts/install-relay.sh" "gz:$remoteStage/install-relay.sh"
    Assert-NativeSuccess 'Could not upload the relay installer.'
    & scp -3 "root@${labIp}:$releaseRoot/scripts/rollback-relay.sh" "gz:$remoteStage/rollback-relay.sh"
    Assert-NativeSuccess 'Could not upload the relay rollback helper.'
    & scp -3 "root@${labIp}:$releaseRoot/scripts/provision-relay-identity.sh" "gz:$remoteStage/provision-relay-identity.sh"
    Assert-NativeSuccess 'Could not upload the relay identity bootstrap.'
    & scp -3 "root@${labIp}:$releaseRoot/scripts/provision-relay-fault-access.sh" "gz:$remoteStage/provision-relay-fault-access.sh"
    Assert-NativeSuccess 'Could not upload the relay fault-access bootstrap.'
    & scp -3 "root@${labIp}:$releaseRoot/scripts/relay-restart-authorized.sh" "gz:$remoteStage/relay-restart-authorized.sh"
    Assert-NativeSuccess 'Could not upload the relay restart forced command.'
    & scp -3 "root@${labIp}:$releaseRoot/scripts/relay-restart-actuator.sh" "gz:$remoteStage/relay-restart-actuator.sh"
    Assert-NativeSuccess 'Could not upload the relay restart actuator.'
    & scp -3 "root@${labIp}:$releaseRoot/scripts/relay-restart-permit-authorize.sh" "gz:$remoteStage/relay-restart-permit-authorize.sh"
    Assert-NativeSuccess 'Could not upload the relay restart permit authorizer.'
    $stagedManifestRecord = & ssh gz "set -eu; sha256sum '$remoteStage/MANIFEST.sha256'"
    Assert-NativeSuccess 'Could not hash the staged relay manifest.'
    $stagedManifestHash = @($stagedManifestRecord -split '\s+')[0]
    if ($stagedManifestHash -ne $builderManifestHash) { throw 'The staged manifest differs from the verified remote manifest.' }
    $remoteVerifier = @'
set -eu
cd '__STAGE__'
verify() {
  logical=$1
  file=$2
  lines=$(grep -F "  ${logical}" MANIFEST.sha256 || true)
  test "$(printf '%s\n' "${lines}" | grep -c .)" -eq 1
  test "${lines#*  }" = "${logical}"
  expected=${lines%% *}
  actual=$(sha256sum "${file}" | awk '{print $1}')
  test "${actual}" = "${expected}"
}
verify bin/campus-link-relay campus-link-relay
verify config/relay.json relay.json
verify scripts/install-relay.sh install-relay.sh
verify scripts/rollback-relay.sh rollback-relay.sh
verify scripts/provision-relay-identity.sh provision-relay-identity.sh
verify scripts/provision-relay-fault-access.sh provision-relay-fault-access.sh
verify scripts/relay-restart-actuator.sh relay-restart-actuator.sh
verify scripts/relay-restart-authorized.sh relay-restart-authorized.sh
verify scripts/relay-restart-permit-authorize.sh relay-restart-permit-authorize.sh
verify systemd/campus-link-relay.service campus-link-relay.service
verify relay-pki/control-ca.crt control-ca.crt
verify relay-pki/relay-control.crt relay-control.crt
verify relay-pki/relay-control.key relay-control.key
verify VERSION VERSION
verify SOURCE_TREE.sha256 SOURCE_TREE.sha256
verify SOURCE_COMMIT SOURCE_COMMIT
'@.Replace('__STAGE__', $remoteStage)
    & ssh gz $remoteVerifier
    Assert-NativeSuccess 'The staged relay payload does not match its manifest.'
    & ssh gz "set -eu; /bin/bash '$remoteStage/provision-relay-identity.sh'"
    Assert-NativeSuccess 'Relay service identity provisioning or validation failed.'
    & scp -3 "root@${labIp}:/etc/campus-link/relay-fault/id_ed25519.pub" "gz:$relayFaultPublicTemp"
    Assert-NativeSuccess 'Could not transfer the gate public key to the relay transaction input.'
    & scp -3 "root@${labIp}:/etc/campus-link/relay-fault/permit_ed25519.pub.pem" "gz:$relayPermitPublicTemp"
    Assert-NativeSuccess 'Could not transfer the gate permit public key to the relay transaction input.'
    & ssh gz "set -eu; chmod 0600 '$relayFaultPublicTemp' '$relayPermitPublicTemp'; /bin/bash '$remoteStage/provision-relay-fault-access.sh' bootstrap-relay-account"
    Assert-NativeSuccess 'Relay fault account bootstrap or exact-state validation failed.'
    $relayInstallAttempted = $true
    & ssh gz "set -eu; export CAMPUS_LINK_TRANSACTION_ID='$transactionId'; /bin/bash '$remoteStage/install-relay.sh' '$remoteStage' '$relayFaultPublicTemp' '$relayPermitPublicTemp' '${labIp}/32'"
    Assert-NativeSuccess 'Relay preflight or installation failed.'
    $relayPrepared = $true
    & ssh gz "set -eu; /usr/local/libexec/campus-link-provision-relay-fault-access relay-state '$relayFaultPublicTemp' '$relayPermitPublicTemp' '${labIp}/32'"
    Assert-NativeSuccess 'Installed relay fault authority does not match the transaction input.'

    $installedEvidenceCommand = @'
set -eu
attestation=/var/lib/campus-link/deployment-attestation.env
manifest=/var/lib/campus-link/installed-release-manifest.sha256
test -f "${attestation}" && test ! -L "${attestation}"
test -f "${manifest}" && test ! -L "${manifest}"
test "$(stat -c '%U:%G:%a' "${attestation}")" = root:root:600
test "$(stat -c '%U:%G:%a' "${manifest}")" = root:root:600
test "$(wc -l < "${attestation}")" -eq 3
grep -Eq '^VERSION=phase1-[a-f0-9]{12}-[a-f0-9]{12}$' "${attestation}"
grep -Eq '^SOURCE_TREE_SHA256=[a-f0-9]{64}$' "${attestation}"
grep -Fqx 'MANIFEST_SHA256=__MANIFEST__' "${attestation}"
test "$(sha256sum "${manifest}" | awk '{print $1}')" = __MANIFEST__
sha256sum "${attestation}" "${manifest}" | awk '{print $1}'
'@.Replace('__MANIFEST__', $builderManifestHash)
    $edgeInstalledEvidence = @(& ssh "root@$labIp" $installedEvidenceCommand)
    Assert-NativeSuccess 'Could not verify the installed edge release evidence.'
    $relayInstalledEvidence = @(& ssh gz $installedEvidenceCommand)
    Assert-NativeSuccess 'Could not verify the installed relay release evidence.'
    if ($edgeInstalledEvidence.Count -ne 2 -or $relayInstalledEvidence.Count -ne 2 -or
        @($edgeInstalledEvidence + $relayInstalledEvidence | Where-Object { $_ -notmatch '^[a-f0-9]{64}$' }).Count -ne 0 -or
        $edgeInstalledEvidence[0] -ne $relayInstalledEvidence[0] -or
        $edgeInstalledEvidence[1] -ne $builderManifestHash -or
        $relayInstalledEvidence[1] -ne $builderManifestHash) {
        throw 'Installed edge and relay release evidence do not match the verified candidate.'
    }
    Remove-RemoteStage
    Remove-RelayInputDirectory

    & (Join-Path $PSScriptRoot 'Authorize-CampusLinkAliyunIngress.ps1') -AliyunCli $AliyunCli -Confirm:$false
    $edgeActivation = @'
set -eu
old_a=$(systemctl show --property=InvocationID --value campus-link-edge-a.service 2>/dev/null || true)
old_b=$(systemctl show --property=InvocationID --value campus-link-edge-b.service 2>/dev/null || true)
systemctl stop campus-link-external.target campus-link-edge-a.service campus-link-edge-b.service campus-link-topology.service
for unit in campus-link-external.target campus-link-edge-a.service campus-link-edge-b.service campus-link-topology.service; do
  state=$(systemctl show --property=ActiveState --value "${unit}")
  test "${state}" = inactive -o "${state}" = failed
done
systemctl start campus-link-external.target
for unit in campus-link-external.target campus-link-topology.service campus-link-edge-a.service campus-link-edge-b.service; do
  systemctl is-active --quiet "${unit}"
done
new_a=$(systemctl show --property=InvocationID --value campus-link-edge-a.service)
new_b=$(systemctl show --property=InvocationID --value campus-link-edge-b.service)
test -n "${new_a}" -a -n "${new_b}" -a "${new_a}" != "${new_b}"
test "${new_a}" != "${old_a}" -a "${new_b}" != "${old_b}"
/usr/local/libexec/campus-link-smoke-external
'@
    & ssh "root@$labIp" $edgeActivation
    Assert-NativeSuccess 'External campus-link smoke test failed.'
}
catch {
    $originalFailure = $_
    $rollbackFailures = [System.Collections.Generic.List[string]]::new()
    if ($relayInstallAttempted) {
        $missingSnapshotExit = if ($relayPrepared) { 44 } else { 0 }
        $relayRecovery = "set -eu; snapshot='/var/lib/campus-link/rollback-relay/snapshots/$transactionId'; if test -f `$snapshot/.rolled-back && test `$(cat `$snapshot/.rolled-back) = '$transactionId'; then exit 0; elif test -f `$snapshot/.complete; then if test -f '$remoteStage/rollback-relay.sh'; then /bin/bash '$remoteStage/rollback-relay.sh' '$transactionId'; else /usr/local/libexec/campus-link-rollback-relay '$transactionId'; fi; else exit $missingSnapshotExit; fi"
        & ssh gz $relayRecovery
        if ($LASTEXITCODE -ne 0) { $rollbackFailures.Add('relay rollback') }
    }
    if ($edgeInstallAttempted) {
        $missingSnapshotExit = if ($edgePrepared) { 44 } else { 0 }
        $edgeRecovery = "set -eu; snapshot='/var/lib/campus-link/rollback-edge/snapshots/$transactionId'; if test -f `$snapshot/.rolled-back && test `$(cat `$snapshot/.rolled-back) = '$transactionId'; then exit 0; elif test -f `$snapshot/.complete; then if test -f '/srv/openwrt-lab/repo/campus-link/scripts/rollback-edge.sh'; then /bin/bash '/srv/openwrt-lab/repo/campus-link/scripts/rollback-edge.sh' '$transactionId'; else /usr/local/libexec/campus-link-rollback-edge '$transactionId'; fi; else exit $missingSnapshotExit; fi"
        & ssh "root@$labIp" $edgeRecovery
        if ($LASTEXITCODE -ne 0) { $rollbackFailures.Add('edge rollback') }
        & ssh "root@$labIp" 'set -eu; if systemctl is-active --quiet campus-link-external.target; then /usr/local/libexec/campus-link-smoke-external; fi'
        if ($LASTEXITCODE -ne 0) { $rollbackFailures.Add('prior-path smoke') }
    }
    if ($rollbackFailures.Count -ne 0) {
        throw "Deployment failed ($($originalFailure.Exception.Message)); exact recovery failed at: $($rollbackFailures -join ', ')."
    }
    throw $originalFailure
}
finally {
    try { Remove-RemoteStage } catch { Write-Warning "Remote stage cleanup also failed: $($_.Exception.Message)" }
    try { Remove-RelayInputDirectory } catch { Write-Warning "Relay authority-input cleanup also failed: $($_.Exception.Message)" }
    $null = & ssh "root@$labIp" "rm -f -- '$relayHostKeyTemp'" 2>$null
}

Write-Host 'campus-link external relay lab deployed and smoke-tested.'
