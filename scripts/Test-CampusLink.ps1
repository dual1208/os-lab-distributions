[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$state = Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.state\openwrt-lab-2.json') | ConvertFrom-Json
$labIp = ($state.networks.v4 | Where-Object type -eq 'public' | Select-Object -First 1).ip_address
if (-not $labIp) { throw 'The lab host has no recorded public IPv4 address.' }

& ssh gz 'set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq tcpdump >/dev/null; rm -f /run/campus-link/udp443.pcap; systemd-run --quiet --collect --unit=campus-link-capture --property=RuntimeMaxSec=25 /usr/bin/tcpdump -ni any udp port 443 -c 96 -w /run/campus-link/udp443.pcap'
if ($LASTEXITCODE -ne 0) { throw 'Could not start the bounded relay capture.' }
Start-Sleep -Seconds 1
& ssh "root@$labIp" '/usr/local/libexec/campus-link-smoke-external'
if ($LASTEXITCODE -ne 0) { throw 'External traffic or policy smoke test failed.' }
Start-Sleep -Seconds 2
& ssh gz 'set -eu; systemctl stop campus-link-capture.service 2>/dev/null || true; test -s /run/campus-link/udp443.pcap; packets=$(tcpdump -nn -r /run/campus-link/udp443.pcap 2>/dev/null | wc -l); test "$packets" -gt 0; hex=$(od -An -tx1 -v /run/campus-link/udp443.pcap | tr -d " \n"); case "$hex" in *0a51000a0a52000a*|*0a52000a0a51000a*) exit 9;; esac; rm -f /run/campus-link/udp443.pcap; /usr/local/bin/campus-linkctl -status /run/campus-link/status.json'
if ($LASTEXITCODE -ne 0) { throw 'The relay capture was empty or exposed a plaintext inner LAN header.' }

$files = @(& ssh gz 'find /etc/campus-link -type f -printf "%f\n" | sort')
$expected = @('control-ca.crt','relay-control.crt','relay-control.key','relay.json')
if (Compare-Object $files $expected) { throw 'gz contains an unexpected campus-link file.' }
Write-Host 'campus-link mTLS, UDP binding, QUIC path, firewall denial, and no-plaintext capture checks passed.'
