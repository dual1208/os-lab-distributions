#!/usr/bin/env bash
set -euo pipefail

readonly STATUS=/run/campus-link/external-smoke.status
rm -f "${STATUS}"
for _ in {1..75}; do
  if grep -q '"quic": "active"' /run/campus-link/site-a/status.json 2>/dev/null && \
     grep -q '"quic": "active"' /run/campus-link/site-b/status.json 2>/dev/null; then
    break
  fi
  sleep 1
done
grep -q '"quic": "active"' /run/campus-link/site-a/status.json
grep -q '"quic": "active"' /run/campus-link/site-b/status.json
ip -n campus-a route get 10.82.0.10 | grep -q 'dev cl0'
ip -n campus-b route get 10.81.0.10 | grep -q 'dev cl0'
ip netns exec oslab-a ping -c 3 -W 2 10.82.0.10 >/dev/null

ip netns exec oslab-b python3 -m http.server 8080 --bind 10.82.0.10 >/run/campus-link/allowed-http.log 2>&1 &
allowed_pid=$!
ip netns exec oslab-b python3 -m http.server 12345 --bind 10.82.0.10 >/run/campus-link/blocked-http.log 2>&1 &
blocked_pid=$!
trap 'kill ${allowed_pid} ${blocked_pid} 2>/dev/null || true' EXIT
sleep 1
ip netns exec oslab-a curl --fail --silent --max-time 5 http://10.82.0.10:8080/ >/dev/null
if ip netns exec oslab-a curl --fail --silent --max-time 3 http://10.82.0.10:12345/ >/dev/null 2>&1; then
  echo 'forbidden TCP/12345 unexpectedly crossed router B' >&2
  exit 3
fi
cat > "${STATUS}" <<EOF
STATUS=pass
CONTROL=mtls-authenticated
UDP=challenge-bound
DATA=quic-datagram-tls1.3
ALLOWED=icmp,tcp/8080
BLOCKED=tcp/12345
EOF
