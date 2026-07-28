#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
readonly READY=/run/campus-link/relay-recovery.ready
readonly RESULT=/run/campus-link/relay-recovery.result
rm -f "${READY}" "${RESULT}"

ip netns exec oslab-b python3 "${PROBE}" serve --bind 10.82.0.22 >/dev/null 2>&1 &
server=$!
trap 'kill ${server} 2>/dev/null || true' EXIT
sleep 1
timeout 5 ip netns exec oslab-a python3 "${PROBE}" health \
  --source 10.81.0.11 --destination 10.82.0.22 >/dev/null
touch "${READY}"
started=$(date +%s%3N)
deadline=$((started + 30000))
withdrawn=0

while (( $(date +%s%3N) < deadline )); do
  if ! ip -n campus-a route show 10.82.0.0/24 | grep -q 'dev cl0'; then
    withdrawn=1
  fi
  if [[ ${withdrawn} -eq 1 ]] && \
     systemctl is-active --quiet campus-link-edge-a.service campus-link-edge-b.service && \
     ip -n campus-a route show 10.82.0.0/24 | grep -q 'dev cl0' && \
     timeout 5 ip netns exec oslab-a python3 "${PROBE}" health \
       --source 10.81.0.11 --destination 10.82.0.22 >/dev/null 2>&1; then
    finished=$(date +%s%3N)
    printf 'recovery_ms=%s route_withdrawn=%s\n' "$((finished - started))" "${withdrawn}" | tee "${RESULT}"
    exit 0
  fi
  sleep 0.2
done
printf 'recovery_ms=timeout route_withdrawn=%s\n' "${withdrawn}" > "${RESULT}"
exit 1
