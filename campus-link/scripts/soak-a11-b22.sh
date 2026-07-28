#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-one-hour}
readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
readonly PORT=18090
readonly RESULT=/run/campus-link/a11-b22-soak-${MODE}.result
case ${MODE} in
  one-hour) duration=3600 ;;
  24-hour) duration=86400 ;;
  *) echo 'usage: soak-a11-b22.sh [REPO_ROOT] [one-hour|24-hour]' >&2; exit 2 ;;
esac
if [[ ${MODE} == 24-hour ]]; then
  while systemctl is-active --quiet campus-link-accelerated-fault.service && \
        [[ ! -f /run/campus-link/accelerated-fault-soak.result ]]; do
    sleep 60
  done
  [[ -f /run/campus-link/accelerated-fault-soak.result ]]
fi
rm -f "${RESULT}"

ip netns exec oslab-a python3 "${PROBE}" serve --bind 10.81.0.11 --tcp-port "${PORT}" --udp-port 18091 >/dev/null 2>&1 &
server_a=$!
ip netns exec oslab-b python3 "${PROBE}" serve --bind 10.82.0.22 --tcp-port "${PORT}" --udp-port 18091 >/dev/null 2>&1 &
server_b=$!
trap 'kill ${server_a} ${server_b} 2>/dev/null || true' EXIT
sleep 1
started=$(date +%s)
deadline=$((started + duration))
probes=0

while (( $(date +%s) < deadline )); do
  systemctl is-active --quiet campus-link-edge-a.service campus-link-edge-b.service
  ip -n campus-a route show 10.82.0.0/24 | grep -q 'dev cl0'
  ip -n campus-b route show 10.81.0.0/24 | grep -q 'dev cl0'
  timeout 5 ip netns exec oslab-a python3 "${PROBE}" health \
    --source 10.81.0.11 --destination 10.82.0.22 --tcp-port "${PORT}" >/dev/null
  timeout 5 ip netns exec oslab-b python3 "${PROBE}" health \
    --source 10.82.0.22 --destination 10.81.0.11 --tcp-port "${PORT}" >/dev/null
  probes=$((probes + 2))
  sleep 10
done

printf 'STATUS=pass\nMODE=%s\nDURATION_SECONDS=%s\nAPPLICATION_PROBES=%s\n' \
  "${MODE}" "${duration}" "${probes}" > "${RESULT}"
cat "${RESULT}"
