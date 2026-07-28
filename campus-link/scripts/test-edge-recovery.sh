#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-smoke}
readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
readonly RESULTS=/run/campus-link/edge-recovery.tsv
case ${MODE} in
  smoke) trials=5 ;;
  full) trials=30 ;;
  *) echo 'usage: test-edge-recovery.sh [REPO_ROOT] [smoke|full]' >&2; exit 2 ;;
esac

ip netns exec oslab-b python3 "${PROBE}" serve --bind 10.82.0.22 >/dev/null 2>&1 &
server=$!
trap 'kill ${server} 2>/dev/null || true' EXIT
sleep 1
printf 'trial\trecovery_ms\troute_withdrawn\n' > "${RESULTS}"

health() {
  timeout 3 ip netns exec oslab-a python3 "${PROBE}" health \
    --source 10.81.0.11 --destination 10.82.0.22 >/dev/null 2>&1
}

for trial in $(seq 1 "${trials}"); do
  started=$(date +%s%3N)
  deadline=$((started + 30000))
  withdrawn=0
  systemctl kill --kill-whom=main --signal=KILL campus-link-edge-a.service
  while (( $(date +%s%3N) < deadline )); do
    if ! ip -n campus-a route show 10.82.0.0/24 | grep -q 'dev cl0'; then
      withdrawn=1
    fi
    if systemctl is-active --quiet campus-link-edge-a.service && \
       ip -n campus-a route show 10.82.0.0/24 | grep -q 'dev cl0' && health; then
      finished=$(date +%s%3N)
      printf '%s\t%s\t%s\n' "${trial}" "$((finished - started))" "${withdrawn}" >> "${RESULTS}"
      sleep 2
      continue 2
    fi
    sleep 0.2
  done
  echo "edge recovery trial ${trial} exceeded 30 seconds" >&2
  exit 1
done

awk -F '\t' 'NR > 1 { if ($2 > max) max=$2; if ($3 != 1) missing=1 } END { if (missing) exit 2; print "PASS trials=" (NR-1) " max_recovery_ms=" max }' "${RESULTS}"
