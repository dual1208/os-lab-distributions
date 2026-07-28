#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py

cleanup() {
  ip netns exec campus-a tc qdisc del dev cl-a-wan root 2>/dev/null || true
  ip netns exec campus-b tc qdisc del dev cl-b-wan root 2>/dev/null || true
  kill "${server:-}" 2>/dev/null || true
}
trap cleanup EXIT

ip netns exec campus-a tc qdisc replace dev cl-a-wan root netem \
  delay 100ms 20ms loss 1% reorder 0.1% 25%
ip netns exec campus-b tc qdisc replace dev cl-b-wan root netem \
  delay 100ms 20ms loss 1% reorder 0.1% 25%
ip netns exec oslab-b python3 "${PROBE}" serve --bind 10.82.0.22 >/dev/null 2>&1 &
server=$!
sleep 1
timeout 10m ip netns exec oslab-a python3 "${PROBE}" client \
  --source 10.81.0.11 --destination 10.82.0.22 \
  --records 100 --concurrency 10 --bulk-bytes 1048576 \
  --udp-packets 100 --udp-interval-ms 30 --udp-wait-seconds 5 --min-udp-ratio 0.75
