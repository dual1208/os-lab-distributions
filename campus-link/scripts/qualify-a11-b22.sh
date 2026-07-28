#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-smoke}
readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
case ${MODE} in
  smoke) bulk_bytes=$((4 * 1024 * 1024)); records=10000; concurrency=100 ;;
  full) bulk_bytes=$((1024 * 1024 * 1024)); records=10000; concurrency=100 ;;
  *) echo 'usage: qualify-a11-b22.sh [REPO_ROOT] [smoke|full]' >&2; exit 2 ;;
esac

for required in oslab-a oslab-b campus-a campus-b; do
  ip netns list | grep -q "^${required}\b"
done
ip -n oslab-a address show dev ep-a | grep -q '10.81.0.11/24'
ip -n oslab-b address show dev ep-b | grep -q '10.82.0.22/24'

ip netns exec oslab-a python3 "${PROBE}" serve --bind 10.81.0.11 &
server_a=$!
ip netns exec oslab-b python3 "${PROBE}" serve --bind 10.82.0.22 &
server_b=$!
trap 'kill ${server_a} ${server_b} 2>/dev/null || true' EXIT
sleep 1

ip netns exec oslab-a python3 "${PROBE}" client \
  --source 10.81.0.11 --destination 10.82.0.22 \
  --records "${records}" --concurrency "${concurrency}" --bulk-bytes "${bulk_bytes}"
ip netns exec oslab-b python3 "${PROBE}" client \
  --source 10.82.0.22 --destination 10.81.0.11 \
  --records "${records}" --concurrency "${concurrency}" --bulk-bytes "${bulk_bytes}"
