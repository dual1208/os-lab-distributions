#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-qualification}
if [[ -f /usr/local/libexec/campus-link-a11-b22.py ]]; then
  readonly PROBE=/usr/local/libexec/campus-link-a11-b22.py
else
  readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
fi
[[ -f ${PROBE} && ! -L ${PROBE} ]]

clear_profile() {
  local output ok=1
  ip netns exec campus-a tc qdisc del dev cl-a-wan root 2>/dev/null || true
  output=$(ip netns exec campus-a tc qdisc show dev cl-a-wan) || return 1
  ! grep -Eq '^qdisc[[:space:]]+netem[[:space:]].*[[:space:]]root([[:space:]]|$)' \
    <<< "${output}" || ok=0
  ip netns exec campus-b tc qdisc del dev cl-b-wan root 2>/dev/null || true
  output=$(ip netns exec campus-b tc qdisc show dev cl-b-wan) || return 1
  ! grep -Eq '^qdisc[[:space:]]+netem[[:space:]].*[[:space:]]root([[:space:]]|$)' \
    <<< "${output}" || ok=0
  (( ok != 0 ))
}

apply_profile() {
  ip netns exec campus-a tc qdisc replace dev cl-a-wan root netem \
    delay 100ms 20ms loss 1% reorder 0.1% 25%
  ip netns exec campus-b tc qdisc replace dev cl-b-wan root netem \
    delay 100ms 20ms loss 1% reorder 0.1% 25%
}

cleanup() {
  clear_profile
  kill "${server:-}" 2>/dev/null || true
}

case ${MODE} in
  apply-profile)
    apply_profile
    exit 0
    ;;
  clear-profile)
    clear_profile
    exit 0
    ;;
  qualification) ;;
  *)
    echo 'usage: test-netem.sh [REPO_ROOT] [qualification|apply-profile|clear-profile]' >&2
    exit 2
    ;;
esac

trap cleanup EXIT
apply_profile
ip netns exec oslab-b python3 -B "${PROBE}" serve --bind 10.82.0.22 >/dev/null 2>&1 &
server=$!
sleep 1
timeout 10m ip netns exec oslab-a python3 -B "${PROBE}" client \
  --source 10.81.0.11 --destination 10.82.0.22 \
  --records 100 --concurrency 10 --bulk-bytes 1048576 \
  --udp-packets 100 --udp-interval-ms 30 --udp-wait-seconds 5 --min-udp-ratio 0.75
