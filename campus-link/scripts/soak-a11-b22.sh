#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-one-hour}
readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
readonly PORT=18090
readonly RESULT=/run/campus-link/a11-b22-soak-${MODE}.result
readonly FAILURE=/run/campus-link/a11-b22-soak-${MODE}.failure
readonly RECOVERY_BUDGET_SECONDS=30
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
rm -f "${RESULT}" "${FAILURE}"

probes=0
attempts=0
transient_misses=0
recovered_outages=0
max_outage_ms=0

fail_soak() {
  local direction=$1 failure_class=$2
  local tmp=${FAILURE}.$$
  umask 077
  printf 'STATUS=fail\nMODE=%s\nDIRECTION=%s\nFAILURE_CLASS=%s\nAPPLICATION_PROBES=%s\nATTEMPTS=%s\nTRANSIENT_MISSES=%s\nRECOVERED_OUTAGES=%s\nMAX_OUTAGE_MS=%s\n' \
    "${MODE}" "${direction}" "${failure_class}" "${probes}" "${attempts}" \
    "${transient_misses}" "${recovered_outages}" "${max_outage_ms}" > "${tmp}"
  mv -f "${tmp}" "${FAILURE}"
  exit 1
}

probe_direction() {
  local direction=$1 source=$2 destination=$3
  local outage_started_ms=0
  local recovery_deadline=0
  local rc now_ms outage_ms
  while true; do
    attempts=$((attempts + 1))
    set +e
    timeout 5 ip netns exec "${source}" python3 "${PROBE}" health \
      --source "${4}" --destination "${5}" --tcp-port "${PORT}" >/dev/null 2>&1
    rc=$?
    set -e
    case ${rc} in
      0)
        probes=$((probes + 1))
        if (( outage_started_ms != 0 )); then
          now_ms=$(date +%s%3N)
          outage_ms=$((now_ms - outage_started_ms))
          recovered_outages=$((recovered_outages + 1))
          (( outage_ms <= max_outage_ms )) || max_outage_ms=${outage_ms}
        fi
        return 0
        ;;
      75|124)
        transient_misses=$((transient_misses + 1))
        if (( outage_started_ms == 0 )); then
          outage_started_ms=$(date +%s%3N)
          recovery_deadline=$(($(date +%s) + RECOVERY_BUDGET_SECONDS))
        fi
        if (( $(date +%s) >= recovery_deadline )); then
          fail_soak "${direction}" availability-timeout
        fi
        sleep 1
        ;;
      76)
        fail_soak "${direction}" integrity
        ;;
      *)
        fail_soak "${direction}" probe-error
        ;;
    esac
  done
}

ip netns exec oslab-a python3 "${PROBE}" serve --bind 10.81.0.11 --tcp-port "${PORT}" --udp-port 18091 >/dev/null 2>&1 &
server_a=$!
ip netns exec oslab-b python3 "${PROBE}" serve --bind 10.82.0.22 --tcp-port "${PORT}" --udp-port 18091 >/dev/null 2>&1 &
server_b=$!
trap 'kill ${server_a} ${server_b} 2>/dev/null || true' EXIT
sleep 1
started=$(date +%s)
deadline=$((started + duration))

while (( $(date +%s) < deadline )); do
  kill -0 "${server_a}" "${server_b}" 2>/dev/null || fail_soak BOTH probe-server-dead
  systemctl is-active --quiet campus-link-edge-a.service campus-link-edge-b.service || fail_soak BOTH edge-inactive
  ip -n campus-a route show 10.82.0.0/24 | grep -q 'dev cl0' || fail_soak A_TO_B route-missing
  ip -n campus-b route show 10.81.0.0/24 | grep -q 'dev cl0' || fail_soak B_TO_A route-missing
  probe_direction A_TO_B oslab-a oslab-b 10.81.0.11 10.82.0.22
  probe_direction B_TO_A oslab-b oslab-a 10.82.0.22 10.81.0.11
  sleep 10
done

tmp=${RESULT}.$$
umask 077
printf 'STATUS=pass\nMODE=%s\nDURATION_SECONDS=%s\nAPPLICATION_PROBES=%s\nATTEMPTS=%s\nTRANSIENT_MISSES=%s\nRECOVERED_OUTAGES=%s\nMAX_OUTAGE_MS=%s\n' \
  "${MODE}" "${duration}" "${probes}" "${attempts}" "${transient_misses}" \
  "${recovered_outages}" "${max_outage_ms}" > "${tmp}"
mv -f "${tmp}" "${RESULT}"
cat "${RESULT}"
