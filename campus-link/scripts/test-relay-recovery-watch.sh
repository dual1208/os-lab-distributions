#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ -f /usr/local/libexec/campus-link-a11-b22.py ]]; then
  readonly PROBE=/usr/local/libexec/campus-link-a11-b22.py
else
  readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
fi
readonly READY=/run/campus-link/relay-recovery.ready
readonly RESULT=/run/campus-link/relay-recovery.result
readonly EDGE_A_STATUS=/run/campus-link/site-a/status.json
readonly EDGE_B_STATUS=/run/campus-link/site-b/status.json
[[ -f ${PROBE} && ! -L ${PROBE} ]]
rm -f -- "${READY}" "${RESULT}"

status_snapshot() {
  python3 -B - "${EDGE_A_STATUS}" "${EDGE_B_STATUS}" <<'PY'
import json, sys
values = []
for expected, path in (("site-a", sys.argv[1]), ("site-b", sys.argv[2])):
    with open(path, "r", encoding="utf-8") as source:
        status = json.load(source)
    path_status = status.get("path", {})
    telemetry = status.get("relay_telemetry", {})
    if status.get("site") != expected:
        raise SystemExit("site mismatch")
    if path_status.get("direct_required") is not True:
        raise SystemExit("direct-required policy absent")
    if path_status.get("selected") != "direct" or path_status.get("direct_healthy") is not True:
        raise SystemExit("direct path changed")
    counters = (
        telemetry.get("control_session"), path_status.get("direct_epoch"),
        path_status.get("direct_instance"), path_status.get("relay_sent_packets"),
        path_status.get("relay_received_packets"),
    )
    if any(type(item) is not int or item < 0 for item in counters) or any(item == 0 for item in counters[:3]):
        raise SystemExit("invalid status counter")
    values.extend((str(counters[0]), str(counters[1]), str(counters[2]),
                   "1" if path_status.get("relay_healthy") is True else "0",
                   str(counters[3]), str(counters[4])))
print(" ".join(values))
PY
}

health() {
  timeout 3 ip netns exec oslab-a python3 -B "${PROBE}" health \
    --source 10.81.0.11 --destination 10.82.0.22 >/dev/null 2>&1
}

ip netns exec oslab-b python3 -B "${PROBE}" serve --bind 10.82.0.22 >/dev/null 2>&1 &
server=$!
trap 'kill ${server} 2>/dev/null || true' EXIT
sleep 1
health
read -r base_a_session base_a_epoch base_a_instance base_a_relay_healthy base_a_sent base_a_received \
  base_b_session base_b_epoch base_b_instance base_b_relay_healthy base_b_sent base_b_received \
  < <(status_snapshot)
[[ ${base_a_relay_healthy} == 1 && ${base_b_relay_healthy} == 1 ]]
touch "${READY}"
started=$(awk '{printf "%d\n", $1 * 1000}' /proc/uptime)
deadline=$((started + 30000))

while :; do
  now=$(awk '{printf "%d\n", $1 * 1000}' /proc/uptime)
  (( now < deadline )) || break
  ip -n campus-a route show 10.82.0.0/24 | grep -q 'dev cl0'
  ip -n campus-b route show 10.81.0.0/24 | grep -q 'dev cl0'
  health || {
    printf 'recovery_ms=failed route_withdrawn=0 traffic_interruptions=1 direct_preserved=0 relay_data_delta=unknown control_recovered=0\n' > "${RESULT}"
    exit 1
  }
  read -r a_session a_epoch a_instance a_relay_healthy a_sent a_received \
    b_session b_epoch b_instance b_relay_healthy b_sent b_received < <(status_snapshot)
  [[ ${a_epoch} == "${base_a_epoch}" && ${b_epoch} == "${base_b_epoch}" ]]
  [[ ${a_instance} == "${base_a_instance}" && ${b_instance} == "${base_b_instance}" ]]
  [[ ${a_sent} == "${base_a_sent}" && ${a_received} == "${base_a_received}" ]]
  [[ ${b_sent} == "${base_b_sent}" && ${b_received} == "${base_b_received}" ]]
  if [[ ${a_session} != "${base_a_session}" && ${b_session} != "${base_b_session}" &&
        ${a_relay_healthy} == 1 && ${b_relay_healthy} == 1 ]]; then
    printf 'recovery_ms=%s route_withdrawn=0 traffic_interruptions=0 direct_preserved=1 relay_data_delta=0 control_recovered=1\n' \
      "$((now - started))" | tee "${RESULT}"
    exit 0
  fi
  sleep 0.2
done
printf 'recovery_ms=timeout route_withdrawn=0 traffic_interruptions=0 direct_preserved=1 relay_data_delta=0 control_recovered=0\n' > "${RESULT}"
exit 1
