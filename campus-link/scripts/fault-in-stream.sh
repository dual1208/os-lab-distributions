#!/usr/bin/env bash
set -euo pipefail
ulimit -S -c 0
ulimit -H -c 0

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-production}
readonly RESULT=/run/campus-link/fault-in-stream.result
readonly PREREQUISITE=/run/campus-link/accelerated-fault-soak.result
readonly EDGE_A_STATUS=${CAMPUS_LINK_EDGE_A_STATUS:-/run/campus-link/site-a/status.json}
readonly EDGE_B_STATUS=${CAMPUS_LINK_EDGE_B_STATUS:-/run/campus-link/site-b/status.json}
readonly STREAM_PORT=18083
readonly SEND_SEQUENCE=51000000
readonly RECEIVE_SEQUENCE=52000000
readonly MEMORY_CEILING_BYTES=100663296
readonly STALL_GUARD_MS=250
readonly DIRECT_IDLE_TIMEOUT_MS=12000
readonly MAX_APPLICATION_OUTAGE_BOUND_MS=25000
readonly MUX_NO_PATH_DEADLINE_MS=30000
readonly IMPAIRED_MIN_MILLI_MBIT_S=2000
readonly RELAY_PROGRESS_MIN_BYTES=1048576
readonly RELAY_NEAR_UNBLOCK_WINDOW_MS=1000
readonly RELAY_RESTART_DRIVER_BUDGET_MILLISECONDS=360000
readonly RELAY_RESTART_OUTER_BUDGET_MILLISECONDS=390000
readonly RELAY_RESTART_ACTIVE_BUDGET_MILLISECONDS=150000
readonly RELAY_RESTART_DRIVER_CLEANUP_BUDGET_MILLISECONDS=14000
readonly RELAY_RESTART_DRIVER_CLEANUP_MILLISECONDS=20000
readonly RELAY_RESTART_DRIVER_TERM_GRACE_MILLISECONDS=15000
readonly OTHER_PROCESS_CLEANUP_MILLISECONDS=5000
readonly FAULT_CLEANUP_TOTAL_MILLISECONDS=30000
readonly FAULT_NETWORK_CLEANUP_MILLISECONDS=8000
readonly FAULT_CLEANUP_COMMAND_MILLISECONDS=2000
readonly FAULT_CLEANUP_KILL_GRACE_MILLISECONDS=500
readonly FAULT_RULE_DELETE_LIMIT=16
readonly NETEM_CLEANUP_MILLISECONDS=3000
(( RELAY_RESTART_DRIVER_BUDGET_MILLISECONDS < \
  RELAY_RESTART_OUTER_BUDGET_MILLISECONDS ))
(( RELAY_RESTART_DRIVER_CLEANUP_BUDGET_MILLISECONDS < \
  RELAY_RESTART_DRIVER_CLEANUP_MILLISECONDS ))
(( RELAY_RESTART_DRIVER_CLEANUP_BUDGET_MILLISECONDS < \
  RELAY_RESTART_DRIVER_TERM_GRACE_MILLISECONDS ))
(( RELAY_RESTART_DRIVER_TERM_GRACE_MILLISECONDS < \
  RELAY_RESTART_DRIVER_CLEANUP_MILLISECONDS ))
(( FAULT_NETWORK_CLEANUP_MILLISECONDS + \
  RELAY_RESTART_DRIVER_CLEANUP_MILLISECONDS < \
  FAULT_CLEANUP_TOTAL_MILLISECONDS ))
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
readonly SCRIPT_DIR

if [[ -f ${SCRIPT_DIR}/campus-link-gate-evidence ]]; then
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/campus-link-gate-evidence
else
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/gate-evidence.sh
fi
if [[ -f /usr/local/libexec/campus-link-stream-transport.py ]]; then
  readonly STREAM_PROBE=/usr/local/libexec/campus-link-stream-transport.py
  readonly STATUS_GATE=/usr/local/libexec/campus-link-status-gate.py
  readonly NETEM=/usr/local/libexec/campus-link-test-netem
else
  readonly STREAM_PROBE=${REPO_ROOT}/campus-link/tests/stream_transport.py
  readonly STATUS_GATE=${REPO_ROOT}/campus-link/tests/status_gate.py
  readonly NETEM=${SCRIPT_DIR}/test-netem.sh
fi
if [[ -x /usr/local/libexec/campus-link-relay-restart-driver ]]; then
  readonly RELAY_RESTART_DRIVER=/usr/local/libexec/campus-link-relay-restart-driver
else
  readonly RELAY_RESTART_DRIVER=${SCRIPT_DIR}/relay-restart-driver.sh
fi

case ${MODE} in
  production)
    stream_bytes=${CAMPUS_LINK_FAULT_STREAM_BYTES:-2147483648}
    relay_outage_target_ms=${CAMPUS_LINK_RELAY_OUTAGE_MS:-15000}
    direct_fault_target_ms=${CAMPUS_LINK_DIRECT_FAULT_HOLD_MS:-15000}
    minimum_direct_packets=1000
    ;;
  isolated-test)
    stream_bytes=${CAMPUS_LINK_FAULT_STREAM_BYTES:-8388608}
    relay_outage_target_ms=${CAMPUS_LINK_RELAY_OUTAGE_MS:-12000}
    direct_fault_target_ms=${CAMPUS_LINK_DIRECT_FAULT_HOLD_MS:-15000}
    minimum_direct_packets=1
    ;;
  *)
    echo 'usage: fault-in-stream.sh [REPO_ROOT] [production|isolated-test]' >&2
    exit 2
    ;;
esac

[[ ${EUID} -eq 0 ]]
[[ ${stream_bytes} =~ ^[0-9]{1,15}$ && ${stream_bytes} -gt 0 && ${stream_bytes} -le 8589934592 ]]
[[ ${relay_outage_target_ms} =~ ^[0-9]{1,8}$ && ${relay_outage_target_ms} -gt 0 ]]
[[ ${direct_fault_target_ms} =~ ^[0-9]{1,8}$ && ${direct_fault_target_ms} -gt 0 ]]
if [[ ${MODE} == production ]]; then
  (( stream_bytes >= 2147483648 ))
  (( relay_outage_target_ms >= 15000 ))
  (( direct_fault_target_ms >= 15000 && direct_fault_target_ms <= 20000 ))
  (( direct_fault_target_ms > DIRECT_IDLE_TIMEOUT_MS ))
  (( MAX_APPLICATION_OUTAGE_BOUND_MS < MUX_NO_PATH_DEADLINE_MS ))
fi
[[ -f ${EVIDENCE_HELPER} && ! -L ${EVIDENCE_HELPER} ]]
[[ -f ${STREAM_PROBE} && ! -L ${STREAM_PROBE} ]]
[[ -f ${STATUS_GATE} && ! -L ${STATUS_GATE} ]]
[[ -x ${NETEM} && ! -L ${NETEM} ]]
[[ -x ${RELAY_RESTART_DRIVER} && ! -L ${RELAY_RESTART_DRIVER} ]]
# shellcheck source=gate-evidence.sh
source "${EVIDENCE_HELPER}"
umask 077
campus_link_acquire_deployment_shared_lock
campus_link_acquire_gate_execution_lock

readonly run_manifest=${CAMPUS_LINK_RUN_MANIFEST}
campus_link_validate_run_manifest "${run_manifest}"
run_id=$(campus_link_marker_value "${run_manifest}" RUN_ID) || exit 1
candidate_sha256=$(campus_link_marker_value "${run_manifest}" CANDIDATE_SHA256) || exit 1
run_manifest_sha256=$(campus_link_run_manifest_sha256 "${run_manifest}") || exit 1
campus_link_validate_chain "${run_manifest}" accelerated-fault
prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || exit 1
[[ ${prerequisite_sha256} =~ ^[a-f0-9]{64}$ ]]
started_ms=$(campus_link_monotonic_ms) || exit 1
prerequisite_completed_ms=$(campus_link_marker_value "${PREREQUISITE}" COMPLETE_MONOTONIC_MS) || exit 1
(( started_ms >= prerequisite_completed_ms ))
campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
rm -f -- "${RESULT}"

for namespace in oslab-a oslab-b campus-a campus-b; do
  ip netns list | grep -q "^${namespace}\b"
done

evidence_dir=$(mktemp -d /run/campus-link/.fault-in-stream.XXXXXX) || exit 1
chmod 0700 "${evidence_dir}"
pids=()
pid_start_ticks=()
netem_active=0
control_blocked=0
direct_blocked=0
relay_restart_pid=
relay_restart_start_ticks=

process_start_ticks() {
  local pid=$1 line rest
  [[ -r /proc/${pid}/stat ]] || return 1
  IFS= read -r line < "/proc/${pid}/stat" || return 1
  rest=${line##*) }
  set -- ${rest}
  [[ $# -ge 20 && ${20} =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "${20}"
}

process_state() {
  local pid=$1 line rest state
  [[ -r /proc/${pid}/stat ]] || return 1
  IFS= read -r line < "/proc/${pid}/stat" || return 1
  rest=${line##*) }
  state=${rest%% *}
  [[ ${state} =~ ^[A-Z]$ ]] || return 1
  printf '%s\n' "${state}"
}

inspect_process_identity() {
  local pid=$1 expected_start_ticks=$2 destination=$3 path line rest outcome
  local -a fields=()
  outcome=inspection-error
  if [[ ${pid} =~ ^[1-9][0-9]*$ && \
    ${expected_start_ticks} =~ ^[1-9][0-9]*$ ]]; then
    path=/proc/${pid}/stat
    if [[ ! -e ${path} ]]; then
      outcome=gone
    elif [[ -r ${path} ]]; then
      if IFS= read -r line < "${path}"; then
        rest=${line##*) }
        if [[ ${rest} != "${line}" ]]; then
          read -r -a fields <<< "${rest}" || fields=()
          if (( ${#fields[@]} >= 20 )) && \
            [[ ${fields[0]} =~ ^[A-Za-z]$ && \
              ${fields[19]} =~ ^[1-9][0-9]*$ ]]; then
            if [[ ${fields[19]} != "${expected_start_ticks}" ]]; then
              outcome=identity-mismatch
            elif [[ ${fields[0]} == Z ]]; then
              outcome=zombie
            else
              outcome=live
            fi
          fi
        fi
      elif [[ ! -e ${path} ]]; then
        outcome=gone
      fi
    fi
  fi
  printf -v "${destination}" '%s' "${outcome}"
}

relay_restart_child_matches() {
  local state
  [[ -n ${relay_restart_pid:-} && -n ${relay_restart_start_ticks:-} ]] || return 1
  inspect_process_identity "${relay_restart_pid}" "${relay_restart_start_ticks}" state
  [[ ${state} == live ]]
}

wait_relay_restart_until() {
  local deadline_ms=$1 destination=$2 now_ms state status
  while :; do
    now_ms=$(campus_link_monotonic_ms) || return 1
    (( now_ms < deadline_ms )) || return 124
    inspect_process_identity "${relay_restart_pid}" \
      "${relay_restart_start_ticks}" state
    case ${state} in
      live) sleep 0.05 ;;
      zombie|gone) break ;;
      *) return 125 ;;
    esac
  done
  now_ms=$(campus_link_monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 124
  if wait "${relay_restart_pid}"; then
    status=0
  else
    status=$?
  fi
  printf -v "${destination}" '%s' "${status}"
  return 0
}

cleanup_run_bounded() {
  local deadline_ms=$1 total_cap_ms=$2 grace_ms=$3
  local now_ms remaining_ms total_ms command_ms duration grace_duration
  shift 3
  now_ms=$(campus_link_monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 1
  remaining_ms=$((deadline_ms - now_ms))
  total_ms=${remaining_ms}
  (( total_ms <= total_cap_ms )) || total_ms=${total_cap_ms}
  (( total_ms > grace_ms )) || return 1
  command_ms=$((total_ms - grace_ms))
  printf -v duration '%d.%03ds' $((command_ms / 1000)) \
    $((command_ms % 1000)) || return 1
  printf -v grace_duration '%d.%03ds' $((grace_ms / 1000)) \
    $((grace_ms % 1000)) || return 1
  timeout --signal=TERM --kill-after="${grace_duration}" "${duration}" "$@"
}

delete_exact_rule_bounded() {
  local deadline_ms=$1 namespace=$2 attempt status chain
  shift 2
  chain=${1:-}
  [[ ${chain} == OUTPUT || ${chain} == INPUT ]] || return 1
  for ((attempt = 0; attempt <= FAULT_RULE_DELETE_LIMIT; attempt++)); do
    if cleanup_run_bounded "${deadline_ms}" \
      "${FAULT_CLEANUP_COMMAND_MILLISECONDS}" \
      "${FAULT_CLEANUP_KILL_GRACE_MILLISECONDS}" \
      ip netns exec "${namespace}" iptables -w 1 -C "$@" 2>/dev/null; then
      (( attempt < FAULT_RULE_DELETE_LIMIT )) || return 1
      cleanup_run_bounded "${deadline_ms}" \
        "${FAULT_CLEANUP_COMMAND_MILLISECONDS}" \
        "${FAULT_CLEANUP_KILL_GRACE_MILLISECONDS}" \
        ip netns exec "${namespace}" iptables -w 1 -D "$@" || return 1
    else
      status=$?
      case ${status} in
        1)
          # iptables uses status 1 for an absent rule, but a failed namespace
          # execution can also be nonzero.  Prove that the exact table/chain is
          # still queryable before interpreting the check as absence.
          cleanup_run_bounded "${deadline_ms}" \
            "${FAULT_CLEANUP_COMMAND_MILLISECONDS}" \
            "${FAULT_CLEANUP_KILL_GRACE_MILLISECONDS}" \
            ip netns exec "${namespace}" iptables -w 1 -S "${chain}" \
            >/dev/null || return 1
          return 0
          ;;
        *) return 1 ;;
      esac
    fi
  done
  return 1
}

clear_control_block() {
  local namespace=$1 wan=$2 deadline_ms=$3 ok=1
  delete_exact_rule_bounded "${deadline_ms}" "${namespace}" \
    OUTPUT -o "${wan}" -p tcp --dport 443 -m comment \
    --comment campus-link-fault-stream-control -j REJECT \
    --reject-with tcp-reset || ok=0
  delete_exact_rule_bounded "${deadline_ms}" "${namespace}" \
    INPUT -i "${wan}" -p tcp --sport 443 -m comment \
    --comment campus-link-fault-stream-control -j DROP || ok=0
  (( ok != 0 ))
}

set_control_block() {
  local namespace=$1 wan=$2
  ip netns exec "${namespace}" iptables -w 2 -I OUTPUT 1 -o "${wan}" -p tcp \
    --dport 443 -m comment --comment campus-link-fault-stream-control \
    -j REJECT --reject-with tcp-reset
  ip netns exec "${namespace}" iptables -w 2 -I INPUT 1 -i "${wan}" -p tcp \
    --sport 443 -m comment --comment campus-link-fault-stream-control -j DROP
}

clear_direct_block() {
  local namespace=$1 wan=$2 deadline_ms=$3 direction interface_flag ok=1
  for direction in OUTPUT INPUT; do
    if [[ ${direction} == OUTPUT ]]; then
      interface_flag=-o
    else
      interface_flag=-i
    fi
    delete_exact_rule_bounded "${deadline_ms}" "${namespace}" "${direction}" \
      "${interface_flag}" "${wan}" -p udp -m comment \
      --comment campus-link-fault-stream-direct -j DROP || ok=0
  done
  (( ok != 0 ))
}

set_direct_block() {
  local namespace=$1 wan=$2
  ip netns exec "${namespace}" iptables -w 2 -I OUTPUT 1 -o "${wan}" -p udp \
    -m comment --comment campus-link-fault-stream-direct -j DROP
  ip netns exec "${namespace}" iptables -w 2 -I INPUT 1 -i "${wan}" -p udp \
    -m comment --comment campus-link-fault-stream-direct -j DROP
}

cleanup() {
  local status=$? pid index state driver_pid driver_ticks now_ms ignored_status
  local cleanup_started_ms cleanup_deadline_ms network_deadline_ms
  local driver_kill_at_ms other_kill_at_ms
  local cleanup_ok=1 driver_reaped=1 driver_kill_sent=0 other_kill_sent=0 all_reaped
  local -a remaining_pids=() remaining_start_ticks=()
  trap - EXIT HUP INT TERM
  set +e
  cleanup_started_ms=$(campus_link_monotonic_ms) || cleanup_ok=0
  if (( cleanup_ok != 0 )); then
    cleanup_deadline_ms=$((cleanup_started_ms + \
      FAULT_CLEANUP_TOTAL_MILLISECONDS))
    network_deadline_ms=$((cleanup_started_ms + \
      FAULT_NETWORK_CLEANUP_MILLISECONDS))
    driver_kill_at_ms=$((cleanup_started_ms + \
      RELAY_RESTART_DRIVER_TERM_GRACE_MILLISECONDS))
    other_kill_at_ms=$((cleanup_started_ms + \
      OTHER_PROCESS_CLEANUP_MILLISECONDS))
  else
    cleanup_deadline_ms=0
    network_deadline_ms=0
    driver_kill_at_ms=0
    other_kill_at_ms=0
  fi
  if (( direct_blocked != 0 )); then
    clear_direct_block campus-a cl-a-wan "${network_deadline_ms}" || cleanup_ok=0
    clear_direct_block campus-b cl-b-wan "${network_deadline_ms}" || cleanup_ok=0
  fi
  if (( control_blocked != 0 )); then
    clear_control_block campus-a cl-a-wan "${network_deadline_ms}" || cleanup_ok=0
    clear_control_block campus-b cl-b-wan "${network_deadline_ms}" || cleanup_ok=0
  fi
  if (( netem_active != 0 )); then
    cleanup_run_bounded "${network_deadline_ms}" \
      "${NETEM_CLEANUP_MILLISECONDS}" \
      "${FAULT_CLEANUP_KILL_GRACE_MILLISECONDS}" \
      "${NETEM}" "${REPO_ROOT}" clear-profile >/dev/null 2>&1 || cleanup_ok=0
  fi
  driver_pid=${relay_restart_pid:-}
  driver_ticks=${relay_restart_start_ticks:-}
  if [[ -n ${driver_pid} ]]; then
    driver_reaped=0
    inspect_process_identity "${driver_pid}" "${driver_ticks}" state
    case ${state} in
      live) kill -TERM "${driver_pid}" 2>/dev/null || true ;;
      zombie|gone) ;;
      *) cleanup_ok=0 ;;
    esac
  fi
  for index in "${!pids[@]}"; do
    pid=${pids[index]}
    if [[ -n ${driver_pid} && ${pid} == "${driver_pid}" ]]; then
      continue
    fi
    remaining_pids+=("${pid}")
    remaining_start_ticks+=("${pid_start_ticks[index]:-}")
  done
  pids=()
  pid_start_ticks=()
  for index in "${!remaining_pids[@]}"; do
    inspect_process_identity "${remaining_pids[index]}" \
      "${remaining_start_ticks[index]}" state
    case ${state} in
      live)
        pids+=("${remaining_pids[index]}")
        pid_start_ticks+=("${remaining_start_ticks[index]}")
        ;;
      zombie|gone) ;;
      *) cleanup_ok=0 ;;
    esac
  done
  if (( ${#pids[@]} > 0 )); then
    kill -TERM "${pids[@]}" 2>/dev/null || true
  fi
  pids=("${remaining_pids[@]}")
  pid_start_ticks=("${remaining_start_ticks[@]}")

  while (( cleanup_deadline_ms > 0 )); do
    now_ms=$(campus_link_monotonic_ms) || { cleanup_ok=0; break; }
    (( now_ms < cleanup_deadline_ms )) || break
    all_reaped=1

    if (( driver_reaped == 0 )); then
      all_reaped=0
      inspect_process_identity "${driver_pid}" "${driver_ticks}" state
      case ${state} in
        live) ;;
        zombie|gone)
          now_ms=$(campus_link_monotonic_ms) || { cleanup_ok=0; break; }
          (( now_ms < cleanup_deadline_ms )) || break
          wait "${driver_pid}" 2>/dev/null || ignored_status=$?
          driver_reaped=1
          relay_restart_pid=
          relay_restart_start_ticks=
          ;;
        *) cleanup_ok=0 ;;
      esac
    fi

    for index in "${!pids[@]}"; do
      pid=${pids[index]}
      [[ -n ${pid} ]] || continue
      all_reaped=0
      inspect_process_identity "${pid}" "${pid_start_ticks[index]}" state
      case ${state} in
        live) ;;
        zombie|gone)
          now_ms=$(campus_link_monotonic_ms) || { cleanup_ok=0; break 2; }
          (( now_ms < cleanup_deadline_ms )) || break 2
          wait "${pid}" 2>/dev/null || ignored_status=$?
          pids[index]=
          pid_start_ticks[index]=
          ;;
        *) cleanup_ok=0 ;;
      esac
    done
    (( all_reaped != 0 )) && break

    if (( other_kill_sent == 0 && now_ms >= other_kill_at_ms )); then
      for index in "${!pids[@]}"; do
        pid=${pids[index]}
        [[ -n ${pid} ]] || continue
        inspect_process_identity "${pid}" "${pid_start_ticks[index]}" state
        case ${state} in
          live) kill -KILL "${pid}" 2>/dev/null || true ;;
          zombie|gone) ;;
          *) cleanup_ok=0 ;;
        esac
      done
      other_kill_sent=1
    fi
    if (( driver_reaped == 0 && driver_kill_sent == 0 && \
      now_ms >= driver_kill_at_ms )); then
      inspect_process_identity "${driver_pid}" "${driver_ticks}" state
      case ${state} in
        live) kill -KILL "${driver_pid}" 2>/dev/null || true ;;
        zombie|gone) ;;
        *) cleanup_ok=0 ;;
      esac
      driver_kill_sent=1
    fi
    sleep 0.05
  done

  all_reaped=${driver_reaped}
  for pid in "${pids[@]}"; do
    [[ -z ${pid} ]] || all_reaped=0
  done
  if (( (all_reaped == 0 || cleanup_ok == 0) && status == 0 )); then
    status=1
  fi
  relay_restart_pid=
  relay_restart_start_ticks=
  pids=()
  pid_start_ticks=()
  rm -f -- "${result_source:-}"
  if [[ ${evidence_dir} == /run/campus-link/.fault-in-stream.* && -d ${evidence_dir} && ! -L ${evidence_dir} ]]; then
    rm -rf -- "${evidence_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Remove only stale, exact rules from an interrupted prior gate before applying
# this run's bounded faults.
stale_cleanup_started_ms=$(campus_link_monotonic_ms) || exit 1
stale_cleanup_deadline_ms=$((stale_cleanup_started_ms + \
  FAULT_NETWORK_CLEANUP_MILLISECONDS))
clear_control_block campus-a cl-a-wan "${stale_cleanup_deadline_ms}"
clear_control_block campus-b cl-b-wan "${stale_cleanup_deadline_ms}"
clear_direct_block campus-a cl-a-wan "${stale_cleanup_deadline_ms}"
clear_direct_block campus-b cl-b-wan "${stale_cleanup_deadline_ms}"

read_unit_uint() {
  local unit=$1 property=$2 value
  value=$(systemctl show -p "${property}" --value "${unit}") || return 1
  [[ ${value} =~ ^(0|[1-9][0-9]{0,15})$ ]] || return 1
  printf '%s\n' "${value}" || return 1
  return 0
}

progress_uint() {
  local file=$1 key=$2 value LC_ALL=C
  local maximum=9223372036854775807
  value=$(campus_link_marker_value "${file}" "${key}") || return 1
  [[ ${value} =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
  [[ ${#value} -lt 19 || ${value} < "${maximum}" || ${value} == "${maximum}" ]] || return 1
  printf '%s\n' "${value}" || return 1
  return 0
}

rate_to_milli_mbit() {
  local value=$1
  [[ ${value} =~ ^(0|[1-9][0-9]{0,8})\.([0-9]{3})$ ]] || return 1
  printf '%s\n' "$((10#${BASH_REMATCH[1]} * 1000 + 10#${BASH_REMATCH[2]}))" || return 1
  return 0
}

edge_a_restarts=$(read_unit_uint campus-link-edge-a.service NRestarts) || exit 1
edge_b_restarts=$(read_unit_uint campus-link-edge-b.service NRestarts) || exit 1
edge_a_invocation=$(systemctl show -p InvocationID --value campus-link-edge-a.service) || exit 1
edge_b_invocation=$(systemctl show -p InvocationID --value campus-link-edge-b.service) || exit 1
[[ ${edge_a_invocation} =~ ^[a-f0-9]{32}$ && ${edge_b_invocation} =~ ^[a-f0-9]{32}$ ]]
edge_a_memory_max=$(read_unit_uint campus-link-edge-a.service MemoryMax) || exit 1
edge_b_memory_max=$(read_unit_uint campus-link-edge-b.service MemoryMax) || exit 1
(( edge_a_memory_max > 0 && edge_a_memory_max <= MEMORY_CEILING_BYTES ))
(( edge_b_memory_max > 0 && edge_b_memory_max <= MEMORY_CEILING_BYTES ))
process_continuity_checks=0

assert_process_continuity() {
  local current_a_restarts current_b_restarts current_a_invocation current_b_invocation
  current_a_restarts=$(read_unit_uint campus-link-edge-a.service NRestarts) || return 1
  current_b_restarts=$(read_unit_uint campus-link-edge-b.service NRestarts) || return 1
  [[ ${current_a_restarts} == "${edge_a_restarts}" ]] || return 1
  [[ ${current_b_restarts} == "${edge_b_restarts}" ]] || return 1
  current_a_invocation=$(systemctl show -p InvocationID --value \
    campus-link-edge-a.service) || return 1
  current_b_invocation=$(systemctl show -p InvocationID --value \
    campus-link-edge-b.service) || return 1
  [[ ${current_a_invocation} == "${edge_a_invocation}" ]] || return 1
  [[ ${current_b_invocation} == "${edge_b_invocation}" ]] || return 1
  process_continuity_checks=$((process_continuity_checks + 2))
  return 0
}

sample_memory() {
  local watched_pid=$1 current_a current_b
  while kill -0 "${watched_pid}" 2>/dev/null; do
    current_a=$(read_unit_uint campus-link-edge-a.service MemoryCurrent) || return 1
    current_b=$(read_unit_uint campus-link-edge-b.service MemoryCurrent) || return 1
    (( current_a <= MEMORY_CEILING_BYTES && current_b <= MEMORY_CEILING_BYTES ))
    printf '%s\t%s\n' "${current_a}" "${current_b}"
    sleep 0.1
  done
  current_a=$(read_unit_uint campus-link-edge-a.service MemoryCurrent) || return 1
  current_b=$(read_unit_uint campus-link-edge-b.service MemoryCurrent) || return 1
  (( current_a <= MEMORY_CEILING_BYTES && current_b <= MEMORY_CEILING_BYTES ))
  printf '%s\t%s\n' "${current_a}" "${current_b}"
}

capture_status() {
  local output=$1
  python3 -B "${STATUS_GATE}" capture \
    --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" --output "${output}"
}

read_progress() {
  local progress_file=$1 receive_sequence=$2 output=$3
  shift 3
  python3 -B "${STREAM_PROBE}" wait-progress \
    --progress-file "${progress_file}" \
    --receive-sequence "${receive_sequence}" "$@" > "${output}"
  campus_link_validate_schema "${output}" FORMAT MONOTONIC_NS RECEIVE_SEQUENCE RECEIVED_BYTES
  campus_link_marker_equals "${output}" FORMAT 1 || return 1
  campus_link_marker_equals "${output}" RECEIVE_SEQUENCE \
    "${receive_sequence}" || return 1
}

wait_until_ms() {
  local target=$1 now
  while :; do
    now=$(campus_link_monotonic_ms) || return 1
    (( now >= target )) && return 0
    kill -0 "${client_pid}"
    sleep 0.05
  done
}

netem_active=1
"${NETEM}" "${REPO_ROOT}" apply-profile
for namespace_device in 'campus-a cl-a-wan' 'campus-b cl-b-wan'; do
  read -r namespace device <<< "${namespace_device}"
  qdisc=$(ip netns exec "${namespace}" tc qdisc show dev "${device}") || return 1
  [[ ${qdisc} == *netem* && ${qdisc} == *"delay 100ms 20ms"* ]]
  [[ ${qdisc} == *"loss 1%"* && ${qdisc} == *"reorder 0.1%"* ]]
done

ip netns exec oslab-b python3 -B "${STREAM_PROBE}" serve-session-once \
  --bind 10.82.0.22 --port "${STREAM_PORT}" --progress-timeout 35 \
  --phase-timeout 10800 --progress-file "${evidence_dir}/a-to-b-progress.json" \
  --progress-receive-sequence "${SEND_SEQUENCE}" --progress-interval 0.05 \
  --accept-timeout 30 \
  > "${evidence_dir}/server.log" 2>&1 &
server_pid=$!
pids+=("${server_pid}")
server_start_ticks=$(process_start_ticks "${server_pid}") || exit 1
pid_start_ticks+=("${server_start_ticks}")
sleep 1
kill -0 "${server_pid}"

python3 -B "${STATUS_GATE}" wait-direct \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" --timeout-seconds 60
capture_status "${evidence_dir}/before.json"
assert_process_continuity

ip netns exec oslab-a python3 -B "${STREAM_PROBE}" client \
  --source 10.81.0.11 --destination 10.82.0.22 --port "${STREAM_PORT}" \
  --rounds 1 --send-bytes "${stream_bytes}" --receive-bytes "${stream_bytes}" \
  --send-sequence "${SEND_SEQUENCE}" --receive-sequence "${RECEIVE_SEQUENCE}" \
  --progress-timeout 35 --phase-timeout 10800 \
  --min-send-mbit-s 2 --min-receive-mbit-s 2 \
  --progress-file "${evidence_dir}/b-to-a-progress.json" --progress-interval 0.05 \
  > "${evidence_dir}/client.log" 2>&1 &
client_pid=$!
pids+=("${client_pid}")
client_start_ticks=$(process_start_ticks "${client_pid}") || exit 1
pid_start_ticks+=("${client_start_ticks}")
sample_memory "${client_pid}" > "${evidence_dir}/memory.tsv" &
memory_pid=$!
pids+=("${memory_pid}")
memory_start_ticks=$(process_start_ticks "${memory_pid}") || exit 1
pid_start_ticks+=("${memory_start_ticks}")

read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
  "${evidence_dir}/before-restart-a-to-b.env" \
  --minimum-received-bytes 1 --timeout-seconds 60
read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
  "${evidence_dir}/before-restart-b-to-a.env" \
  --minimum-received-bytes 1 --timeout-seconds 60
kill -0 "${client_pid}"
assert_process_continuity

readonly relay_restart_active=${evidence_dir}/relay-restart-active.env
readonly relay_restart_release=${evidence_dir}/relay-restart-release.env
readonly relay_restart_started=${evidence_dir}/relay-restart-started.env
readonly relay_restart_commit=${evidence_dir}/relay-restart-commit.env
relay_restart_outer_started_ms=$(campus_link_monotonic_ms) || exit 1
relay_restart_outer_deadline_ms=$((relay_restart_outer_started_ms + \
  RELAY_RESTART_OUTER_BUDGET_MILLISECONDS))
"${RELAY_RESTART_DRIVER}" "${run_id}" \
  "${relay_restart_active}" "${relay_restart_release}" \
  "${relay_restart_started}" "${relay_restart_commit}" \
  > "${evidence_dir}/relay-restart.env" \
  2> "${evidence_dir}/relay-restart.error" &
relay_restart_pid=$!
relay_restart_start_ticks=$(process_start_ticks "${relay_restart_pid}") || exit 1
pids+=("${relay_restart_pid}")
pid_start_ticks+=("${relay_restart_start_ticks}")
relay_restart_active_deadline_ms=$((relay_restart_outer_started_ms + \
  RELAY_RESTART_ACTIVE_BUDGET_MILLISECONDS))
(( relay_restart_active_deadline_ms <= relay_restart_outer_deadline_ms )) || \
  relay_restart_active_deadline_ms=${relay_restart_outer_deadline_ms}
while [[ ! -e ${relay_restart_active} && ! -L ${relay_restart_active} ]]; do
  relay_restart_poll_ms=$(campus_link_monotonic_ms) || exit 1
  (( relay_restart_poll_ms < relay_restart_active_deadline_ms ))
  relay_restart_child_matches
  sleep 0.05
done
campus_link_validate_schema "${relay_restart_active}" \
  FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \
  PERMIT_AUTHORIZER_SHA256 RUN_ID \
  BEFORE_INVOCATION_SHA256 HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE
campus_link_marker_equals "${relay_restart_active}" FORMAT 1
campus_link_marker_equals "${relay_restart_active}" ACTION relay-restart
campus_link_marker_equals "${relay_restart_active}" RUN_ID "${run_id}"
relay_restart_active_hold_ms=$(campus_link_marker_uint \
  "${relay_restart_active}" HOLD_MILLISECONDS) || exit 1
[[ ${relay_restart_active_hold_ms} == 15000 ]]
campus_link_marker_equals "${relay_restart_active}" STOPPED 1
relay_restart_stopped_challenge=$(campus_link_marker_value \
  "${relay_restart_active}" STOPPED_CHALLENGE) || exit 1
[[ ${relay_restart_stopped_challenge} =~ ^[a-f0-9]{64}$ ]]
python3 -B "${STATUS_GATE}" wait-control-outage \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" \
  --before "${evidence_dir}/before.json" --timeout-seconds 10
read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
  "${evidence_dir}/post-stop-baseline-a-to-b.env" \
  --minimum-received-bytes 1 --timeout-seconds 2
read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
  "${evidence_dir}/post-stop-baseline-b-to-a.env" \
  --minimum-received-bytes 1 --timeout-seconds 2
post_stop_a_to_b_bytes=$(progress_uint \
  "${evidence_dir}/post-stop-baseline-a-to-b.env" RECEIVED_BYTES) || exit 1
post_stop_b_to_a_bytes=$(progress_uint \
  "${evidence_dir}/post-stop-baseline-b-to-a.env" RECEIVED_BYTES) || exit 1
post_stop_a_to_b_ns=$(progress_uint \
  "${evidence_dir}/post-stop-baseline-a-to-b.env" MONOTONIC_NS) || exit 1
post_stop_b_to_a_ns=$(progress_uint \
  "${evidence_dir}/post-stop-baseline-b-to-a.env" MONOTONIC_NS) || exit 1
read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
  "${evidence_dir}/during-restart-a-to-b.env" \
  --after-received-bytes "${post_stop_a_to_b_bytes}" --timeout-seconds 8
read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
  "${evidence_dir}/during-restart-b-to-a.env" \
  --after-received-bytes "${post_stop_b_to_a_bytes}" --timeout-seconds 8
during_restart_a_to_b_bytes=$(progress_uint "${evidence_dir}/during-restart-a-to-b.env" RECEIVED_BYTES) || exit 1
during_restart_b_to_a_bytes=$(progress_uint "${evidence_dir}/during-restart-b-to-a.env" RECEIVED_BYTES) || exit 1
during_restart_a_to_b_ns=$(progress_uint \
  "${evidence_dir}/during-restart-a-to-b.env" MONOTONIC_NS) || exit 1
during_restart_b_to_a_ns=$(progress_uint \
  "${evidence_dir}/during-restart-b-to-a.env" MONOTONIC_NS) || exit 1
(( during_restart_a_to_b_ns > post_stop_a_to_b_ns ))
(( during_restart_b_to_a_ns > post_stop_b_to_a_ns ))
relay_restart_progress_a_to_b_delta_bytes=$((during_restart_a_to_b_bytes - post_stop_a_to_b_bytes))
relay_restart_progress_b_to_a_delta_bytes=$((during_restart_b_to_a_bytes - post_stop_b_to_a_bytes))
if [[ ${MODE} == production ]]; then
  (( relay_restart_progress_a_to_b_delta_bytes >= RELAY_PROGRESS_MIN_BYTES ))
  (( relay_restart_progress_b_to_a_delta_bytes >= RELAY_PROGRESS_MIN_BYTES ))
else
  (( relay_restart_progress_a_to_b_delta_bytes > 0 ))
  (( relay_restart_progress_b_to_a_delta_bytes > 0 ))
fi
# The authenticated actuator remains systemd-masked and stopped until this
# root-private release is published after both progress observations.
relay_restart_child_matches
assert_process_continuity
relay_restart_release_source=$(mktemp "${evidence_dir}/.relay-restart-release.XXXXXX") || exit 1
printf 'FORMAT=1\nRUN_ID=%s\nRELEASE=1\n' "${run_id}" > "${relay_restart_release_source}"
campus_link_atomic_marker "${relay_restart_release}" "${relay_restart_release_source}"
rm -f -- "${relay_restart_release_source}"

relay_restart_started_poll_ms=$(campus_link_monotonic_ms) || exit 1
relay_restart_started_deadline_ms=$((relay_restart_started_poll_ms + 45000))
(( relay_restart_started_deadline_ms <= relay_restart_outer_deadline_ms )) || \
  relay_restart_started_deadline_ms=${relay_restart_outer_deadline_ms}
while [[ ! -e ${relay_restart_started} && ! -L ${relay_restart_started} ]]; do
  relay_restart_poll_ms=$(campus_link_monotonic_ms) || exit 1
  (( relay_restart_poll_ms < relay_restart_started_deadline_ms ))
  relay_restart_child_matches
  sleep 0.05
done
campus_link_validate_schema "${relay_restart_started}" \
  FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \
  PERMIT_AUTHORIZER_SHA256 RUN_ID \
  BEFORE_INVOCATION_SHA256 HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE STARTED \
  AFTER_INVOCATION_SHA256 RESTART_DURATION_MS ACTIVE STARTED_CHALLENGE
campus_link_marker_equals "${relay_restart_started}" FORMAT 1
campus_link_marker_equals "${relay_restart_started}" ACTION relay-restart
campus_link_marker_equals "${relay_restart_started}" RUN_ID "${run_id}"
campus_link_marker_equals "${relay_restart_started}" STOPPED 1
campus_link_marker_equals "${relay_restart_started}" STARTED 1
campus_link_marker_equals "${relay_restart_started}" ACTIVE 1
relay_restart_started_challenge=$(campus_link_marker_value \
  "${relay_restart_started}" STARTED_CHALLENGE) || exit 1
[[ ${relay_restart_started_challenge} =~ ^[a-f0-9]{64}$ ]]
relay_restart_before_digest=$(campus_link_marker_value \
  "${relay_restart_started}" BEFORE_INVOCATION_SHA256) || exit 1
relay_restart_after_digest=$(campus_link_marker_value \
  "${relay_restart_started}" AFTER_INVOCATION_SHA256) || exit 1
[[ ${relay_restart_before_digest} =~ ^[a-f0-9]{64}$ ]]
[[ ${relay_restart_after_digest} =~ ^[a-f0-9]{64}$ ]]
[[ ${relay_restart_before_digest} != "${relay_restart_after_digest}" ]]
relay_restart_hold_ms=$(campus_link_marker_uint \
  "${relay_restart_started}" HOLD_MILLISECONDS) || exit 1
relay_restart_duration_ms=$(campus_link_marker_uint \
  "${relay_restart_started}" RESTART_DURATION_MS) || exit 1
(( relay_restart_hold_ms == 15000 ))
(( relay_restart_duration_ms >= relay_restart_hold_ms && relay_restart_duration_ms <= 120000 ))

python3 -B "${STATUS_GATE}" wait-control-reconnected \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" \
  --before "${evidence_dir}/before.json" --timeout-seconds 60
kill -0 "${client_pid}"
relay_restart_child_matches
assert_process_continuity
relay_restart_commit_source=$(mktemp "${evidence_dir}/.relay-restart-commit.XXXXXX") || exit 1
printf 'FORMAT=1\nRUN_ID=%s\nCOMMIT=1\n' "${run_id}" > "${relay_restart_commit_source}"
campus_link_atomic_marker "${relay_restart_commit}" "${relay_restart_commit_source}"
rm -f -- "${relay_restart_commit_source}"

wait_relay_restart_until "${relay_restart_outer_deadline_ms}" \
  relay_restart_status || {
  echo 'Relay restart driver exceeded the fault-gate deadline.' >&2
  exit 1
}
relay_restart_pid=
relay_restart_start_ticks=
# Remove the reaped driver PID before any later validation can enter cleanup;
# the kernel may immediately reuse that numeric PID for an unrelated process.
pids=("${server_pid}" "${client_pid}" "${memory_pid}")
pid_start_ticks=("${server_start_ticks}" "${client_start_ticks}" \
  "${memory_start_ticks}")
(( relay_restart_status == 0 ))
[[ ! -s ${evidence_dir}/relay-restart.error ]]
campus_link_validate_schema "${evidence_dir}/relay-restart.env" \
  FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \
  PERMIT_AUTHORIZER_SHA256 RUN_ID \
  BEFORE_INVOCATION_SHA256 HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE STARTED \
  AFTER_INVOCATION_SHA256 RESTART_DURATION_MS ACTIVE STARTED_CHALLENGE \
  STATUS COMMITTED SIGNED_RELEASE SIGNED_COMMIT \
  FINAL_INVOCATION_SHA256 NRESTARTS_DELTA COMMIT_STABILITY_MILLISECONDS
campus_link_marker_equals "${evidence_dir}/relay-restart.env" FORMAT 1
campus_link_marker_equals "${evidence_dir}/relay-restart.env" STATUS pass
campus_link_marker_equals "${evidence_dir}/relay-restart.env" ACTION relay-restart
campus_link_marker_equals "${evidence_dir}/relay-restart.env" RUN_ID "${run_id}"
campus_link_marker_equals "${evidence_dir}/relay-restart.env" STOPPED 1
campus_link_marker_equals "${evidence_dir}/relay-restart.env" STARTED 1
campus_link_marker_equals "${evidence_dir}/relay-restart.env" ACTIVE 1
campus_link_marker_equals "${evidence_dir}/relay-restart.env" COMMITTED 1
campus_link_marker_equals "${evidence_dir}/relay-restart.env" SIGNED_RELEASE 1
campus_link_marker_equals "${evidence_dir}/relay-restart.env" SIGNED_COMMIT 1
relay_restart_final_digest=$(campus_link_marker_value \
  "${evidence_dir}/relay-restart.env" FINAL_INVOCATION_SHA256) || exit 1
[[ ${relay_restart_final_digest} == "${relay_restart_after_digest}" ]]
relay_restart_nrestarts_delta=$(campus_link_marker_uint \
  "${evidence_dir}/relay-restart.env" NRESTARTS_DELTA) || exit 1
[[ ${relay_restart_nrestarts_delta} == 0 ]]
relay_restart_commit_stability_ms=$(campus_link_marker_uint \
  "${evidence_dir}/relay-restart.env" COMMIT_STABILITY_MILLISECONDS) || exit 1
(( relay_restart_commit_stability_ms == 5000 ))
capture_status "${evidence_dir}/relay-restart-recovered.json"
kill -0 "${client_pid}"
assert_process_continuity

read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
  "${evidence_dir}/before-control-a-to-b.env" \
  --after-received-bytes "${during_restart_a_to_b_bytes}" --timeout-seconds 10
read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
  "${evidence_dir}/before-control-b-to-a.env" \
  --after-received-bytes "${during_restart_b_to_a_bytes}" --timeout-seconds 10
before_control_a_to_b_bytes=$(progress_uint "${evidence_dir}/before-control-a-to-b.env" RECEIVED_BYTES) || exit 1
before_control_b_to_a_bytes=$(progress_uint "${evidence_dir}/before-control-b-to-a.env" RECEIVED_BYTES) || exit 1

control_block_started_ms=$(campus_link_monotonic_ms) || exit 1
control_blocked=1
set_control_block campus-a cl-a-wan
set_control_block campus-b cl-b-wan
python3 -B "${STATUS_GATE}" wait-control-outage \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" \
  --before "${evidence_dir}/relay-restart-recovered.json" --timeout-seconds 20
read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
  "${evidence_dir}/during-control-a-to-b.env" \
  --after-received-bytes "${before_control_a_to_b_bytes}" --timeout-seconds 10
read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
  "${evidence_dir}/during-control-b-to-a.env" \
  --after-received-bytes "${before_control_b_to_a_bytes}" --timeout-seconds 10
during_control_a_to_b_bytes=$(progress_uint "${evidence_dir}/during-control-a-to-b.env" RECEIVED_BYTES) || exit 1
during_control_b_to_a_bytes=$(progress_uint "${evidence_dir}/during-control-b-to-a.env" RECEIVED_BYTES) || exit 1
near_unblock_target_ms=$((control_block_started_ms + relay_outage_target_ms))
wait_until_ms $((near_unblock_target_ms - RELAY_NEAR_UNBLOCK_WINDOW_MS))
python3 -B "${STATUS_GATE}" wait-control-outage \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" \
  --before "${evidence_dir}/relay-restart-recovered.json" --timeout-seconds 1
read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
  "${evidence_dir}/near-control-unblock-a-to-b.env" \
  --after-received-bytes "${during_control_a_to_b_bytes}" --timeout-seconds 1
read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
  "${evidence_dir}/near-control-unblock-b-to-a.env" \
  --after-received-bytes "${during_control_b_to_a_bytes}" --timeout-seconds 1
near_control_a_to_b_bytes=$(progress_uint "${evidence_dir}/near-control-unblock-a-to-b.env" RECEIVED_BYTES) || exit 1
near_control_b_to_a_bytes=$(progress_uint "${evidence_dir}/near-control-unblock-b-to-a.env" RECEIVED_BYTES) || exit 1
near_control_observed_ms=$(campus_link_monotonic_ms) || exit 1
(( near_control_observed_ms <= near_unblock_target_ms ))
relay_near_unblock_guard_ms=$((near_unblock_target_ms - near_control_observed_ms))
(( relay_near_unblock_guard_ms <= RELAY_NEAR_UNBLOCK_WINDOW_MS ))
relay_progress_a_to_b_delta_bytes=$((near_control_a_to_b_bytes - before_control_a_to_b_bytes))
relay_progress_b_to_a_delta_bytes=$((near_control_b_to_a_bytes - before_control_b_to_a_bytes))
if [[ ${MODE} == production ]]; then
  (( relay_progress_a_to_b_delta_bytes >= RELAY_PROGRESS_MIN_BYTES ))
  (( relay_progress_b_to_a_delta_bytes >= RELAY_PROGRESS_MIN_BYTES ))
else
  (( relay_progress_a_to_b_delta_bytes > 0 ))
  (( relay_progress_b_to_a_delta_bytes > 0 ))
fi
kill -0 "${client_pid}"
assert_process_continuity
wait_until_ms $((control_block_started_ms + relay_outage_target_ms))
fault_release_started_ms=$(campus_link_monotonic_ms) || exit 1
fault_release_deadline_ms=$((fault_release_started_ms + \
  FAULT_NETWORK_CLEANUP_MILLISECONDS))
clear_control_block campus-a cl-a-wan "${fault_release_deadline_ms}"
clear_control_block campus-b cl-b-wan "${fault_release_deadline_ms}"
control_blocked=0
control_block_completed_ms=$(campus_link_monotonic_ms) || exit 1
relay_control_outage_ms=$((control_block_completed_ms - control_block_started_ms))
(( relay_control_outage_ms >= relay_outage_target_ms ))

python3 -B "${STATUS_GATE}" wait-control-reconnected \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" \
  --before "${evidence_dir}/relay-restart-recovered.json" --timeout-seconds 60
capture_status "${evidence_dir}/relay-recovered.json"
kill -0 "${client_pid}"
assert_process_continuity

read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
  "${evidence_dir}/before-direct-a-to-b.env" \
  --minimum-received-bytes 1 --timeout-seconds 5
read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
  "${evidence_dir}/before-direct-b-to-a.env" \
  --minimum-received-bytes 1 --timeout-seconds 5
direct_blocked=1
set_direct_block campus-a cl-a-wan
set_direct_block campus-b cl-b-wan
python3 -B "${STATUS_GATE}" wait-direct-outage \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" \
  --before "${evidence_dir}/relay-recovered.json" --timeout-seconds 15

stable_count_a_to_b=0
stable_count_b_to_a=0
previous_a_to_b_bytes=-1
previous_b_to_a_bytes=-1
stable_started_ms=$(campus_link_monotonic_ms) || exit 1
stable_deadline_ms=$((stable_started_ms + 10000))
while :; do
  stable_poll_ms=$(campus_link_monotonic_ms) || exit 1
  (( stable_poll_ms < stable_deadline_ms )) || break
  read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
    "${evidence_dir}/stalled-a-to-b.env" \
    --minimum-received-bytes 1 --timeout-seconds 2
  read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
    "${evidence_dir}/stalled-b-to-a.env" \
    --minimum-received-bytes 1 --timeout-seconds 2
  stalled_a_to_b_bytes=$(progress_uint "${evidence_dir}/stalled-a-to-b.env" RECEIVED_BYTES) || exit 1
  stalled_b_to_a_bytes=$(progress_uint "${evidence_dir}/stalled-b-to-a.env" RECEIVED_BYTES) || exit 1
  stalled_a_to_b_ns=$(progress_uint "${evidence_dir}/stalled-a-to-b.env" MONOTONIC_NS) || exit 1
  stalled_b_to_a_ns=$(progress_uint "${evidence_dir}/stalled-b-to-a.env" MONOTONIC_NS) || exit 1
  if (( stalled_a_to_b_bytes == previous_a_to_b_bytes )); then
    stable_count_a_to_b=$((stable_count_a_to_b + 1))
  else
    stable_count_a_to_b=0
    previous_a_to_b_bytes=${stalled_a_to_b_bytes}
  fi
  if (( stalled_b_to_a_bytes == previous_b_to_a_bytes )); then
    stable_count_b_to_a=$((stable_count_b_to_a + 1))
  else
    stable_count_b_to_a=0
    previous_b_to_a_bytes=${stalled_b_to_a_bytes}
  fi
  (( stable_count_a_to_b >= 2 && stable_count_b_to_a >= 2 )) && break
  sleep 0.5
done
(( stable_count_a_to_b >= 2 && stable_count_b_to_a >= 2 ))
kill -0 "${client_pid}"
assert_process_continuity

stalled_a_to_b_ms=$((stalled_a_to_b_ns / 1000000))
stalled_b_to_a_ms=$((stalled_b_to_a_ns / 1000000))
while :; do
  read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
    "${evidence_dir}/hold-a-to-b.env" --minimum-received-bytes 1 --timeout-seconds 2
  read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
    "${evidence_dir}/hold-b-to-a.env" --minimum-received-bytes 1 --timeout-seconds 2
  hold_a_to_b_bytes=$(progress_uint "${evidence_dir}/hold-a-to-b.env" RECEIVED_BYTES) || exit 1
  hold_b_to_a_bytes=$(progress_uint "${evidence_dir}/hold-b-to-a.env" RECEIVED_BYTES) || exit 1
  hold_a_to_b_ns=$(progress_uint "${evidence_dir}/hold-a-to-b.env" MONOTONIC_NS) || exit 1
  hold_b_to_a_ns=$(progress_uint "${evidence_dir}/hold-b-to-a.env" MONOTONIC_NS) || exit 1
  if (( hold_a_to_b_bytes != stalled_a_to_b_bytes )); then
    (( hold_a_to_b_bytes > stalled_a_to_b_bytes ))
    stalled_a_to_b_bytes=${hold_a_to_b_bytes}
    stalled_a_to_b_ns=${hold_a_to_b_ns}
    stalled_a_to_b_ms=$((stalled_a_to_b_ns / 1000000))
  fi
  if (( hold_b_to_a_bytes != stalled_b_to_a_bytes )); then
    (( hold_b_to_a_bytes > stalled_b_to_a_bytes ))
    stalled_b_to_a_bytes=${hold_b_to_a_bytes}
    stalled_b_to_a_ns=${hold_b_to_a_ns}
    stalled_b_to_a_ms=$((stalled_b_to_a_ns / 1000000))
  fi
  latest_stalled_ms=${stalled_a_to_b_ms}
  (( stalled_b_to_a_ms <= latest_stalled_ms )) || latest_stalled_ms=${stalled_b_to_a_ms}
  direct_release_target_ms=$((latest_stalled_ms + direct_fault_target_ms + STALL_GUARD_MS))
  now_ms=$(campus_link_monotonic_ms) || exit 1
  (( now_ms >= direct_release_target_ms )) && break
  kill -0 "${client_pid}"
  sleep 0.05
done
fault_release_started_ms=$(campus_link_monotonic_ms) || exit 1
fault_release_deadline_ms=$((fault_release_started_ms + \
  FAULT_NETWORK_CLEANUP_MILLISECONDS))
clear_direct_block campus-a cl-a-wan "${fault_release_deadline_ms}"
clear_direct_block campus-b cl-b-wan "${fault_release_deadline_ms}"
direct_blocked=0
direct_unblocked_ms=$(campus_link_monotonic_ms) || exit 1
direct_fault_hold_a_to_b_ms=$((direct_unblocked_ms - stalled_a_to_b_ms))
direct_fault_hold_b_to_a_ms=$((direct_unblocked_ms - stalled_b_to_a_ms))
direct_fault_hold_ms=$((direct_unblocked_ms - latest_stalled_ms))
(( direct_fault_hold_a_to_b_ms >= direct_fault_target_ms ))
(( direct_fault_hold_b_to_a_ms >= direct_fault_target_ms ))

read_progress "${evidence_dir}/a-to-b-progress.json" "${SEND_SEQUENCE}" \
  "${evidence_dir}/recovered-progress-a-to-b.env" \
  --after-received-bytes "${stalled_a_to_b_bytes}" --timeout-seconds 10
read_progress "${evidence_dir}/b-to-a-progress.json" "${RECEIVE_SEQUENCE}" \
  "${evidence_dir}/recovered-progress-b-to-a.env" \
  --after-received-bytes "${stalled_b_to_a_bytes}" --timeout-seconds 10
recovered_a_to_b_ns=$(progress_uint "${evidence_dir}/recovered-progress-a-to-b.env" MONOTONIC_NS) || exit 1
recovered_b_to_a_ns=$(progress_uint "${evidence_dir}/recovered-progress-b-to-a.env" MONOTONIC_NS) || exit 1
(( recovered_a_to_b_ns > stalled_a_to_b_ns ))
(( recovered_b_to_a_ns > stalled_b_to_a_ns ))
(( recovered_a_to_b_ns > direct_unblocked_ms * 1000000 ))
(( recovered_b_to_a_ns > direct_unblocked_ms * 1000000 ))
max_application_outage_a_to_b_ms=$(((recovered_a_to_b_ns - stalled_a_to_b_ns + 999999) / 1000000))
max_application_outage_b_to_a_ms=$(((recovered_b_to_a_ns - stalled_b_to_a_ns + 999999) / 1000000))
(( max_application_outage_a_to_b_ms >= direct_fault_target_ms ))
(( max_application_outage_b_to_a_ms >= direct_fault_target_ms ))
(( max_application_outage_a_to_b_ms <= MAX_APPLICATION_OUTAGE_BOUND_MS ))
(( max_application_outage_b_to_a_ms <= MAX_APPLICATION_OUTAGE_BOUND_MS ))
max_application_outage_ms=${max_application_outage_a_to_b_ms}
(( max_application_outage_b_to_a_ms <= max_application_outage_ms )) || \
  max_application_outage_ms=${max_application_outage_b_to_a_ms}
python3 -B "${STATUS_GATE}" wait-direct \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" --timeout-seconds 10
assert_process_continuity

wait "${client_pid}"
client_status=$?
(( client_status == 0 ))
client_pid=
wait "${memory_pid}"
memory_status=$?
(( memory_status == 0 ))
memory_pid=
if wait "${server_pid}"; then
  server_status=0
else
  server_status=$?
fi
server_pid=
pids=()
pid_start_ticks=()
(( server_status == 0 ))
server_log_expected=$(mktemp "${evidence_dir}/.server-log-expected.XXXXXX") || exit 1
chmod 0600 "${server_log_expected}"
printf 'PASS connections=1 reconnects=0 records=1\n' > "${server_log_expected}"
campus_link_require_root_file "${evidence_dir}/server.log" 600
campus_link_require_root_file "${server_log_expected}" 600
server_log_links=$(stat -c '%h' -- "${evidence_dir}/server.log") || exit 1
server_expected_links=$(stat -c '%h' -- "${server_log_expected}") || exit 1
[[ ${server_log_links} == 1 ]]
[[ ${server_expected_links} == 1 ]]
cmp -s -- "${evidence_dir}/server.log" "${server_log_expected}"
rm -f -- "${server_log_expected}"
python3 -B "${STATUS_GATE}" wait-telemetry \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" \
  --before "${evidence_dir}/relay-recovered.json" --timeout-seconds 30
capture_status "${evidence_dir}/direct-recovered.json"
assert_process_continuity

client_log_lines=$(wc -l < "${evidence_dir}/client.log") || exit 1
[[ ${client_log_lines} -eq 2 ]]
grep -Eq "^ROUND=1 send_bytes=${stream_bytes} send_sha256=[a-f0-9]{64} send_mbit_s=[0-9]+\.[0-9]{3} receive_bytes=${stream_bytes} receive_sha256=[a-f0-9]{64} receive_mbit_s=[0-9]+\.[0-9]{3}$" \
  "${evidence_dir}/client.log"
grep -Fxq 'PASS rounds=1 connection_reused=true' "${evidence_dir}/client.log"
a_to_b_rate=$(sed -nE 's/^ROUND=1 .* send_mbit_s=([0-9]+\.[0-9]{3}) receive_bytes=.*$/\1/p' \
  "${evidence_dir}/client.log") || exit 1
b_to_a_rate=$(sed -nE 's/^ROUND=1 .* receive_mbit_s=([0-9]+\.[0-9]{3})$/\1/p' \
  "${evidence_dir}/client.log") || exit 1
[[ -n ${a_to_b_rate} && -n ${b_to_a_rate} ]]
a_to_b_milli_mbit_s=$(rate_to_milli_mbit "${a_to_b_rate}") || exit 1
b_to_a_milli_mbit_s=$(rate_to_milli_mbit "${b_to_a_rate}") || exit 1
(( a_to_b_milli_mbit_s >= IMPAIRED_MIN_MILLI_MBIT_S ))
(( b_to_a_milli_mbit_s >= IMPAIRED_MIN_MILLI_MBIT_S ))

memory_peak_source=$(mktemp "${evidence_dir}/.memory-peaks.XXXXXX") || exit 1
chmod 0600 "${memory_peak_source}"
if ! awk -F '\t' -v ceiling="${MEMORY_CEILING_BYTES}" '
  BEGIN { a=0; b=0 }
  function bounded(value) {
    if (value !~ /^(0|[1-9][0-9]*)$/) return 0
    if (length(value) < length(ceiling)) return 1
    if (length(value) > length(ceiling)) return 0
    return value + 0 <= ceiling + 0
  }
  NF != 2 || !bounded($1) || !bounded($2) {
    invalid=1
    exit 2
  }
  {
    if ($1 + 0 > a) a=$1 + 0
    if ($2 + 0 > b) b=$2 + 0
  }
  END {
    if (invalid) exit 2
    if (NR == 0) exit 3
    print a, b
  }
' "${evidence_dir}/memory.tsv" > "${memory_peak_source}"; then
  rm -f -- "${memory_peak_source}"
  exit 1
fi
mapfile -t memory_peak_lines < "${memory_peak_source}" || exit 1
rm -f -- "${memory_peak_source}"
[[ ${#memory_peak_lines[@]} -eq 1 ]]
[[ ${memory_peak_lines[0]} =~ ^(0|[1-9][0-9]{0,8})\ (0|[1-9][0-9]{0,8})$ ]]
peak_a=${BASH_REMATCH[1]}
peak_b=${BASH_REMATCH[2]}
memory_peak_a=$(read_unit_uint campus-link-edge-a.service MemoryPeak) || exit 1
memory_peak_b=$(read_unit_uint campus-link-edge-b.service MemoryPeak) || exit 1
if (( memory_peak_a > peak_a )); then
  peak_a=${memory_peak_a}
fi
if (( memory_peak_b > peak_b )); then
  peak_b=${memory_peak_b}
fi
(( peak_a <= MEMORY_CEILING_BYTES && peak_b <= MEMORY_CEILING_BYTES ))
(( process_continuity_checks >= 12 ))

python3 -B "${STATUS_GATE}" verify-fault-stream \
  --before "${evidence_dir}/before.json" \
  --relay-recovered "${evidence_dir}/relay-recovered.json" \
  --direct-recovered "${evidence_dir}/direct-recovered.json" \
  --minimum-direct-packets "${minimum_direct_packets}" --raw-relay-rate 1 \
  > "${evidence_dir}/verified.env"
campus_link_validate_schema "${evidence_dir}/verified.env" \
  "${CAMPUS_LINK_FAULT_EVIDENCE_KEYS[@]}"

campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
current_prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || exit 1
[[ ${current_prerequisite_sha256} == "${prerequisite_sha256}" ]]
completed_ms=$(campus_link_monotonic_ms) || exit 1
(( completed_ms >= started_ms ))
result_source=$(mktemp /run/campus-link/.fault-in-stream-result.XXXXXX) || exit 1
printf 'FORMAT=1\nSTATUS=pass\nGATE=fault-in-stream\nMODE=%s\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=%s\nSTART_MONOTONIC_MS=%s\nCOMPLETE_MONOTONIC_MS=%s\nSTREAM_BYTES_EACH_DIRECTION=%s\nSTREAM_ROUNDS=1\nIMPAIRED_MIN_MILLI_MBIT_S=%s\nMEASURED_A_TO_B_MILLI_MBIT_S=%s\nMEASURED_B_TO_A_MILLI_MBIT_S=%s\nNETEM_DELAY_MS=100\nNETEM_JITTER_MS=20\nNETEM_LOSS_BASIS_POINTS=100\nNETEM_REORDER_BASIS_POINTS=10\nRELAY_CONTROL_OUTAGE_MS=%s\nRELAY_PROGRESS_A_TO_B_BEFORE_BYTES=%s\nRELAY_PROGRESS_A_TO_B_DURING_BYTES=%s\nRELAY_PROGRESS_A_TO_B_NEAR_UNBLOCK_BYTES=%s\nRELAY_PROGRESS_A_TO_B_DELTA_BYTES=%s\nRELAY_PROGRESS_B_TO_A_BEFORE_BYTES=%s\nRELAY_PROGRESS_B_TO_A_DURING_BYTES=%s\nRELAY_PROGRESS_B_TO_A_NEAR_UNBLOCK_BYTES=%s\nRELAY_PROGRESS_B_TO_A_DELTA_BYTES=%s\nRELAY_PROGRESS_SAMPLES_EACH_DIRECTION=3\nRELAY_NEAR_UNBLOCK_GUARD_MS=%s\nDIRECT_FAULT_HOLD_MS=%s\nDIRECT_FAULT_HOLD_A_TO_B_MS=%s\nDIRECT_FAULT_HOLD_B_TO_A_MS=%s\nMAX_APPLICATION_OUTAGE_MS=%s\nMAX_APPLICATION_OUTAGE_A_TO_B_MS=%s\nMAX_APPLICATION_OUTAGE_B_TO_A_MS=%s\nMEMORY_CEILING_BYTES=%s\nEDGE_A_PEAK_MEMORY_BYTES=%s\nEDGE_B_PEAK_MEMORY_BYTES=%s\nPROCESS_CONTINUITY_CHECKS=%s\nCHECKSUM_DIRECTIONS=2\nSEQUENCE_RECORDS=2\nRELAY_CONTROL_OUTAGE_OBSERVATIONS=2\nRELAY_PROCESS_RESTARTS=1\nRELAY_RESTART_ACKS=1\nRELAY_RESTART_SIGNED_PERMITS=1\nRELAY_RESTART_SESSION_BINDINGS=1\nRELAY_RESTART_PERMIT_CONSUMPTIONS=1\nRELAY_RESTART_SIGNED_PHASES=2\nRELAY_RESTART_COMMITS=1\nRELAY_RESTART_NRESTARTS_DELTA=0\nRELAY_RESTART_COMMIT_STABILITY_MS=%s\nRELAY_RESTART_HOLD_MS=%s\nRELAY_RESTART_DURATION_MS=%s\nRELAY_RESTART_PROGRESS_A_TO_B_DELTA_BYTES=%s\nRELAY_RESTART_PROGRESS_B_TO_A_DELTA_BYTES=%s\nRELAY_RESTART_CONTROL_OUTAGE_OBSERVATIONS=2\nRELAY_RESTART_INVOCATION_TRANSITIONS=1\nDIRECT_WITHDRAWAL_OBSERVATIONS=2\n' \
  "${MODE}" "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${prerequisite_sha256}" "${started_ms}" "${completed_ms}" "${stream_bytes}" \
  "${IMPAIRED_MIN_MILLI_MBIT_S}" "${a_to_b_milli_mbit_s}" "${b_to_a_milli_mbit_s}" \
  "${relay_control_outage_ms}" "${before_control_a_to_b_bytes}" \
  "${during_control_a_to_b_bytes}" "${near_control_a_to_b_bytes}" \
  "${relay_progress_a_to_b_delta_bytes}" "${before_control_b_to_a_bytes}" \
  "${during_control_b_to_a_bytes}" "${near_control_b_to_a_bytes}" \
  "${relay_progress_b_to_a_delta_bytes}" "${relay_near_unblock_guard_ms}" \
  "${direct_fault_hold_ms}" "${direct_fault_hold_a_to_b_ms}" \
  "${direct_fault_hold_b_to_a_ms}" "${max_application_outage_ms}" \
  "${max_application_outage_a_to_b_ms}" "${max_application_outage_b_to_a_ms}" \
  "${MEMORY_CEILING_BYTES}" "${peak_a}" "${peak_b}" "${process_continuity_checks}" \
  "${relay_restart_commit_stability_ms}" \
  "${relay_restart_hold_ms}" "${relay_restart_duration_ms}" \
  "${relay_restart_progress_a_to_b_delta_bytes}" \
  "${relay_restart_progress_b_to_a_delta_bytes}" \
  > "${result_source}"
cat -- "${evidence_dir}/verified.env" >> "${result_source}"
campus_link_validate_gate_marker "${result_source}" "${run_manifest}" \
  fault-in-stream "${MODE}" STREAM_BYTES_EACH_DIRECTION STREAM_ROUNDS \
  IMPAIRED_MIN_MILLI_MBIT_S MEASURED_A_TO_B_MILLI_MBIT_S \
  MEASURED_B_TO_A_MILLI_MBIT_S \
  NETEM_DELAY_MS NETEM_JITTER_MS NETEM_LOSS_BASIS_POINTS \
  NETEM_REORDER_BASIS_POINTS RELAY_CONTROL_OUTAGE_MS \
  RELAY_PROGRESS_A_TO_B_BEFORE_BYTES RELAY_PROGRESS_A_TO_B_DURING_BYTES \
  RELAY_PROGRESS_A_TO_B_NEAR_UNBLOCK_BYTES RELAY_PROGRESS_A_TO_B_DELTA_BYTES \
  RELAY_PROGRESS_B_TO_A_BEFORE_BYTES RELAY_PROGRESS_B_TO_A_DURING_BYTES \
  RELAY_PROGRESS_B_TO_A_NEAR_UNBLOCK_BYTES RELAY_PROGRESS_B_TO_A_DELTA_BYTES \
  RELAY_PROGRESS_SAMPLES_EACH_DIRECTION RELAY_NEAR_UNBLOCK_GUARD_MS \
  DIRECT_FAULT_HOLD_MS DIRECT_FAULT_HOLD_A_TO_B_MS DIRECT_FAULT_HOLD_B_TO_A_MS \
  MAX_APPLICATION_OUTAGE_MS MAX_APPLICATION_OUTAGE_A_TO_B_MS \
  MAX_APPLICATION_OUTAGE_B_TO_A_MS MEMORY_CEILING_BYTES EDGE_A_PEAK_MEMORY_BYTES \
  EDGE_B_PEAK_MEMORY_BYTES PROCESS_CONTINUITY_CHECKS CHECKSUM_DIRECTIONS \
  SEQUENCE_RECORDS RELAY_CONTROL_OUTAGE_OBSERVATIONS RELAY_PROCESS_RESTARTS \
  RELAY_RESTART_ACKS RELAY_RESTART_SIGNED_PERMITS \
  RELAY_RESTART_SESSION_BINDINGS RELAY_RESTART_PERMIT_CONSUMPTIONS \
  RELAY_RESTART_SIGNED_PHASES RELAY_RESTART_COMMITS \
  RELAY_RESTART_NRESTARTS_DELTA RELAY_RESTART_COMMIT_STABILITY_MS \
  RELAY_RESTART_HOLD_MS \
  RELAY_RESTART_DURATION_MS \
  RELAY_RESTART_PROGRESS_A_TO_B_DELTA_BYTES \
  RELAY_RESTART_PROGRESS_B_TO_A_DELTA_BYTES \
  RELAY_RESTART_CONTROL_OUTAGE_OBSERVATIONS \
  RELAY_RESTART_INVOCATION_TRANSITIONS \
  DIRECT_WITHDRAWAL_OBSERVATIONS "${CAMPUS_LINK_FAULT_EVIDENCE_KEYS[@]}"
if [[ ${MODE} == production ]]; then
  campus_link_validate_fault_evidence_values "${result_source}"
fi
campus_link_atomic_marker "${RESULT}" "${result_source}"
printf 'STATUS=pass\nMODE=%s\nSTREAM_BYTES_EACH_DIRECTION=%s\nMAX_APPLICATION_OUTAGE_MS=%s\n' \
  "${MODE}" "${stream_bytes}" "${max_application_outage_ms}"
