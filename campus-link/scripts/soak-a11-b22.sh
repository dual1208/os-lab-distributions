#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-one-hour}
readonly PORT=18090
readonly RESULT=/run/campus-link/a11-b22-soak-${MODE}.result
readonly FAILURE=/run/campus-link/a11-b22-soak-${MODE}.failure
readonly STREAM_RECORD_BYTES=16777216
readonly MAX_STREAM_RECORDS=549755813887
readonly MIN_STREAM_BYTES_PER_SECOND=250000
readonly PROGRESS_TIMEOUT_SECONDS=30
readonly PROGRESS_TIMEOUT_MS=30000
readonly COMPLETION_GRACE_SECONDS=120
readonly OBSERVATION_LIMIT_MS=5000
readonly SOAK_CLEANUP_TOTAL_MILLISECONDS=25000
readonly SOAK_CLEANUP_TERM_GRACE_MILLISECONDS=5000
readonly CHILD_HANDSHAKE_TIMEOUT_SECONDS=5
readonly A_TO_B_SEQUENCE=30000000000
readonly B_TO_A_SEQUENCE=40000000000
SCRIPT_PARENT=$(dirname -- "${BASH_SOURCE[0]}") || exit 1
SCRIPT_DIR=$(cd -- "${SCRIPT_PARENT}" && pwd -P) || exit 1
readonly SCRIPT_DIR
unset SCRIPT_PARENT
if [[ -f ${SCRIPT_DIR}/campus-link-gate-evidence ]]; then
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/campus-link-gate-evidence
else
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/gate-evidence.sh
fi
if [[ -f /usr/local/libexec/campus-link-stream-transport.py ]]; then
  readonly STREAM_PROBE=/usr/local/libexec/campus-link-stream-transport.py
  readonly STATUS_GATE=/usr/local/libexec/campus-link-status-gate.py
else
  readonly STREAM_PROBE=${REPO_ROOT}/campus-link/tests/stream_transport.py
  readonly STATUS_GATE=${REPO_ROOT}/campus-link/tests/status_gate.py
fi

[[ ${EUID} -eq 0 ]]
[[ -f ${EVIDENCE_HELPER} && ! -L ${EVIDENCE_HELPER} ]]
[[ -f ${STREAM_PROBE} && ! -L ${STREAM_PROBE} ]]
[[ -f ${STATUS_GATE} && ! -L ${STATUS_GATE} ]]
# shellcheck source=gate-evidence.sh
source "${EVIDENCE_HELPER}"
umask 077

command_output_matches() {
  local pattern=$1 output
  shift
  output=$("$@") || return 1
  grep -- "${pattern}" <<< "${output}" >/dev/null
}

case ${MODE} in
  one-hour)
    duration=3600
    gate=one-hour-soak
    prerequisite=none
    prerequisite_gate=none
    ;;
  24-hour)
    duration=86400
    gate=24h-soak
    prerequisite=/run/campus-link/nat-rebinding.result
    prerequisite_gate=nat-rebinding
    ;;
  seven-day)
    duration=604800
    gate=7d-burn-in
    prerequisite=/run/campus-link/a11-b22-soak-24-hour.result
    prerequisite_gate=24h-soak
    ;;
  *)
    echo 'usage: soak-a11-b22.sh [REPO_ROOT] [one-hour|24-hour|seven-day]' >&2
    exit 2
    ;;
esac

campus_link_acquire_deployment_shared_lock
campus_link_acquire_gate_execution_lock
rm -f -- "${RESULT}" "${FAILURE}"

if [[ ${prerequisite} != none ]]; then
  readonly run_manifest=${CAMPUS_LINK_RUN_MANIFEST}
  campus_link_validate_run_manifest "${run_manifest}"
  run_id=$(campus_link_marker_value "${run_manifest}" RUN_ID) || exit 1
  candidate_sha256=$(campus_link_marker_value "${run_manifest}" CANDIDATE_SHA256) || exit 1
  run_manifest_sha256=$(campus_link_run_manifest_sha256 "${run_manifest}") || exit 1
  campus_link_validate_chain "${run_manifest}" "${prerequisite_gate}"
  prerequisite_sha256=$(sha256sum -- "${prerequisite}" | awk '{print $1}') || exit 1
else
  readonly run_manifest=none
  run_id=$(openssl rand -hex 16) || exit 1
  candidate_sha256=$(campus_link_candidate_fingerprint) || exit 1
  run_manifest_sha256=none
  prerequisite_sha256=none
fi
[[ ${run_id} =~ ^[a-f0-9]{32}$ ]]
[[ ${candidate_sha256} =~ ^[a-f0-9]{64}$ ]]
[[ ${prerequisite_sha256} == none || ${prerequisite_sha256} =~ ^[a-f0-9]{64}$ ]]

started_ms=0
stream_state=not-started
stream_started_ns=0
stream_updated_ns=0
stream_connections=0
stream_reconnects=0
stream_records=0
stream_sent=0
stream_received=0
stream_first_send=${A_TO_B_SEQUENCE}
stream_last_send=${A_TO_B_SEQUENCE}
stream_first_receive=${B_TO_A_SEQUENCE}
stream_last_receive=${B_TO_A_SEQUENCE}
stream_max_send_gap_ms=0
stream_max_receive_gap_ms=0
stream_transcript_sha256=none
progress_observations=0
direct_status_observations=0
pids=()
pid_start_ticks=()
evidence_dir=
status_previous=

process_start_ticks() {
  local pid=$1 line rest
  [[ ${pid} =~ ^[1-9][0-9]*$ && -r /proc/${pid}/stat ]] || return 1
  IFS= read -r line < "/proc/${pid}/stat" || return 1
  rest=${line##*) }
  [[ ${rest} != "${line}" ]] || return 1
  set -- ${rest}
  (( $# >= 20 )) || return 1
  [[ ${20} =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "${20}"
}

is_shell_uint() {
  local value=$1 maximum=9223372036854775807
  local LC_ALL=C
  [[ ${value} =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
  [[ ${#value} -lt 19 || ${value} < "${maximum}" || ${value} == "${maximum}" ]]
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
    elif [[ -r ${path} ]] && IFS= read -r line < "${path}"; then
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
    fi
  fi
  printf -v "${destination}" '%s' "${outcome}"
}

signal_tracked_child() {
  local pid=$1 expected_start_ticks=$2 signal_name=$3
  [[ ${pid} =~ ^[1-9][0-9]*$ && \
    ${expected_start_ticks} =~ ^[1-9][0-9]*$ ]] || return 1
  [[ ${signal_name} == TERM || ${signal_name} == KILL ]] || return 1
  python3 -B "${STREAM_PROBE}" signal-pid --pid "${pid}" \
    --start-ticks "${expected_start_ticks}" --signal "${signal_name}"
}

track_child() {
  local pid=$1 ticks=$2 state
  [[ ${pid} =~ ^[1-9][0-9]*$ && ${ticks} =~ ^[1-9][0-9]*$ ]] || return 1
  inspect_process_identity "${pid}" "${ticks}" state
  [[ ${state} == live ]] || return 1
  pids+=("${pid}")
  pid_start_ticks+=("${ticks}")
}

launch_tracked_child() {
  local pid_destination=$1 ticks_destination=$2 label=$3 output=$4
  shift 4
  local ready=${evidence_dir}/${label}.ready ack=${evidence_dir}/${label}.ack
  local nonce pid observed_nonce observed_pid observed_ticks extra state
  local ready_fd ack_fd wrapper_pid wrapper_ticks wrapper_ack metadata
  [[ ${label} == server || ${label} == client ]] || return 1
  [[ ${output} == "${evidence_dir}/${label}.log" && ! -e ${output} && \
    ! -L ${output} && $# -gt 0 ]] || return 1
  [[ ! -e ${ready} && ! -L ${ready} && ! -e ${ack} && ! -L ${ack} ]] || \
    return 1
  nonce=$(openssl rand -hex 16) || return 1
  [[ ${nonce} =~ ^[a-f0-9]{32}$ ]] || return 1
  mkfifo -m 0600 -- "${ready}" "${ack}" || return 1
  metadata=$(stat -c '%u:%g:%a:%h' -- "${ready}" "${ack}") || return 1
  [[ ${metadata} == $'0:0:600:1\n0:0:600:1' ]] || return 1
  exec {ready_fd}<>"${ready}" || return 1
  if ! exec {ack_fd}<>"${ack}"; then
    exec {ready_fd}>&-
    return 1
  fi
  (
    wrapper_pid=${BASHPID}
    wrapper_ticks=$(process_start_ticks "${wrapper_pid}") || exit 125
    printf '%s %s %s\n' "${nonce}" "${wrapper_pid}" "${wrapper_ticks}" \
      > "${ready}" || exit 125
    IFS= read -r -t "${CHILD_HANDSHAKE_TIMEOUT_SECONDS}" wrapper_ack \
      < "${ack}" || exit 125
    [[ ${wrapper_ack} == "${nonce}" ]] || exit 125
    exec {ready_fd}>&-
    exec {ack_fd}>&-
    exec "$@"
  ) >"${output}" 2>&1 &
  pid=$!

  state=invalid
  if IFS=' ' read -r -t "${CHILD_HANDSHAKE_TIMEOUT_SECONDS}" -u "${ready_fd}" \
    observed_nonce observed_pid observed_ticks extra && \
    [[ ${observed_nonce} == "${nonce}" && ${observed_pid} == "${pid}" && \
      ${observed_ticks} =~ ^[1-9][0-9]*$ && -z ${extra:-} ]] && \
    ! IFS= read -r -t 0 -u "${ready_fd}" extra && \
    track_child "${pid}" "${observed_ticks}"; then
    if printf '%s\n' "${nonce}" >&"${ack_fd}"; then
      state=ready
    fi
  fi
  exec {ready_fd}>&-
  exec {ack_fd}>&-
  rm -f -- "${ready}" "${ack}" || return 1
  [[ ${state} == ready ]] || return 1
  printf -v "${pid_destination}" '%s' "${pid}"
  printf -v "${ticks_destination}" '%s' "${observed_ticks}"
}

clear_tracked_child() {
  local target=$1 index found=0
  for index in "${!pids[@]}"; do
    if [[ ${pids[index]:-} == "${target}" ]]; then
      pids[index]=
      pid_start_ticks[index]=
      found=1
    fi
  done
  (( found != 0 ))
}

cleanup_tracked_children() {
  local deadline_ms=$1 kill_at_ms=$2 now_ms index pid state ignored_status
  local all_reaped
  local -a kill_sent=()
  for index in "${!pids[@]}"; do
    pid=${pids[index]:-}
    [[ -n ${pid} ]] || continue
    inspect_process_identity "${pid}" "${pid_start_ticks[index]:-}" state
    case ${state} in
      live)
        signal_tracked_child "${pid}" "${pid_start_ticks[index]}" TERM || return 1
        ;;
      zombie|gone)
        wait "${pid}" 2>/dev/null || ignored_status=$?
        pids[index]=
        pid_start_ticks[index]=
        ;;
      *) return 1 ;;
    esac
  done

  while :; do
    now_ms=$(campus_link_monotonic_ms) || return 1
    (( now_ms < deadline_ms )) || break
    all_reaped=1
    for index in "${!pids[@]}"; do
      pid=${pids[index]:-}
      [[ -n ${pid} ]] || continue
      inspect_process_identity "${pid}" "${pid_start_ticks[index]:-}" state
      case ${state} in
        live)
          all_reaped=0
          if (( now_ms >= kill_at_ms )) && \
            [[ -z ${kill_sent[index]+present} ]]; then
            signal_tracked_child "${pid}" "${pid_start_ticks[index]}" KILL || \
              return 1
            kill_sent[index]=1
          fi
          ;;
        zombie|gone)
          wait "${pid}" 2>/dev/null || ignored_status=$?
          pids[index]=
          pid_start_ticks[index]=
          ;;
        *) return 1 ;;
      esac
    done
    (( all_reaped != 0 )) && return 0
    sleep 0.05 || return 1
  done

  for index in "${!pids[@]}"; do
    pid=${pids[index]:-}
    [[ -n ${pid} ]] || continue
    inspect_process_identity "${pid}" "${pid_start_ticks[index]:-}" state
    case ${state} in
      zombie|gone)
        wait "${pid}" 2>/dev/null || ignored_status=$?
        pids[index]=
        pid_start_ticks[index]=
        ;;
      *) return 1 ;;
    esac
  done
  return 0
}

cleanup() {
  local status=$? cleanup_ok=1 started deadline kill_at
  trap - EXIT HUP INT TERM
  set +e
  started=$(campus_link_monotonic_ms) || cleanup_ok=0
  if (( cleanup_ok != 0 )); then
    deadline=$((started + SOAK_CLEANUP_TOTAL_MILLISECONDS))
    kill_at=$((started + SOAK_CLEANUP_TERM_GRACE_MILLISECONDS))
    cleanup_tracked_children "${deadline}" "${kill_at}" || cleanup_ok=0
  fi
  if (( cleanup_ok != 0 )) && [[ -n ${result_source:-} ]]; then
    if [[ ${result_source} == /run/campus-link/.a11-b22-soak-result.* && \
      -f ${result_source} && ! -L ${result_source} ]]; then
      rm -f -- "${result_source}" || cleanup_ok=0
    else
      cleanup_ok=0
    fi
  fi
  if (( cleanup_ok != 0 )) && [[ -n ${evidence_dir} ]]; then
    if [[ ${evidence_dir} == /run/campus-link/.continuous-soak.* && \
      -d ${evidence_dir} && ! -L ${evidence_dir} ]]; then
      rm -f -- "${evidence_dir}/progress.json" "${evidence_dir}/client.log" \
        "${evidence_dir}/server.log" "${evidence_dir}/status-before.json" \
        "${evidence_dir}/status-current.json" "${evidence_dir}/status-next.json" \
        "${evidence_dir}/status-verified.env" "${evidence_dir}/server.expected" \
        "${evidence_dir}/server.ready" "${evidence_dir}/server.ack" \
        "${evidence_dir}/client.ready" "${evidence_dir}/client.ack" || \
        cleanup_ok=0
      (( cleanup_ok == 0 )) || rmdir -- "${evidence_dir}" 2>/dev/null || \
        cleanup_ok=0
    else
      cleanup_ok=0
    fi
  fi
  if (( cleanup_ok == 0 && status == 0 )); then
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

fail_soak() {
  local direction=$1 failure_class=$2 completed_ms tmp
  completed_ms=$(campus_link_monotonic_ms) || exit 1
  tmp=$(mktemp /run/campus-link/.a11-b22-soak-failure.XXXXXX) || exit 1
  printf 'FORMAT=1\nSTATUS=fail\nGATE=%s\nMODE=%s\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=%s\nSTART_MONOTONIC_MS=%s\nCOMPLETE_MONOTONIC_MS=%s\nDIRECTION=%s\nFAILURE_CLASS=%s\nTCP_CONNECTIONS=%s\nTCP_RECONNECTS=%s\nFULL_DUPLEX_RECORDS=%s\nSTREAM_BYTES_A_TO_B=%s\nSTREAM_BYTES_B_TO_A=%s\nPROGRESS_OBSERVATIONS=%s\nMAX_PROGRESS_GAP_A_TO_B_MS=%s\nMAX_PROGRESS_GAP_B_TO_A_MS=%s\n' \
    "${gate}" "${MODE}" "${run_id}" "${candidate_sha256}" \
    "${run_manifest_sha256}" "${prerequisite_sha256}" "${started_ms}" \
    "${completed_ms}" "${direction}" "${failure_class}" \
    "${stream_connections}" "${stream_reconnects}" "${stream_records}" \
    "${stream_sent}" "${stream_received}" "${progress_observations}" \
    "${stream_max_send_gap_ms}" "${stream_max_receive_gap_ms}" > "${tmp}"
  campus_link_validate_schema "${tmp}" \
    FORMAT STATUS GATE MODE RUN_ID CANDIDATE_SHA256 RUN_MANIFEST_SHA256 \
    PREREQUISITE_MARKER_SHA256 START_MONOTONIC_MS COMPLETE_MONOTONIC_MS \
    DIRECTION FAILURE_CLASS TCP_CONNECTIONS TCP_RECONNECTS \
    FULL_DUPLEX_RECORDS STREAM_BYTES_A_TO_B STREAM_BYTES_B_TO_A \
    PROGRESS_OBSERVATIONS MAX_PROGRESS_GAP_A_TO_B_MS \
    MAX_PROGRESS_GAP_B_TO_A_MS
  campus_link_atomic_marker "${FAILURE}" "${tmp}"
  rm -f -- "${tmp}"
  exit 1
}

assert_soak_immutable() {
  local current
  if [[ ${prerequisite} != none ]]; then
    campus_link_validate_chain "${run_manifest}" "${prerequisite_gate}" || return 1
    current=$(sha256sum -- "${prerequisite}" | awk '{print $1}') || return 1
    [[ ${current} == "${prerequisite_sha256}" ]] || return 1
    campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
  else
    current=$(campus_link_candidate_fingerprint) || return 1
    [[ ${current} == "${candidate_sha256}" ]]
  fi
}

assert_runtime() {
  local value
  assert_soak_immutable || return 1
  systemctl is-active --quiet campus-link-edge-a.service campus-link-edge-b.service || return 1
  value=$(systemctl show -p NRestarts --value campus-link-edge-a.service) || return 1
  [[ ${value} == "${edge_a_restarts}" ]] || return 1
  value=$(systemctl show -p NRestarts --value campus-link-edge-b.service) || return 1
  [[ ${value} == "${edge_b_restarts}" ]] || return 1
  value=$(systemctl show -p InvocationID --value campus-link-edge-a.service) || return 1
  [[ ${value} == "${edge_a_invocation}" ]] || return 1
  value=$(systemctl show -p InvocationID --value campus-link-edge-b.service) || return 1
  [[ ${value} == "${edge_b_invocation}" ]] || return 1
  command_output_matches 'dev cl0' ip -n campus-a route show 10.82.0.0/24 || return 1
  command_output_matches 'dev cl0' ip -n campus-b route show 10.81.0.0/24 || return 1
}

verify_soak_status_sample() {
  local final=${1:-no} next=${evidence_dir}/status-next.json
  local current=${evidence_dir}/status-current.json
  [[ ${final} == no || ${final} == yes ]] || return 1
  [[ ${status_previous} == "${evidence_dir}/status-before.json" || \
    ${status_previous} == "${current}" ]] || return 1
  rm -f -- "${next}" || return 1
  python3 -B "${STATUS_GATE}" capture \
    --edge-a /run/campus-link/site-a/status.json \
    --edge-b /run/campus-link/site-b/status.json \
    --after "${status_previous}" --timeout-seconds 5 \
    --output "${next}" || return 1
  if [[ ${final} == yes ]]; then
    rm -f -- "${evidence_dir}/status-verified.env" || return 1
    python3 -B "${STATUS_GATE}" verify-soak \
      --before "${evidence_dir}/status-before.json" \
      --previous "${status_previous}" --after "${next}" \
      --minimum-direct-packets 1000 --raw-relay-rate 1 --final \
      > "${evidence_dir}/status-verified.env" || return 1
  else
    python3 -B "${STATUS_GATE}" verify-soak \
      --before "${evidence_dir}/status-before.json" \
      --previous "${status_previous}" --after "${next}" \
      --minimum-direct-packets 1000 --raw-relay-rate 1 || return 1
  fi
  if [[ ${status_previous} == "${current}" ]]; then
    rm -f -- "${current}" || return 1
  fi
  mv -- "${next}" "${current}" || return 1
  status_previous=${current}
  direct_status_observations=$((direct_status_observations + 1))
}

load_stream_progress() {
  local output extra
  output=$(python3 -B "${STREAM_PROBE}" inspect-continuous \
    --progress-file "${evidence_dir}/progress.json" 2>/dev/null) || return 1
  [[ ${output} != *$'\n'* ]] || return 1
  read -r stream_state stream_started_ns stream_updated_ns stream_connections \
    stream_reconnects stream_records stream_sent stream_received \
    stream_first_send stream_last_send stream_first_receive stream_last_receive \
    stream_max_send_gap_ms stream_max_receive_gap_ms stream_transcript_sha256 \
    extra <<< "${output}" || return 1
  [[ -z ${extra:-} ]] || return 1
  [[ ${stream_state} == running || ${stream_state} == pass ]] || return 1
  local value
  for value in "${stream_started_ns}" "${stream_updated_ns}" \
    "${stream_connections}" "${stream_reconnects}" "${stream_records}" \
    "${stream_sent}" "${stream_received}" "${stream_first_send}" \
    "${stream_last_send}" "${stream_first_receive}" "${stream_last_receive}" \
    "${stream_max_send_gap_ms}" "${stream_max_receive_gap_ms}"; do
    is_shell_uint "${value}" || return 1
  done
  [[ ${stream_transcript_sha256} =~ ^[a-f0-9]{64}$ ]] || return 1
  (( stream_records <= MAX_STREAM_RECORDS )) || return 1
}

python3 -B "${STATUS_GATE}" wait-direct \
  --edge-a /run/campus-link/site-a/status.json \
  --edge-b /run/campus-link/site-b/status.json --timeout-seconds 60 || \
  fail_soak BOTH direct-path-preflight
edge_a_restarts=$(systemctl show -p NRestarts --value campus-link-edge-a.service) || \
  fail_soak BOTH runtime-preflight
edge_b_restarts=$(systemctl show -p NRestarts --value campus-link-edge-b.service) || \
  fail_soak BOTH runtime-preflight
edge_a_invocation=$(systemctl show -p InvocationID --value campus-link-edge-a.service) || \
  fail_soak BOTH runtime-preflight
edge_b_invocation=$(systemctl show -p InvocationID --value campus-link-edge-b.service) || \
  fail_soak BOTH runtime-preflight
[[ ${edge_a_restarts} =~ ^[0-9]+$ && ${edge_b_restarts} =~ ^[0-9]+$ ]]
[[ ${edge_a_invocation} =~ ^[a-f0-9]{32}$ && ${edge_b_invocation} =~ ^[a-f0-9]{32}$ ]]
assert_runtime || fail_soak BOTH runtime-preflight

evidence_dir=$(mktemp -d /run/campus-link/.continuous-soak.XXXXXX) || \
  fail_soak BOTH evidence-directory
[[ -d ${evidence_dir} && ! -L ${evidence_dir} ]]
evidence_metadata=$(stat -c '%u:%g:%a' -- "${evidence_dir}") || \
  fail_soak BOTH evidence-directory
[[ ${evidence_metadata} == 0:0:700 ]] || fail_soak BOTH evidence-directory
python3 -B "${STATUS_GATE}" capture \
  --edge-a /run/campus-link/site-a/status.json \
  --edge-b /run/campus-link/site-b/status.json \
  --output "${evidence_dir}/status-before.json" || \
  fail_soak BOTH direct-status-preflight
status_previous=${evidence_dir}/status-before.json
direct_status_observations=1
last_status_observation_ms=$(campus_link_monotonic_ms) || \
  fail_soak BOTH direct-status-preflight
assert_runtime || fail_soak BOTH runtime-preflight
server_phase_timeout=$((duration + COMPLETION_GRACE_SECONDS + 10))
launch_tracked_child server_pid server_start_ticks server \
  "${evidence_dir}/server.log" \
  ip netns exec oslab-b python3 -B "${STREAM_PROBE}" serve-once \
  --bind 10.82.0.22 --port "${PORT}" --max-stream-bytes "${STREAM_RECORD_BYTES}" \
  --progress-timeout "${PROGRESS_TIMEOUT_SECONDS}" \
  --phase-timeout "${server_phase_timeout}" --accept-timeout 30 || \
  fail_soak BOTH stream-server-identity
sleep 1
inspect_process_identity "${server_pid}" "${server_start_ticks}" server_state
[[ ${server_state} == live ]] || fail_soak BOTH stream-server-start

client_launch_ms=$(campus_link_monotonic_ms) || fail_soak BOTH stream-client-time
if [[ ${prerequisite} != none ]]; then
  prerequisite_completed_ms=$(campus_link_marker_value "${prerequisite}" COMPLETE_MONOTONIC_MS) || \
    fail_soak BOTH prerequisite-time-order
  (( client_launch_ms >= prerequisite_completed_ms )) || fail_soak BOTH prerequisite-time-order
fi
launch_tracked_child client_pid client_start_ticks client \
  "${evidence_dir}/client.log" \
  ip netns exec oslab-a python3 -B "${STREAM_PROBE}" continuous-client \
  --source 10.81.0.11 --destination 10.82.0.22 --port "${PORT}" \
  --duration-seconds "${duration}" \
  --completion-grace-seconds "${COMPLETION_GRACE_SECONDS}" \
  --record-bytes "${STREAM_RECORD_BYTES}" --send-sequence "${A_TO_B_SEQUENCE}" \
  --receive-sequence "${B_TO_A_SEQUENCE}" \
  --progress-timeout "${PROGRESS_TIMEOUT_SECONDS}" --progress-interval 1 \
  --progress-file "${evidence_dir}/progress.json" || \
  fail_soak BOTH stream-client-identity

initial_deadline_ms=$((client_launch_ms + PROGRESS_TIMEOUT_MS))
while ! load_stream_progress; do
  inspect_process_identity "${client_pid}" "${client_start_ticks}" client_state
  inspect_process_identity "${server_pid}" "${server_start_ticks}" server_state
  [[ ${client_state} == live && ${server_state} == live ]] || \
    fail_soak BOTH stream-start
  now_ms=$(campus_link_monotonic_ms) || fail_soak BOTH stream-start-timeout
  (( now_ms < initial_deadline_ms )) || fail_soak BOTH stream-start-timeout
  if (( now_ms - last_status_observation_ms >= 1000 )); then
    assert_runtime || fail_soak BOTH runtime-changed
    verify_soak_status_sample no || fail_soak BOTH direct-status-evidence
    last_status_observation_ms=$(campus_link_monotonic_ms) || \
      fail_soak BOTH direct-status-evidence
  fi
  sleep 0.1
done
started_ms=$((stream_started_ns / 1000000))
(( started_ms >= client_launch_ms )) || fail_soak BOTH stream-start-time-order
[[ ${stream_connections} == 1 && ${stream_reconnects} == 0 ]] || fail_soak BOTH connection-count
[[ ${stream_first_send} == "${A_TO_B_SEQUENCE}" ]] || fail_soak A_TO_B sequence-start
[[ ${stream_first_receive} == "${B_TO_A_SEQUENCE}" ]] || fail_soak B_TO_A sequence-start

progress_observations=1
last_observation_ms=$(campus_link_monotonic_ms) || fail_soak BOTH observation-time
last_updated_ns=${stream_updated_ns}
last_records=${stream_records}
last_sent=${stream_sent}
last_received=${stream_received}
last_send_advance_ms=${started_ms}
last_receive_advance_ms=${started_ms}

while :; do
  inspect_process_identity "${client_pid}" "${client_start_ticks}" client_state
  case ${client_state} in
    live) ;;
    zombie|gone) break ;;
    *) fail_soak BOTH stream-client-identity ;;
  esac
  inspect_process_identity "${server_pid}" "${server_start_ticks}" server_state
  [[ ${server_state} == live ]] || fail_soak BOTH stream-server-dead
  assert_runtime || fail_soak BOTH runtime-changed
  verify_soak_status_sample no || fail_soak BOTH direct-status-evidence
  last_status_observation_ms=$(campus_link_monotonic_ms) || \
    fail_soak BOTH direct-status-evidence
  load_stream_progress || fail_soak BOTH progress-evidence
  now_ms=$(campus_link_monotonic_ms) || fail_soak BOTH observation-time
  (( now_ms - last_observation_ms <= OBSERVATION_LIMIT_MS )) || fail_soak BOTH observation-deadline
  [[ ${stream_connections} == 1 && ${stream_reconnects} == 0 ]] || fail_soak BOTH connection-count
  (( stream_started_ns / 1000000 == started_ms )) || fail_soak BOTH stream-start-changed
  (( stream_updated_ns >= last_updated_ns )) || fail_soak BOTH progress-regressed
  (( stream_records >= last_records )) || fail_soak BOTH record-regressed
  (( stream_sent >= last_sent )) || fail_soak A_TO_B progress-regressed
  (( stream_received >= last_received )) || fail_soak B_TO_A progress-regressed
  if (( stream_sent > last_sent )); then
    last_send_advance_ms=${now_ms}
  fi
  if (( stream_received > last_received )); then
    last_receive_advance_ms=${now_ms}
  fi
  (( now_ms - last_send_advance_ms <= PROGRESS_TIMEOUT_MS )) || fail_soak A_TO_B progress-timeout
  (( now_ms - last_receive_advance_ms <= PROGRESS_TIMEOUT_MS )) || fail_soak B_TO_A progress-timeout
  (( stream_max_send_gap_ms <= PROGRESS_TIMEOUT_MS )) || fail_soak A_TO_B progress-gap
  (( stream_max_receive_gap_ms <= PROGRESS_TIMEOUT_MS )) || fail_soak B_TO_A progress-gap
  last_updated_ns=${stream_updated_ns}
  last_records=${stream_records}
  last_sent=${stream_sent}
  last_received=${stream_received}
  progress_observations=$((progress_observations + 1))
  last_observation_ms=${now_ms}
  sleep 1
done

if ! wait "${client_pid}"; then
  fail_soak BOTH stream-client-failed
fi
clear_tracked_child "${client_pid}" || fail_soak BOTH stream-client-identity
load_stream_progress || fail_soak BOTH final-progress-evidence
[[ ${stream_state} == pass ]] || fail_soak BOTH stream-not-complete
now_ms=$(campus_link_monotonic_ms) || fail_soak BOTH stream-server-close-timeout
server_exit_deadline=$((now_ms + PROGRESS_TIMEOUT_MS))
while :; do
  inspect_process_identity "${server_pid}" "${server_start_ticks}" server_state
  case ${server_state} in
    live) ;;
    zombie|gone) break ;;
    *) fail_soak BOTH stream-server-identity ;;
  esac
  now_ms=$(campus_link_monotonic_ms) || fail_soak BOTH stream-server-close-timeout
  (( now_ms < server_exit_deadline )) || fail_soak BOTH stream-server-close-timeout
  if (( now_ms - last_status_observation_ms >= 1000 )); then
    assert_runtime || fail_soak BOTH runtime-changed
    verify_soak_status_sample no || fail_soak BOTH direct-status-evidence
    last_status_observation_ms=$(campus_link_monotonic_ms) || \
      fail_soak BOTH direct-status-evidence
  fi
  sleep 0.1
done
if ! wait "${server_pid}"; then
  fail_soak BOTH stream-server-failed
fi
clear_tracked_child "${server_pid}" || fail_soak BOTH stream-server-identity
printf 'PASS connections=1 reconnects=0 records=%s\n' "${stream_records}" \
  > "${evidence_dir}/server.expected" || fail_soak BOTH stream-server-evidence
[[ -f ${evidence_dir}/server.log && ! -L ${evidence_dir}/server.log && \
  -f ${evidence_dir}/server.expected && ! -L ${evidence_dir}/server.expected ]] || \
  fail_soak BOTH stream-server-evidence
server_log_metadata=$(stat -c '%u:%g:%a:%h' -- "${evidence_dir}/server.log") || \
  fail_soak BOTH stream-server-evidence
server_expected_metadata=$(stat -c '%u:%g:%a:%h' -- \
  "${evidence_dir}/server.expected") || fail_soak BOTH stream-server-evidence
[[ ${server_log_metadata} == 0:0:600:1 && \
  ${server_expected_metadata} == 0:0:600:1 ]] || \
  fail_soak BOTH stream-server-evidence
cmp -s -- "${evidence_dir}/server.log" "${evidence_dir}/server.expected" || \
  fail_soak BOTH stream-server-evidence

assert_runtime || fail_soak BOTH runtime-final
verify_soak_status_sample yes || fail_soak BOTH direct-status-final
last_status_observation_ms=$(campus_link_monotonic_ms) || \
  fail_soak BOTH direct-status-final
load_stream_progress || fail_soak BOTH final-progress-evidence
progress_observations=$((progress_observations + 1))
[[ ${stream_state} == pass ]] || fail_soak BOTH stream-not-complete
[[ ${stream_connections} == 1 && ${stream_reconnects} == 0 ]] || fail_soak BOTH connection-count
(( stream_records > 0 )) || fail_soak BOTH no-complete-record
completed_ms=$((stream_updated_ns / 1000000))
session_elapsed_ms=$((completed_ms - started_ms))
(( stream_records <= MAX_STREAM_RECORDS )) || fail_soak BOTH record-count-overflow
(( stream_sent == stream_records * STREAM_RECORD_BYTES )) || fail_soak A_TO_B byte-accounting
(( stream_received == stream_records * STREAM_RECORD_BYTES )) || fail_soak B_TO_A byte-accounting
minimum_stream_bytes=$((session_elapsed_ms * MIN_STREAM_BYTES_PER_SECOND / 1000))
(( stream_sent >= minimum_stream_bytes )) || fail_soak A_TO_B throughput-floor
(( stream_received >= minimum_stream_bytes )) || fail_soak B_TO_A throughput-floor
[[ ${stream_first_send} == "${A_TO_B_SEQUENCE}" ]] || fail_soak A_TO_B sequence-start
[[ ${stream_first_receive} == "${B_TO_A_SEQUENCE}" ]] || fail_soak B_TO_A sequence-start
(( stream_last_send == stream_first_send + stream_records - 1 )) || fail_soak A_TO_B sequence-end
(( stream_last_receive == stream_first_receive + stream_records - 1 )) || fail_soak B_TO_A sequence-end
(( stream_max_send_gap_ms <= PROGRESS_TIMEOUT_MS )) || fail_soak A_TO_B progress-gap
(( stream_max_receive_gap_ms <= PROGRESS_TIMEOUT_MS )) || fail_soak B_TO_A progress-gap

(( completed_ms >= started_ms + duration * 1000 )) || fail_soak BOTH stream-ended-early
(( completed_ms <= started_ms + (duration + COMPLETION_GRACE_SECONDS) * 1000 )) || fail_soak BOTH completion-grace
elapsed=$(((completed_ms - started_ms) / 1000))
minimum_observations=$((duration / 5))
(( progress_observations >= minimum_observations )) || fail_soak BOTH insufficient-observations
(( direct_status_observations >= minimum_observations && \
  direct_status_observations >= progress_observations )) || \
  fail_soak BOTH insufficient-direct-status-observations
campus_link_validate_schema "${evidence_dir}/status-verified.env" \
  "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}" || \
  fail_soak BOTH direct-status-schema
max_direct_evidence_ms=$(((duration + COMPLETION_GRACE_SECONDS + 60) * 1000))
minimum_direct_evidence_ms=$((duration * 1000))
campus_link_validate_direct_evidence_values \
  "${evidence_dir}/status-verified.env" "${max_direct_evidence_ms}" 1000 \
  "${minimum_direct_evidence_ms}" || fail_soak BOTH direct-status-values

result_source=$(mktemp /run/campus-link/.a11-b22-soak-result.XXXXXX) || \
  fail_soak BOTH result-file
printf 'FORMAT=1\nSTATUS=pass\nGATE=%s\nMODE=%s\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=%s\nSTART_MONOTONIC_MS=%s\nCOMPLETE_MONOTONIC_MS=%s\nREQUIRED_DURATION_SECONDS=%s\nDURATION_SECONDS=%s\nTCP_CONNECTIONS=1\nTCP_RECONNECTS=0\nFULL_DUPLEX_RECORDS=%s\nSTREAM_BYTES_A_TO_B=%s\nSTREAM_BYTES_B_TO_A=%s\nFIRST_A_TO_B_SEQUENCE=%s\nLAST_A_TO_B_SEQUENCE=%s\nFIRST_B_TO_A_SEQUENCE=%s\nLAST_B_TO_A_SEQUENCE=%s\nSTREAM_TRANSCRIPT_SHA256=%s\nPROGRESS_TIMEOUT_MS=%s\nCOMPLETION_GRACE_SECONDS=%s\nMAX_PROGRESS_GAP_A_TO_B_MS=%s\nMAX_PROGRESS_GAP_B_TO_A_MS=%s\nPROGRESS_OBSERVATIONS=%s\nDIRECT_STATUS_OBSERVATIONS=%s\n' \
  "${gate}" "${MODE}" "${run_id}" "${candidate_sha256}" \
  "${run_manifest_sha256}" "${prerequisite_sha256}" "${started_ms}" \
  "${completed_ms}" "${duration}" "${elapsed}" "${stream_records}" \
  "${stream_sent}" "${stream_received}" "${stream_first_send}" \
  "${stream_last_send}" "${stream_first_receive}" "${stream_last_receive}" \
  "${stream_transcript_sha256}" "${PROGRESS_TIMEOUT_MS}" \
  "${COMPLETION_GRACE_SECONDS}" "${stream_max_send_gap_ms}" \
  "${stream_max_receive_gap_ms}" "${progress_observations}" \
  "${direct_status_observations}" > "${result_source}"
cat -- "${evidence_dir}/status-verified.env" >> "${result_source}"
campus_link_validate_continuous_stream_values "${result_source}" "${duration}" || \
  fail_soak BOTH result-stream-values
campus_link_validate_direct_evidence_values "${result_source}" \
  "${max_direct_evidence_ms}" 1000 "${minimum_direct_evidence_ms}" || \
  fail_soak BOTH result-direct-values
if [[ ${prerequisite} != none ]]; then
  campus_link_validate_gate_marker "${result_source}" "${run_manifest}" \
    "${gate}" "${MODE}" REQUIRED_DURATION_SECONDS DURATION_SECONDS \
    TCP_CONNECTIONS TCP_RECONNECTS FULL_DUPLEX_RECORDS STREAM_BYTES_A_TO_B \
    STREAM_BYTES_B_TO_A FIRST_A_TO_B_SEQUENCE LAST_A_TO_B_SEQUENCE \
    FIRST_B_TO_A_SEQUENCE LAST_B_TO_A_SEQUENCE STREAM_TRANSCRIPT_SHA256 \
    PROGRESS_TIMEOUT_MS COMPLETION_GRACE_SECONDS \
    MAX_PROGRESS_GAP_A_TO_B_MS MAX_PROGRESS_GAP_B_TO_A_MS \
    PROGRESS_OBSERVATIONS DIRECT_STATUS_OBSERVATIONS \
    "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}"
else
  campus_link_validate_schema "${result_source}" \
    FORMAT STATUS GATE MODE RUN_ID CANDIDATE_SHA256 RUN_MANIFEST_SHA256 \
    PREREQUISITE_MARKER_SHA256 START_MONOTONIC_MS COMPLETE_MONOTONIC_MS \
    REQUIRED_DURATION_SECONDS DURATION_SECONDS TCP_CONNECTIONS \
    TCP_RECONNECTS FULL_DUPLEX_RECORDS STREAM_BYTES_A_TO_B \
    STREAM_BYTES_B_TO_A FIRST_A_TO_B_SEQUENCE LAST_A_TO_B_SEQUENCE \
    FIRST_B_TO_A_SEQUENCE LAST_B_TO_A_SEQUENCE STREAM_TRANSCRIPT_SHA256 \
    PROGRESS_TIMEOUT_MS COMPLETION_GRACE_SECONDS \
    MAX_PROGRESS_GAP_A_TO_B_MS MAX_PROGRESS_GAP_B_TO_A_MS \
    PROGRESS_OBSERVATIONS DIRECT_STATUS_OBSERVATIONS \
    "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}"
fi
campus_link_atomic_marker "${RESULT}" "${result_source}"
rm -f -- "${result_source}"
result_source=
printf 'STATUS=pass\nMODE=%s\nDURATION_SECONDS=%s\nTCP_CONNECTIONS=1\nTCP_RECONNECTS=0\nFULL_DUPLEX_RECORDS=%s\nSTREAM_BYTES_A_TO_B=%s\nSTREAM_BYTES_B_TO_A=%s\nMAX_PROGRESS_GAP_A_TO_B_MS=%s\nMAX_PROGRESS_GAP_B_TO_A_MS=%s\nPROGRESS_OBSERVATIONS=%s\nDIRECT_STATUS_OBSERVATIONS=%s\n' \
  "${MODE}" "${elapsed}" "${stream_records}" "${stream_sent}" \
  "${stream_received}" "${stream_max_send_gap_ms}" \
  "${stream_max_receive_gap_ms}" "${progress_observations}" \
  "${direct_status_observations}"
