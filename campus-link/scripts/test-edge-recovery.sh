#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-smoke}
readonly RESULTS=/run/campus-link/edge-recovery.tsv
SCRIPT_PARENT=$(dirname -- "${BASH_SOURCE[0]}") || exit 1
SCRIPT_DIR=$(cd -- "${SCRIPT_PARENT}" && pwd -P) || exit 1
readonly SCRIPT_DIR
unset SCRIPT_PARENT
if [[ -f ${SCRIPT_DIR}/campus-link-gate-evidence ]]; then
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/campus-link-gate-evidence
else
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/gate-evidence.sh
fi
if [[ -f /usr/local/libexec/campus-link-a11-b22.py ]]; then
  readonly PROBE=/usr/local/libexec/campus-link-a11-b22.py
else
  readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
fi
if [[ -f /usr/local/libexec/campus-link-stream-transport.py ]]; then
  readonly STREAM_PROBE=/usr/local/libexec/campus-link-stream-transport.py
else
  readonly STREAM_PROBE=${REPO_ROOT}/campus-link/tests/stream_transport.py
fi

[[ ${EUID} -eq 0 ]]
[[ -f ${EVIDENCE_HELPER} && ! -L ${EVIDENCE_HELPER} ]]
[[ -f ${PROBE} && ! -L ${PROBE} ]]
[[ -f ${STREAM_PROBE} && ! -L ${STREAM_PROBE} ]]
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
  smoke) trials=5 ;;
  full) trials=30 ;;
  *) echo 'usage: test-edge-recovery.sh [REPO_ROOT] [smoke|full]' >&2; exit 2 ;;
esac
readonly POST_HEALTH_GUARD_MS=2000
readonly MAX_TRACKED_RESTARTS=999999999999999
readonly STREAM_PORT=18091
readonly STREAM_RECORD_BYTES=1048576
readonly STREAM_PROGRESS_TIMEOUT_SECONDS=30
readonly STREAM_PROGRESS_TIMEOUT_MS=30000
readonly STREAM_START_TIMEOUT_MS=10000
readonly STREAM_SESSION_DEADLINE_SECONDS=45
readonly STREAM_COMPLETION_GRACE_SECONDS=15
readonly STREAM_COMPLETION_TIMEOUT_SECONDS=15
readonly MAX_STREAM_COUNTER=8999999999999999999
readonly A_TO_B_SEQUENCE_BASE=30000000000
readonly B_TO_A_SEQUENCE_BASE=40000000000
readonly STREAM_SEQUENCE_STRIDE=1000000

# Populated only by read_unit_state. Keeping the three values in one
# systemctl transaction avoids accepting a tuple assembled across a restart.
UNIT_ACTIVE_STATE=
UNIT_INVOCATION_ID=
UNIT_RESTART_COUNT=
read_unit_state() {
  local unit=$1 output key value
  local seen_active=0 seen_invocation=0 seen_restarts=0
  UNIT_ACTIVE_STATE=
  UNIT_INVOCATION_ID=
  UNIT_RESTART_COUNT=
  if ! output=$(systemctl show --no-pager \
      --property=ActiveState --property=InvocationID --property=NRestarts "${unit}"); then
    echo "could not read supervised state for ${unit}" >&2
    return 1
  fi
  while IFS='=' read -r key value; do
    case ${key} in
      ActiveState)
        (( seen_active == 0 )) || { echo "duplicate ActiveState for ${unit}" >&2; return 1; }
        UNIT_ACTIVE_STATE=${value}
        seen_active=1
        ;;
      InvocationID)
        (( seen_invocation == 0 )) || { echo "duplicate InvocationID for ${unit}" >&2; return 1; }
        UNIT_INVOCATION_ID=${value}
        seen_invocation=1
        ;;
      NRestarts)
        (( seen_restarts == 0 )) || { echo "duplicate NRestarts for ${unit}" >&2; return 1; }
        UNIT_RESTART_COUNT=${value}
        seen_restarts=1
        ;;
      '')
        [[ -z ${value} ]] || { echo "malformed supervised property for ${unit}" >&2; return 1; }
        ;;
      *) echo "unexpected supervised property for ${unit}" >&2; return 1 ;;
    esac
  done <<< "${output}"
  (( seen_active == 1 && seen_invocation == 1 && seen_restarts == 1 )) || {
    echo "incomplete supervised state for ${unit}" >&2
    return 1
  }
  [[ ${UNIT_ACTIVE_STATE} =~ ^[a-z][a-z-]*$ ]] || {
    echo "malformed ActiveState for ${unit}" >&2
    return 1
  }
  [[ -z ${UNIT_INVOCATION_ID} || ${UNIT_INVOCATION_ID} =~ ^[0-9a-f]{32}$ ]] || {
    echo "malformed InvocationID for ${unit}" >&2
    return 1
  }
  [[ ${UNIT_RESTART_COUNT} =~ ^(0|[1-9][0-9]{0,14})$ ]] || {
    echo "malformed or unbounded NRestarts for ${unit}" >&2
    return 1
  }
}

require_active_identity() {
  local unit=$1
  read_unit_state "${unit}" || return 1
  [[ ${UNIT_ACTIVE_STATE} == active && ${UNIT_INVOCATION_ID} =~ ^[0-9a-f]{32}$ ]] || {
    echo "${unit} lacked one canonical active invocation" >&2
    return 1
  }
}

assert_survivor_state() {
  local unit=$1 expected_invocation=$2 expected_restarts=$3
  read_unit_state "${unit}" || return 1
  [[ ${UNIT_ACTIVE_STATE} == active && ${UNIT_INVOCATION_ID} == "${expected_invocation}" &&
     ${UNIT_RESTART_COUNT} == "${expected_restarts}" ]] || {
    echo "surviving edge identity or restart count changed for ${unit}" >&2
    return 1
  }
}

# Populated by observe_target_restart. An empty invocation means that the
# single supervised replacement has not reached an active invocation yet.
OBSERVED_TARGET_INVOCATION=
OBSERVED_TARGET_INCREMENTED=0
observe_target_restart() {
  local unit=$1 before_invocation=$2 before_restarts=$3 expected_restarts=$4
  local pinned_invocation=$5 increment_seen=$6
  OBSERVED_TARGET_INVOCATION=
  OBSERVED_TARGET_INCREMENTED=${increment_seen}
  read_unit_state "${unit}" || return 1
  case ${UNIT_RESTART_COUNT} in
    "${before_restarts}")
      (( increment_seen == 0 )) || {
        echo "target restart count reset for ${unit}" >&2
        return 1
      }
      [[ -z ${pinned_invocation} ]] || {
        echo "target restart count changed after replacement for ${unit}" >&2
        return 1
      }
      if [[ ${UNIT_ACTIVE_STATE} == active ]]; then
        [[ ${UNIT_INVOCATION_ID} == "${before_invocation}" ]] || {
          echo "target invocation changed without one restart for ${unit}" >&2
          return 1
        }
      fi
      ;;
    "${expected_restarts}")
      OBSERVED_TARGET_INCREMENTED=1
      if [[ ${UNIT_ACTIVE_STATE} != active ]]; then
        [[ -z ${pinned_invocation} ]] || {
          echo "replacement target stopped after becoming healthy for ${unit}" >&2
          return 1
        }
        return 0
      fi
      [[ ${UNIT_INVOCATION_ID} =~ ^[0-9a-f]{32}$ &&
         ${UNIT_INVOCATION_ID} != "${before_invocation}" ]] || {
        echo "target did not acquire exactly one replacement invocation for ${unit}" >&2
        return 1
      }
      if [[ -n ${pinned_invocation} && ${UNIT_INVOCATION_ID} != "${pinned_invocation}" ]]; then
        echo "target replacement invocation changed again for ${unit}" >&2
        return 1
      fi
      OBSERVED_TARGET_INVOCATION=${UNIT_INVOCATION_ID}
      ;;
    *)
      echo "target restart count reset, overflowed, or jumped for ${unit}" >&2
      return 1
      ;;
  esac
}

assert_target_pinned() {
  local unit=$1 expected_invocation=$2 expected_restarts=$3
  [[ ${expected_invocation} =~ ^[0-9a-f]{32}$ ]] || return 1
  read_unit_state "${unit}" || return 1
  [[ ${UNIT_ACTIVE_STATE} == active && ${UNIT_INVOCATION_ID} == "${expected_invocation}" &&
     ${UNIT_RESTART_COUNT} == "${expected_restarts}" ]] || {
    echo "target edge restarted or changed identity during recovery guard for ${unit}" >&2
    return 1
  }
}

pids=()
trial_dirs=()
stream_client_pid=
stream_server_pid=
stream_watchdog_pid=
evidence_dir=$(mktemp -d /run/campus-link/.edge-recovery.XXXXXX) || exit 1
transcript_source=${evidence_dir}/transcripts.tsv
results_work=$(mktemp /run/campus-link/.edge-recovery-results.XXXXXX) || exit 1
: > "${transcript_source}"

stream_connections=0
stream_reconnects=0
full_duplex_records=0
stream_bytes_a_to_b=0
stream_bytes_b_to_a=0
pre_restart_progress_checks=0
replacement_active_checkpoints=0
post_restart_progress_checks=0
stream_survival_checks=0
max_progress_gap_a_to_b_ms=0
max_progress_gap_b_to_a_ms=0
max_recovery_ms=0

# Populated only by load_stream_progress, which delegates exact JSON schema,
# custody, duplicate-key, and link validation to the transport harness.
STREAM_STATE=
STREAM_STARTED_NS=0
STREAM_UPDATED_NS=0
STREAM_CONNECTIONS=0
STREAM_RECONNECTS=0
STREAM_RECORDS=0
STREAM_SENT=0
STREAM_RECEIVED=0
STREAM_FIRST_SEND=0
STREAM_LAST_SEND=0
STREAM_FIRST_RECEIVE=0
STREAM_LAST_RECEIVE=0
STREAM_MAX_SEND_GAP_MS=0
STREAM_MAX_RECEIVE_GAP_MS=0
STREAM_TRANSCRIPT_SHA256=
load_stream_progress() {
  local progress_file=$1 output extra value
  output=$(python3 -B "${STREAM_PROBE}" inspect-continuous \
    --progress-file "${progress_file}") || return 1
  [[ ${output} != *$'\n'* ]] || return 1
  read -r STREAM_STATE STREAM_STARTED_NS STREAM_UPDATED_NS \
    STREAM_CONNECTIONS STREAM_RECONNECTS STREAM_RECORDS STREAM_SENT \
    STREAM_RECEIVED STREAM_FIRST_SEND STREAM_LAST_SEND STREAM_FIRST_RECEIVE \
    STREAM_LAST_RECEIVE STREAM_MAX_SEND_GAP_MS STREAM_MAX_RECEIVE_GAP_MS \
    STREAM_TRANSCRIPT_SHA256 extra <<< "${output}"
  [[ -z ${extra:-} ]] || return 1
  [[ ${STREAM_STATE} == running || ${STREAM_STATE} == pass ]] || return 1
  for value in "${STREAM_STARTED_NS}" "${STREAM_UPDATED_NS}" \
    "${STREAM_CONNECTIONS}" "${STREAM_RECONNECTS}" "${STREAM_RECORDS}" \
    "${STREAM_SENT}" "${STREAM_RECEIVED}" "${STREAM_FIRST_SEND}" \
    "${STREAM_LAST_SEND}" "${STREAM_FIRST_RECEIVE}" "${STREAM_LAST_RECEIVE}" \
    "${STREAM_MAX_SEND_GAP_MS}" "${STREAM_MAX_RECEIVE_GAP_MS}"; do
    [[ ${value} =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
    (( value <= MAX_STREAM_COUNTER )) || return 1
  done
  (( STREAM_STARTED_NS > 0 && STREAM_UPDATED_NS >= STREAM_STARTED_NS )) || return 1
  [[ ${STREAM_CONNECTIONS} == 1 && ${STREAM_RECONNECTS} == 0 ]] || return 1
  [[ ${STREAM_TRANSCRIPT_SHA256} =~ ^[a-f0-9]{64}$ ]] || return 1
  (( STREAM_RECORDS <= MAX_STREAM_COUNTER / STREAM_RECORD_BYTES )) || return 1
  (( STREAM_MAX_SEND_GAP_MS <= STREAM_PROGRESS_TIMEOUT_MS )) || return 1
  (( STREAM_MAX_RECEIVE_GAP_MS <= STREAM_PROGRESS_TIMEOUT_MS )) || return 1
}

process_start_ticks() {
  local pid=$1 stat_line tail
  local -a fields
  [[ ${pid} =~ ^[1-9][0-9]*$ ]] || return 1
  IFS= read -r stat_line < "/proc/${pid}/stat" || return 1
  [[ ${stat_line} == "${pid} ("* && ${stat_line} == *') '* ]] || return 1
  # Field 22 is token 20 after the final command-name delimiter. Using the
  # final delimiter remains correct even if the parenthesized comm has spaces
  # or parentheses.
  tail=${stat_line##*) }
  read -r -a fields <<< "${tail}"
  (( ${#fields[@]} >= 20 )) || return 1
  [[ ${fields[19]} =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "${fields[19]}"
}

process_established_socket() {
  local pid=$1 descriptor link inode
  local -a sockets=()
  [[ ${pid} =~ ^[1-9][0-9]*$ && -d /proc/${pid}/fd ]] || return 1
  for descriptor in /proc/"${pid}"/fd/*; do
    link=$(readlink -- "${descriptor}" 2>/dev/null) || return 1
    if [[ ${link} =~ ^socket:\[([0-9]+)\]$ ]]; then
      sockets+=("${BASH_REMATCH[1]}")
    fi
  done
  (( ${#sockets[@]} == 1 )) || return 1
  inode=${sockets[0]}
  awk -v inode="${inode}" '
    NR > 1 && $4 == "01" && $10 == inode { matches++ }
    END { exit(matches == 1 ? 0 : 1) }
  ' "/proc/${pid}/net/tcp" || return 1
  printf '%s\n' "${inode}"
}

process_instance() {
  local pid=$1 first_start second_start first_socket second_socket
  local proc_identity executable_identity
  first_start=$(process_start_ticks "${pid}") || return 1
  first_socket=$(process_established_socket "${pid}") || return 1
  proc_identity=$(stat -Lc '%d:%i' -- "/proc/${pid}" 2>/dev/null) || return 1
  executable_identity=$(stat -Lc '%d:%i' -- "/proc/${pid}/exe" 2>/dev/null) || return 1
  second_start=$(process_start_ticks "${pid}") || return 1
  second_socket=$(process_established_socket "${pid}") || return 1
  [[ ${first_start} == "${second_start}" && ${first_socket} == "${second_socket}" &&
     ${proc_identity} =~ ^[0-9]+:[0-9]+$ &&
     ${executable_identity} =~ ^[0-9]+:[0-9]+$ ]] || return 1
  printf '%s:%s:%s:%s\n' "${first_start}" "${proc_identity}" \
    "${executable_identity}" "${first_socket}"
}

assert_stream_live() {
  local current_client_instance current_server_instance
  kill -0 "${TRIAL_CLIENT_PID}" "${TRIAL_SERVER_PID}" 2>/dev/null || {
    echo 'established stream process exited during edge restart' >&2
    return 1
  }
  current_client_instance=$(process_instance "${TRIAL_CLIENT_PID}") || return 1
  current_server_instance=$(process_instance "${TRIAL_SERVER_PID}") || return 1
  [[ ${current_client_instance} == "${TRIAL_CLIENT_INSTANCE}" &&
     ${current_server_instance} == "${TRIAL_SERVER_INSTANCE}" ]] || {
    echo 'established stream process instance was replaced' >&2
    return 1
  }
  load_stream_progress "${TRIAL_PROGRESS_FILE}" || {
    echo 'established stream progress evidence became invalid' >&2
    return 1
  }
  [[ ${STREAM_STATE} == running &&
     ${STREAM_STARTED_NS} == "${TRIAL_STARTED_NS}" &&
     ${STREAM_FIRST_SEND} == "${TRIAL_FIRST_SEND}" &&
     ${STREAM_FIRST_RECEIVE} == "${TRIAL_FIRST_RECEIVE}" ]] || {
    echo 'established stream identity changed during edge restart' >&2
    return 1
  }
  (( STREAM_UPDATED_NS >= TRIAL_UPDATED_NS &&
     STREAM_RECORDS >= TRIAL_RECORDS &&
     STREAM_SENT >= TRIAL_SENT && STREAM_RECEIVED >= TRIAL_RECEIVED )) || {
    echo 'established stream progress regressed' >&2
    return 1
  }
  if (( STREAM_RECORDS == TRIAL_RECORDS )); then
    [[ ${STREAM_TRANSCRIPT_SHA256} == "${TRIAL_TRANSCRIPT_SHA256}" ]] || {
      echo 'stream transcript changed without a complete record' >&2
      return 1
    }
  else
    [[ ${STREAM_TRANSCRIPT_SHA256} != "${TRIAL_TRANSCRIPT_SHA256}" ]] || {
      echo 'stream record advanced without digest progress' >&2
      return 1
    }
  fi
  TRIAL_UPDATED_NS=${STREAM_UPDATED_NS}
  TRIAL_RECORDS=${STREAM_RECORDS}
  TRIAL_SENT=${STREAM_SENT}
  TRIAL_RECEIVED=${STREAM_RECEIVED}
  TRIAL_TRANSCRIPT_SHA256=${STREAM_TRANSCRIPT_SHA256}
  stream_survival_checks=$((stream_survival_checks + 1))
}

start_stream_transaction() {
  local stream_index=$1 listener_deadline pre_deadline now_ms listener_output
  local send_sequence=$((A_TO_B_SEQUENCE_BASE + stream_index * STREAM_SEQUENCE_STRIDE))
  local receive_sequence=$((B_TO_A_SEQUENCE_BASE + stream_index * STREAM_SEQUENCE_STRIDE))
  TRIAL_DIR=${evidence_dir}/trial-${stream_index}
  mkdir -m 0700 -- "${TRIAL_DIR}"
  trial_dirs+=("${TRIAL_DIR}")
  TRIAL_PROGRESS_FILE=${TRIAL_DIR}/progress.json
  TRIAL_STOP_FILE=${TRIAL_DIR}/stop.marker
  TRIAL_CLIENT_LOG=${TRIAL_DIR}/client.log
  TRIAL_SERVER_LOG=${TRIAL_DIR}/server.log
  [[ ! -e ${TRIAL_PROGRESS_FILE} && ! -L ${TRIAL_PROGRESS_FILE} &&
     ! -e ${TRIAL_STOP_FILE} && ! -L ${TRIAL_STOP_FILE} ]]
  command -v ss >/dev/null
  listener_output=$(ip netns exec oslab-b ss -H -ltn "sport = :${STREAM_PORT}") || return 1
  if [[ -n ${listener_output} ]]; then
    echo 'dedicated stream port was already in use' >&2
    return 1
  fi
  ip netns exec oslab-b python3 -B "${STREAM_PROBE}" serve-once \
    --bind 10.82.0.22 --port "${STREAM_PORT}" \
    --max-stream-bytes "${STREAM_RECORD_BYTES}" \
    --progress-timeout "${STREAM_PROGRESS_TIMEOUT_SECONDS}" \
    --phase-timeout "$((STREAM_SESSION_DEADLINE_SECONDS + STREAM_COMPLETION_GRACE_SECONDS))" \
    --accept-timeout 10 >"${TRIAL_SERVER_LOG}" 2>&1 &
  TRIAL_SERVER_PID=$!
  stream_server_pid=${TRIAL_SERVER_PID}
  now_ms=$(campus_link_monotonic_ms) || return 1
  listener_deadline=$((now_ms + 5000))
  while :; do
    listener_output=$(ip netns exec oslab-b ss -H -ltn "sport = :${STREAM_PORT}") || return 1
    [[ -z ${listener_output} ]] || break
    kill -0 "${TRIAL_SERVER_PID}" 2>/dev/null || {
      echo 'single-accept stream server exited before connect' >&2
      return 1
    }
    now_ms=$(campus_link_monotonic_ms) || return 1
    (( now_ms < listener_deadline )) || {
      echo 'single-accept stream server did not listen before deadline' >&2
      return 1
    }
    sleep 0.05
  done
  ip netns exec oslab-a python3 -B "${STREAM_PROBE}" continuous-client \
    --source 10.81.0.11 --destination 10.82.0.22 --port "${STREAM_PORT}" \
    --duration-seconds "${STREAM_SESSION_DEADLINE_SECONDS}" \
    --completion-grace-seconds "${STREAM_COMPLETION_GRACE_SECONDS}" \
    --record-bytes "${STREAM_RECORD_BYTES}" --send-sequence "${send_sequence}" \
    --receive-sequence "${receive_sequence}" \
    --progress-timeout "${STREAM_PROGRESS_TIMEOUT_SECONDS}" \
    --progress-file "${TRIAL_PROGRESS_FILE}" --progress-interval 0.05 \
    --stop-file "${TRIAL_STOP_FILE}" >"${TRIAL_CLIENT_LOG}" 2>&1 &
  TRIAL_CLIENT_PID=$!
  stream_client_pid=${TRIAL_CLIENT_PID}

  now_ms=$(campus_link_monotonic_ms) || return 1
  pre_deadline=$((now_ms + STREAM_START_TIMEOUT_MS))
  while true; do
    kill -0 "${TRIAL_CLIENT_PID}" "${TRIAL_SERVER_PID}" 2>/dev/null || {
      echo 'stream ended before pre-restart progress' >&2
      return 1
    }
    [[ ! -e ${TRIAL_STOP_FILE} && ! -L ${TRIAL_STOP_FILE} ]] || {
      echo 'stream stop marker appeared before the restart transaction' >&2
      return 1
    }
    if [[ -e ${TRIAL_PROGRESS_FILE} || -L ${TRIAL_PROGRESS_FILE} ]]; then
      load_stream_progress "${TRIAL_PROGRESS_FILE}" || return 1
      [[ ${STREAM_STATE} == running &&
         ${STREAM_FIRST_SEND} == "${send_sequence}" &&
         ${STREAM_FIRST_RECEIVE} == "${receive_sequence}" ]] || return 1
      if (( STREAM_RECORDS > 0 && STREAM_SENT > 0 && STREAM_RECEIVED > 0 )); then
        break
      fi
    fi
    now_ms=$(campus_link_monotonic_ms) || return 1
    (( now_ms < pre_deadline )) || {
      echo 'stream lacked pre-restart full-duplex digest progress' >&2
      return 1
    }
    sleep 0.05
  done
  TRIAL_CLIENT_INSTANCE=$(process_instance "${TRIAL_CLIENT_PID}") || return 1
  TRIAL_SERVER_INSTANCE=$(process_instance "${TRIAL_SERVER_PID}") || return 1
  TRIAL_STARTED_NS=${STREAM_STARTED_NS}
  TRIAL_UPDATED_NS=${STREAM_UPDATED_NS}
  TRIAL_RECORDS=${STREAM_RECORDS}
  TRIAL_SENT=${STREAM_SENT}
  TRIAL_RECEIVED=${STREAM_RECEIVED}
  TRIAL_FIRST_SEND=${STREAM_FIRST_SEND}
  TRIAL_FIRST_RECEIVE=${STREAM_FIRST_RECEIVE}
  TRIAL_TRANSCRIPT_SHA256=${STREAM_TRANSCRIPT_SHA256}
  TRIAL_PRE_RECORDS=${STREAM_RECORDS}
  TRIAL_PRE_SENT=${STREAM_SENT}
  TRIAL_PRE_RECEIVED=${STREAM_RECEIVED}
  TRIAL_PRE_TRANSCRIPT_SHA256=${STREAM_TRANSCRIPT_SHA256}
  pre_restart_progress_checks=$((pre_restart_progress_checks + 1))
}

finish_stream_transaction() {
  local stop_tmp client_status server_status final_expected_bytes
  local client_log_lines server_log_lines
  stop_tmp=${TRIAL_STOP_FILE}.tmp
  [[ ! -e ${TRIAL_STOP_FILE} && ! -L ${TRIAL_STOP_FILE} &&
     ! -e ${stop_tmp} && ! -L ${stop_tmp} ]]
  printf 'CAMPUS_LINK_STOP=1\n' > "${stop_tmp}"
  chmod 0600 -- "${stop_tmp}"
  mv -T -- "${stop_tmp}" "${TRIAL_STOP_FILE}"

  (
    sleep "${STREAM_COMPLETION_TIMEOUT_SECONDS}"
    kill "${TRIAL_CLIENT_PID}" "${TRIAL_SERVER_PID}" 2>/dev/null || true
  ) &
  stream_watchdog_pid=$!
  set +e
  wait "${TRIAL_CLIENT_PID}"
  client_status=$?
  wait "${TRIAL_SERVER_PID}"
  server_status=$?
  set -e
  kill "${stream_watchdog_pid}" 2>/dev/null || true
  wait "${stream_watchdog_pid}" 2>/dev/null || true
  stream_watchdog_pid=
  stream_client_pid=
  stream_server_pid=
  TRIAL_CLIENT_PID=
  TRIAL_SERVER_PID=
  (( client_status == 0 && server_status == 0 )) || {
    echo 'established stream did not close cleanly after post-restart progress' >&2
    return 1
  }

  load_stream_progress "${TRIAL_PROGRESS_FILE}" || return 1
  [[ ${STREAM_STATE} == pass && ${STREAM_STARTED_NS} == "${TRIAL_STARTED_NS}" &&
     ${STREAM_FIRST_SEND} == "${TRIAL_FIRST_SEND}" &&
     ${STREAM_FIRST_RECEIVE} == "${TRIAL_FIRST_RECEIVE}" ]] || return 1
  (( STREAM_RECORDS > TRIAL_PRE_RECORDS &&
     STREAM_SENT > TRIAL_PRE_SENT && STREAM_RECEIVED > TRIAL_PRE_RECEIVED &&
     STREAM_RECORDS >= TRIAL_POST_RECORDS &&
     STREAM_SENT >= TRIAL_POST_SENT && STREAM_RECEIVED >= TRIAL_POST_RECEIVED &&
     STREAM_RECORDS >= TRIAL_RECORDS && STREAM_SENT >= TRIAL_SENT &&
     STREAM_RECEIVED >= TRIAL_RECEIVED )) || return 1
  [[ ${STREAM_TRANSCRIPT_SHA256} != "${TRIAL_PRE_TRANSCRIPT_SHA256}" ]] || return 1
  final_expected_bytes=$((STREAM_RECORDS * STREAM_RECORD_BYTES))
  (( STREAM_SENT == final_expected_bytes && STREAM_RECEIVED == final_expected_bytes )) || return 1
  client_log_lines=$(wc -l < "${TRIAL_CLIENT_LOG}") || return 1
  server_log_lines=$(wc -l < "${TRIAL_SERVER_LOG}") || return 1
  [[ ${client_log_lines} =~ ^(0|[1-9][0-9]*)$ &&
     ${server_log_lines} =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  [[ ${client_log_lines} -eq 1 && ${server_log_lines} -eq 1 ]]
  grep -Fx "PASS connections=1 reconnects=0 records=${STREAM_RECORDS} sent_bytes=${STREAM_SENT} received_bytes=${STREAM_RECEIVED} transcript_sha256=${STREAM_TRANSCRIPT_SHA256}" \
    "${TRIAL_CLIENT_LOG}" >/dev/null
  grep -Fx "PASS connections=1 reconnects=0 records=${STREAM_RECORDS}" \
    "${TRIAL_SERVER_LOG}" >/dev/null

  (( full_duplex_records <= MAX_STREAM_COUNTER - STREAM_RECORDS &&
     stream_bytes_a_to_b <= MAX_STREAM_COUNTER - STREAM_SENT &&
     stream_bytes_b_to_a <= MAX_STREAM_COUNTER - STREAM_RECEIVED )) || return 1
  stream_connections=$((stream_connections + 1))
  full_duplex_records=$((full_duplex_records + STREAM_RECORDS))
  stream_bytes_a_to_b=$((stream_bytes_a_to_b + STREAM_SENT))
  stream_bytes_b_to_a=$((stream_bytes_b_to_a + STREAM_RECEIVED))
  (( STREAM_MAX_SEND_GAP_MS <= max_progress_gap_a_to_b_ms )) || \
    max_progress_gap_a_to_b_ms=${STREAM_MAX_SEND_GAP_MS}
  (( STREAM_MAX_RECEIVE_GAP_MS <= max_progress_gap_b_to_a_ms )) || \
    max_progress_gap_b_to_a_ms=${STREAM_MAX_RECEIVE_GAP_MS}
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${stream_connections}" \
    "${TRIAL_PRE_RECORDS}" "${TRIAL_PRE_TRANSCRIPT_SHA256}" \
    "${TRIAL_RESTART_RECORDS}" "${TRIAL_RESTART_TRANSCRIPT_SHA256}" \
    "${TRIAL_POST_RECORDS}" "${TRIAL_POST_TRANSCRIPT_SHA256}" \
    "${STREAM_RECORDS}" "${STREAM_TRANSCRIPT_SHA256}" >> "${transcript_source}"
}

cleanup() {
  local trial_dir
  [[ -z ${stream_watchdog_pid} ]] || kill "${stream_watchdog_pid}" 2>/dev/null || true
  [[ -z ${stream_client_pid} ]] || kill "${stream_client_pid}" 2>/dev/null || true
  [[ -z ${stream_server_pid} ]] || kill "${stream_server_pid}" 2>/dev/null || true
  if (( ${#pids[@]} > 0 )); then
    kill "${pids[@]}" 2>/dev/null || true
  fi
  [[ -z ${results_work} ]] || rm -f -- "${results_work}"
  for trial_dir in "${trial_dirs[@]}"; do
    [[ ${trial_dir} == "${evidence_dir}"/trial-* && -d ${trial_dir} && ! -L ${trial_dir} ]] || continue
    rm -f -- "${trial_dir}/progress.json" "${trial_dir}/stop.marker" \
      "${trial_dir}/stop.marker.tmp" "${trial_dir}/client.log" "${trial_dir}/server.log"
    rmdir -- "${trial_dir}" 2>/dev/null || true
  done
  if [[ ${evidence_dir} == /run/campus-link/.edge-recovery.* && -d ${evidence_dir} && ! -L ${evidence_dir} ]]; then
    rm -f -- "${transcript_source}"
    rmdir -- "${evidence_dir}" 2>/dev/null || true
  fi
}
trap cleanup EXIT
ip netns exec oslab-a python3 -B "${PROBE}" serve --bind 10.81.0.11 >/dev/null 2>&1 &
pids+=("$!")
ip netns exec oslab-b python3 -B "${PROBE}" serve --bind 10.82.0.22 >/dev/null 2>&1 &
pids+=("$!")
sleep 1
kill -0 "${pids[@]}"
printf 'edge\ttrial\trecovery_ms\tkill_switch\tconnections\treconnects\trecords\tsent_bytes\treceived_bytes\tmax_send_gap_ms\tmax_receive_gap_ms\ttranscript_sha256\n' > "${results_work}"

kill_switch_active() {
  local namespace=$1 remote_prefix=$2 remote_probe=$3 wan_device=$4
  command_output_matches 'metric 32760' \
    ip -n "${namespace}" route show type unreachable "${remote_prefix}" || return 1
  command_output_matches 'dev cl0 metric 10' \
    ip -n "${namespace}" route show "${remote_prefix}" || return 1
  command_output_matches ' dev cl0 ' \
    ip -n "${namespace}" route get "${remote_probe}" || return 1
  ip netns exec "${namespace}" iptables -w -C OUTPUT -d "${remote_prefix}" \
    -o "${wan_device}" -m comment --comment campus-link-private-prefix-kill-switch -j REJECT || return 1
  ip netns exec "${namespace}" iptables -w -C FORWARD -d "${remote_prefix}" \
    -o "${wan_device}" -m comment --comment campus-link-private-prefix-kill-switch -j REJECT
}

assert_no_plaintext_wan() {
  local namespace=$1 host_device=$2 remote_prefix=$3 remote_probe=$4
  local lan_namespace=$5 source=$6
  local capture capture_pid capture_status
  command -v tcpdump >/dev/null
  capture=$(mktemp /run/campus-link/.kill-switch-capture.XXXXXX) || return 1
  timeout 2 tcpdump -qn -i "${host_device}" -c 1 "dst net ${remote_prefix}" \
    >"${capture}" 2>/dev/null &
  capture_pid=$!
  sleep 0.2
  ip netns exec "${namespace}" python3 -B -c \
    'import socket,sys; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"campus-link-kill-switch", (sys.argv[1], 9))' \
    "${remote_probe}" >/dev/null 2>&1 || true
  ip netns exec "${lan_namespace}" python3 -B -c \
    'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((sys.argv[1],0)); s.sendto(b"campus-link-forward-kill-switch",(sys.argv[2],9))' \
    "${source}" "${remote_probe}" >/dev/null 2>&1 || true
  set +e
  wait "${capture_pid}"
  capture_status=$?
  set -e
  if (( capture_status == 0 )); then
    rm -f -- "${capture}"
    echo "private-prefix plaintext reached ${host_device}" >&2
    return 1
  fi
  [[ ${capture_status} -eq 124 && ! -s ${capture} ]]
  rm -f -- "${capture}"
}

health() {
  local namespace=$1 source=$2 destination=$3
  timeout 3 ip netns exec "${namespace}" python3 -B "${PROBE}" health \
    --source "${source}" --destination "${destination}" >/dev/null 2>&1
}

run_trial() {
  local edge=$1 unit=$2 survivor_unit=$3 namespace=$4 remote_prefix=$5 remote_probe=$6 wan_device=$7
  local wan_host=$8 source=$9 destination=${10} trial=${11} stream_index=${12}
  local target_before_invocation target_before_restarts target_expected_restarts
  local survivor_invocation survivor_restarts target_invocation= target_incremented=0
  local started deadline kill_switch=0 wan_proven=0 finished guard_deadline recovery_ms
  local now_ms route_output route_ready route_match_status
  [[ ${unit} != "${survivor_unit}" ]] || {
    echo "target and survivor units must differ" >&2
    return 1
  }
  # The sole full-duplex connection and a complete digest-bound record must
  # exist before either supervised edge snapshot and before the kill signal.
  start_stream_transaction "${stream_index}"
  TRIAL_RESTART_BASELINE_SET=0
  require_active_identity "${unit}"
  target_before_invocation=${UNIT_INVOCATION_ID}
  target_before_restarts=${UNIT_RESTART_COUNT}
  (( target_before_restarts < MAX_TRACKED_RESTARTS )) || {
    echo "target NRestarts cannot be incremented safely for ${unit}" >&2
    return 1
  }
  target_expected_restarts=$((target_before_restarts + 1))
  require_active_identity "${survivor_unit}"
  survivor_invocation=${UNIT_INVOCATION_ID}
  survivor_restarts=${UNIT_RESTART_COUNT}
  started=$(campus_link_monotonic_ms) || return 1
  deadline=$((started + 30000))
  systemctl kill --kill-whom=main --signal=KILL "${unit}"
  assert_stream_live
  now_ms=$(campus_link_monotonic_ms) || return 1
  while (( now_ms < deadline )); do
    assert_stream_live
    assert_survivor_state "${survivor_unit}" "${survivor_invocation}" "${survivor_restarts}"
    observe_target_restart "${unit}" "${target_before_invocation}" "${target_before_restarts}" \
      "${target_expected_restarts}" "${target_invocation}" "${target_incremented}"
    target_incremented=${OBSERVED_TARGET_INCREMENTED}
    if [[ -n ${OBSERVED_TARGET_INVOCATION} ]]; then
      if (( TRIAL_RESTART_BASELINE_SET == 0 )); then
        TRIAL_RESTART_RECORDS=${TRIAL_RECORDS}
        TRIAL_RESTART_SENT=${TRIAL_SENT}
        TRIAL_RESTART_RECEIVED=${TRIAL_RECEIVED}
        TRIAL_RESTART_TRANSCRIPT_SHA256=${TRIAL_TRANSCRIPT_SHA256}
        TRIAL_RESTART_BASELINE_SET=1
        replacement_active_checkpoints=$((replacement_active_checkpoints + 1))
      fi
      target_invocation=${OBSERVED_TARGET_INVOCATION}
    fi
    if kill_switch_active "${namespace}" "${remote_prefix}" "${remote_probe}" "${wan_device}"; then
      kill_switch=1
      if (( wan_proven == 0 )); then
        assert_no_plaintext_wan "${namespace}" "${wan_host}" "${remote_prefix}" "${remote_probe}" \
          "${namespace/campus/oslab}" "${source}"
        wan_proven=1
      fi
    fi
    route_output=$(ip -n "${namespace}" route show "${remote_prefix}") || return 1
    route_ready=0
    if grep 'dev cl0' <<< "${route_output}" >/dev/null; then
      route_ready=1
    else
      route_match_status=$?
      [[ ${route_match_status} -eq 1 ]] || return 1
    fi
    if [[ -n ${target_invocation} ]] && (( route_ready == 1 )) && \
       health "${namespace/campus/oslab}" "${source}" "${destination}" && \
       (( TRIAL_RESTART_BASELINE_SET == 1 &&
          TRIAL_RECORDS > TRIAL_RESTART_RECORDS &&
          TRIAL_SENT > TRIAL_RESTART_SENT &&
          TRIAL_RECEIVED > TRIAL_RESTART_RECEIVED )) && \
       [[ ${TRIAL_TRANSCRIPT_SHA256} != "${TRIAL_RESTART_TRANSCRIPT_SHA256}" ]]; then
      finished=$(campus_link_monotonic_ms) || return 1
      (( finished <= deadline )) || {
        echo "${edge} recovered after the 30-second stream bound" >&2
        return 1
      }
      TRIAL_POST_RECORDS=${TRIAL_RECORDS}
      TRIAL_POST_SENT=${TRIAL_SENT}
      TRIAL_POST_RECEIVED=${TRIAL_RECEIVED}
      TRIAL_POST_TRANSCRIPT_SHA256=${TRIAL_TRANSCRIPT_SHA256}
      post_restart_progress_checks=$((post_restart_progress_checks + 1))
      guard_deadline=$((finished + POST_HEALTH_GUARD_MS))
      while :; do
        now_ms=$(campus_link_monotonic_ms) || return 1
        (( now_ms < guard_deadline )) || break
        assert_stream_live
        assert_survivor_state "${survivor_unit}" "${survivor_invocation}" "${survivor_restarts}"
        assert_target_pinned "${unit}" "${target_invocation}" "${target_expected_restarts}"
        kill -0 "${pids[@]}"
        kill_switch_active "${namespace}" "${remote_prefix}" "${remote_probe}" "${wan_device}"
        health "${namespace/campus/oslab}" "${source}" "${destination}"
        sleep 0.2
      done
      assert_stream_live
      assert_survivor_state "${survivor_unit}" "${survivor_invocation}" "${survivor_restarts}"
      assert_target_pinned "${unit}" "${target_invocation}" "${target_expected_restarts}"
      kill_switch_active "${namespace}" "${remote_prefix}" "${remote_probe}" "${wan_device}"
      health "${namespace/campus/oslab}" "${source}" "${destination}"
      finish_stream_transaction
      recovery_ms=$((finished - started))
      (( recovery_ms <= max_recovery_ms )) || max_recovery_ms=${recovery_ms}
      printf '%s\t%s\t%s\t%s\t1\t0\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${edge}" "${trial}" "${recovery_ms}" "${kill_switch}" \
        "${STREAM_RECORDS}" "${STREAM_SENT}" "${STREAM_RECEIVED}" \
        "${STREAM_MAX_SEND_GAP_MS}" "${STREAM_MAX_RECEIVE_GAP_MS}" \
        "${STREAM_TRANSCRIPT_SHA256}" >> "${results_work}"
      return 0
    fi
    sleep 0.2
    now_ms=$(campus_link_monotonic_ms) || return 1
  done
  echo "${edge} recovery trial ${trial} exceeded 30 seconds" >&2
  return 1
}

stream_index=0
# for trial in each direction, use shell arithmetic so no external sequence
# producer can truncate the requested qualification count.
for (( trial = 1; trial <= trials; trial++ )); do
  stream_index=$((stream_index + 1))
  run_trial site-a campus-link-edge-a.service campus-link-edge-b.service campus-a 10.82.0.0/24 \
    10.82.0.1 cl-a-wan clwan-a-host 10.81.0.11 10.82.0.22 "${trial}" "${stream_index}"
done
for (( trial = 1; trial <= trials; trial++ )); do
  stream_index=$((stream_index + 1))
  run_trial site-b campus-link-edge-b.service campus-link-edge-a.service campus-b 10.81.0.0/24 \
    10.81.0.1 cl-b-wan clwan-b-host 10.82.0.22 10.81.0.11 "${trial}" "${stream_index}"
done

expected_trials=$((trials * 2))
awk -F '\t' -v expected="${expected_trials}" '
  NR == 1 {
    if ($0 != "edge\ttrial\trecovery_ms\tkill_switch\tconnections\treconnects\trecords\tsent_bytes\treceived_bytes\tmax_send_gap_ms\tmax_receive_gap_ms\ttranscript_sha256") exit 2
    next
  }
  NF != 12 || $4 != 1 || $5 != 1 || $6 != 0 || $7 !~ /^[1-9][0-9]*$/ ||
    $8 !~ /^[1-9][0-9]*$/ || $9 !~ /^[1-9][0-9]*$/ ||
    $12 !~ /^[a-f0-9]{64}$/ { exit 3 }
  { rows++ }
  END { if (rows != expected) exit 4 }
' "${results_work}"
[[ ${stream_connections} == "${expected_trials}" && ${stream_reconnects} == 0 ]]
[[ ${pre_restart_progress_checks} == "${expected_trials}" &&
   ${replacement_active_checkpoints} == "${expected_trials}" &&
   ${post_restart_progress_checks} == "${expected_trials}" ]]
(( full_duplex_records >= expected_trials * 2 ))
(( stream_bytes_a_to_b == full_duplex_records * STREAM_RECORD_BYTES ))
(( stream_bytes_b_to_a == full_duplex_records * STREAM_RECORD_BYTES ))
(( max_recovery_ms <= STREAM_PROGRESS_TIMEOUT_MS ))
(( stream_survival_checks >= expected_trials * 3 ))
stream_transcript_sha256=$(sha256sum -- "${transcript_source}" | awk '{print $1}') || exit 1
[[ ${stream_transcript_sha256} =~ ^[a-f0-9]{64}$ ]]
chmod 0600 -- "${results_work}"
mv -T -- "${results_work}" "${RESULTS}"
results_work=
printf 'PASS trials=%s max_recovery_ms=%s kill_switch=pass tcp_connections=%s tcp_reconnects=0 full_duplex_records=%s stream_bytes_a_to_b=%s stream_bytes_b_to_a=%s pre_restart_progress_checks=%s replacement_active_checkpoints=%s post_restart_progress_checks=%s stream_survival_checks=%s max_progress_gap_a_to_b_ms=%s max_progress_gap_b_to_a_ms=%s stream_digest_directions=%s stream_transcript_sha256=%s\n' \
  "${expected_trials}" "${max_recovery_ms}" "${stream_connections}" \
  "${full_duplex_records}" "${stream_bytes_a_to_b}" "${stream_bytes_b_to_a}" \
  "${pre_restart_progress_checks}" "${replacement_active_checkpoints}" \
  "${post_restart_progress_checks}" "${stream_survival_checks}" \
  "${max_progress_gap_a_to_b_ms}" \
  "${max_progress_gap_b_to_a_ms}" "$((expected_trials * 2))" \
  "${stream_transcript_sha256}"
