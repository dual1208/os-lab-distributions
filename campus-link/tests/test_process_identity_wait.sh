#!/usr/bin/env bash
# Executable regressions for PID-reuse-safe wait guards.

set -euo pipefail
umask 077
export LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DRIVER=${ROOT}/scripts/relay-restart-driver.sh
TRANSPORT=${ROOT}/scripts/relay-restart-transport.sh
FAULT=${ROOT}/scripts/fault-in-stream.sh
SOAK=${ROOT}/scripts/soak-a11-b22.sh
readonly ROOT DRIVER TRANSPORT FAULT SOAK

tmp=$(mktemp -d "${TMPDIR:-/tmp}/campus-link-identity-wait.XXXXXX")
cleanup() {
  rm -rf -- "${tmp}"
}
trap cleanup EXIT

extract_function() {
  local name=$1 source=$2
  awk -v signature="${name}() {" '
    $0 == signature { inside = 1 }
    inside { print }
    inside && $0 == "}" { exit }
  ' "${source}"
}

driver_wait=$(extract_function wait_child_until "${DRIVER}")
transport_wait=$(extract_function wait_child_until "${TRANSPORT}")
fault_wait=$(extract_function wait_relay_restart_until "${FAULT}")
soak_cleanup=$(extract_function cleanup_tracked_children "${SOAK}")
soak_start_ticks=$(extract_function process_start_ticks "${SOAK}")
soak_shell_uint=$(extract_function is_shell_uint "${SOAK}")
soak_inspect=$(extract_function inspect_process_identity "${SOAK}")
soak_track=$(extract_function track_child "${SOAK}")
soak_launch=$(extract_function launch_tracked_child "${SOAK}")
readonly driver_wait transport_wait fault_wait soak_cleanup soak_start_ticks soak_shell_uint
readonly soak_inspect soak_track soak_launch

classification_case() {
  local source helper
  for source in "${DRIVER}" "${TRANSPORT}" "${FAULT}" "${SOAK}"; do
    helper=$(extract_function inspect_process_identity "${source}")
    [[ ${helper} == *'outcome=identity-mismatch'* ]]
    [[ ${helper} == *'if [[ ! -e ${path} ]]; then'*'outcome=gone'* ]]
  done
  helper=$(extract_function inspect_session_member_identity "${TRANSPORT}")
  [[ ${helper} == *'outcome=identity-mismatch'* ]]
}

driver_mismatch_never_waits() (
  eval "${driver_wait}"
  local marker=${tmp}/driver.waited result=unchanged status=0
  campus_link_monotonic_ms() { printf '100\n'; }
  sleep_bounded() { return 99; }
  inspect_process_identity() { printf -v "$3" '%s' identity-mismatch; }
  wait() { : > "${marker}"; return 0; }
  wait_child_until 101 202 200 result || status=$?
  [[ ${status} -eq 125 && ${result} == unchanged && ! -e ${marker} ]]
)

transport_mismatch_never_waits() (
  eval "${transport_wait}"
  local marker=${tmp}/transport.waited result=unchanged status=0
  monotonic_ms() { printf '100\n'; }
  inspect_process_identity() { printf -v "$3" '%s' identity-mismatch; }
  wait() { : > "${marker}"; return 0; }
  wait_child_until 101 202 200 result || status=$?
  [[ ${status} -eq 125 && ${result} == unchanged && ! -e ${marker} ]]
)

fault_mismatch_never_waits() (
  eval "${fault_wait}"
  local marker=${tmp}/fault.waited result=unchanged status=0
  relay_restart_pid=101
  relay_restart_start_ticks=202
  campus_link_monotonic_ms() { printf '100\n'; }
  inspect_process_identity() { printf -v "$3" '%s' identity-mismatch; }
  wait() { : > "${marker}"; return 0; }
  wait_relay_restart_until 200 result || status=$?
  [[ ${status} -eq 125 && ${result} == unchanged && ! -e ${marker} ]]
)

soak_cleanup_escalates_and_reaps_exact_child() (
  eval "${soak_cleanup}"
  local clock_file=${tmp}/soak.clock signals=${tmp}/soak.signals
  local waited=${tmp}/soak.waited mock_state=live
  local -a pids=(101) pid_start_ticks=(202)
  printf '50\n' > "${clock_file}"
  campus_link_monotonic_ms() {
    local now
    IFS= read -r now < "${clock_file}"
    printf '%s\n' "$((now + 50))" > "${clock_file}"
    printf '%s\n' "${now}"
  }
  inspect_process_identity() { printf -v "$3" '%s' "${mock_state}"; }
  signal_tracked_child() {
    printf '%s\n' "$3" >> "${signals}"
    if [[ $3 == KILL ]]; then
      mock_state=zombie
    fi
  }
  wait() { : > "${waited}"; return 0; }
  sleep() { return 0; }
  cleanup_tracked_children 500 100
  [[ $(<"${signals}") == $'TERM\nKILL' ]]
  [[ -e ${waited} && -z ${pids[0]:-} && -z ${pid_start_ticks[0]:-} ]]
)

soak_cleanup_mismatch_never_signals_or_waits() (
  eval "${soak_cleanup}"
  local signal_marker=${tmp}/soak.mismatch.signal
  local wait_marker=${tmp}/soak.mismatch.waited status=0
  local -a pids=(101) pid_start_ticks=(202)
  campus_link_monotonic_ms() { printf '50\n'; }
  inspect_process_identity() { printf -v "$3" '%s' identity-mismatch; }
  signal_tracked_child() { : > "${signal_marker}"; return 0; }
  wait() { : > "${wait_marker}"; return 0; }
  sleep() { return 0; }
  cleanup_tracked_children 500 100 || status=$?
  [[ ${status} -ne 0 && ! -e ${signal_marker} && ! -e ${wait_marker} ]]
  [[ ${pids[0]} == 101 && ${pid_start_ticks[0]} == 202 ]]
)

soak_launch_handshake_enrolls_blocked_exact_child() (
  eval "${soak_start_ticks}"
  eval "${soak_inspect}"
  eval "${soak_track}"
  eval "${soak_launch}"
  local evidence_dir=${tmp}/soak-launch-success child_pid child_ticks state
  local CHILD_HANDSHAKE_TIMEOUT_SECONDS=2
  local -a pids=() pid_start_ticks=()
  mkdir -m 0700 -- "${evidence_dir}"
  stat() { printf '0:0:600:1\n0:0:600:1\n'; }
  launch_tracked_child child_pid child_ticks client \
    "${evidence_dir}/client.log" bash -c 'sleep 0.2'
  [[ ${child_pid} =~ ^[1-9][0-9]*$ && ${child_ticks} =~ ^[1-9][0-9]*$ ]]
  [[ ${pids[0]} == "${child_pid}" && ${pid_start_ticks[0]} == "${child_ticks}" ]]
  inspect_process_identity "${child_pid}" "${child_ticks}" state
  [[ ${state} == live || ${state} == zombie || ${state} == gone ]]
  wait "${child_pid}"
  [[ ! -e ${evidence_dir}/client.ready && ! -e ${evidence_dir}/client.ack ]]
)

soak_launch_missing_readiness_never_enrolls_pid() (
  eval "${soak_launch}"
  local evidence_dir=${tmp}/soak-launch-missing status=0
  local CHILD_HANDSHAKE_TIMEOUT_SECONDS=0.1 enrolled=${tmp}/soak.enrolled
  mkdir -m 0700 -- "${evidence_dir}"
  stat() { printf '0:0:600:1\n0:0:600:1\n'; }
  process_start_ticks() { return 1; }
  track_child() { : > "${enrolled}"; return 0; }
  launch_tracked_child ignored_pid ignored_ticks client \
    "${evidence_dir}/client.log" bash -c 'exit 0' || status=$?
  [[ ${status} -ne 0 && ! -e ${enrolled} ]]
  [[ ! -e ${evidence_dir}/client.ready && ! -e ${evidence_dir}/client.ack ]]
)

soak_shell_uint_is_canonical_and_signed_64_bounded() (
  eval "${soak_shell_uint}"
  is_shell_uint 0
  is_shell_uint 9223372036854775807
  ! is_shell_uint 9223372036854775808
  ! is_shell_uint 01
  ! is_shell_uint +1
)

tests=0
expect_success() {
  local label=$1
  shift
  tests=$((tests + 1))
  if "$@"; then
    printf 'ok %d - %s\n' "${tests}" "${label}"
  else
    printf 'not ok %d - %s\n' "${tests}" "${label}" >&2
    exit 1
  fi
}

printf '1..9\n'
expect_success 'start-tick reuse is distinct from an absent proc path' \
  classification_case
expect_success 'driver identity mismatch never reaches wait' \
  driver_mismatch_never_waits
expect_success 'transport identity mismatch never reaches wait' \
  transport_mismatch_never_waits
expect_success 'fault supervisor identity mismatch never reaches wait' \
  fault_mismatch_never_waits
expect_success 'soak cleanup escalates and reaps only the exact tracked child' \
  soak_cleanup_escalates_and_reaps_exact_child
expect_success 'soak cleanup identity mismatch never signals or waits' \
  soak_cleanup_mismatch_never_signals_or_waits
expect_success 'soak launch enrolls only a blocked self-reported exact child' \
  soak_launch_handshake_enrolls_blocked_exact_child
expect_success 'soak launch missing readiness never enrolls a PID' \
  soak_launch_missing_readiness_never_enrolls_pid
expect_success 'soak numeric evidence is canonical and signed-64 bounded' \
  soak_shell_uint_is_canonical_and_signed_64_bounded
