#!/bin/bash -p
set -euo pipefail
umask 077

[[ $- == *p* ]]
[[ -z ${BASH_ENV+x} && -z ${ENV+x} ]]
[[ -z ${LD_PRELOAD+x} && -z ${LD_LIBRARY_PATH+x} && -z ${LD_AUDIT+x} ]]
[[ -z ${OPENSSL_CONF+x} && -z ${OPENSSL_MODULES+x} && -z ${OPENSSL_ENGINES+x} ]]

sanitize_environment() {
  local name producer_pid producer_status=0 consumer_status=0
  local -a names=()
  mapfile -t names < <(compgen -e) || consumer_status=$?
  producer_pid=$!
  wait "${producer_pid}" || producer_status=$?
  (( consumer_status == 0 && producer_status == 0 )) || return 1
  for name in "${names[@]}"; do
    case ${name} in
      BASHOPTS|BASHPID|EUID|PPID|SHELLOPTS|UID) ;;
      *) unset "${name}" ;;
    esac
  done
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  LC_ALL=C
  HOME=/nonexistent
  IFS=$' \t\n'
  readonly PATH LC_ALL HOME IFS
  export PATH LC_ALL HOME
}
sanitize_environment
ulimit -S -c 0
ulimit -H -c 0

readonly UNIT=campus-link-relay.service
readonly HOLD_MILLISECONDS=15000
readonly COMMIT_STABILITY_MILLISECONDS=5000
readonly MAX_USED_RUNS=4096
readonly COOLDOWN_MILLISECONDS=300000
readonly OPEN_TIMEOUT_MILLISECONDS=10000
readonly RELEASE_TIMEOUT_MILLISECONDS=40000
readonly COMMIT_TIMEOUT_MILLISECONDS=75000
readonly TRANSACTION_TIMEOUT_MILLISECONDS=180000
readonly MAX_RESTART_DURATION_MILLISECONDS=120000
readonly RECOVERY_DELAY_SECONDS=225
readonly RECOVERY_ACTION_TIMEOUT_SECONDS=30
readonly ACTUATOR_CLEANUP_TIMEOUT_MILLISECONDS=25000
readonly RECOVERY_CANCEL_TIMEOUT_MILLISECONDS=5000
readonly QUERY_TIMEOUT_MILLISECONDS=2000
readonly MUTATION_TIMEOUT_MILLISECONDS=18000
readonly SOCKET_QUERY_TIMEOUT_MILLISECONDS=1000
readonly COMMAND_KILL_GRACE_MILLISECONDS=1000
readonly QUERY_KILL_GRACE_MILLISECONDS=500
readonly SOCKET_KILL_GRACE_MILLISECONDS=250
readonly MONITOR_CANCEL_GRACE_MILLISECONDS=1000
readonly RANDOM_TIMEOUT_MILLISECONDS=2000
readonly CRYPTO_TIMEOUT_MILLISECONDS=4000
readonly RESTART_REMOTE_OPERATION_BUDGET_MILLISECONDS=101150
(( 2 * MUTATION_TIMEOUT_MILLISECONDS + 6 * QUERY_TIMEOUT_MILLISECONDS + \
  6 * SOCKET_QUERY_TIMEOUT_MILLISECONDS + RELEASE_TIMEOUT_MILLISECONDS + \
  MONITOR_CANCEL_GRACE_MILLISECONDS + RANDOM_TIMEOUT_MILLISECONDS + \
  CRYPTO_TIMEOUT_MILLISECONDS + 150 == \
  RESTART_REMOTE_OPERATION_BUDGET_MILLISECONDS ))
(( RELEASE_TIMEOUT_MILLISECONDS > HOLD_MILLISECONDS ))
(( RESTART_REMOTE_OPERATION_BUDGET_MILLISECONDS < \
  MAX_RESTART_DURATION_MILLISECONDS ))
readonly RUNTIME_DIR=/run/campus-link-relay-fault
readonly STATE_DIR=/var/lib/campus-link-relay-fault
readonly USED_DIR=${STATE_DIR}/used
readonly EXPECTED_PERMIT=${STATE_DIR}/expected-run.env
readonly START_INHIBIT=${RUNTIME_DIR}/inhibit-start
readonly RECOVERY_BASE=campus-link-relay-fault-recovery
readonly UNIT_FRAGMENT=/etc/systemd/system/campus-link-relay.service
readonly RELEASE_MANIFEST=/var/lib/campus-link/installed-release-manifest.sha256
readonly DEPLOYMENT_ATTESTATION=/var/lib/campus-link/deployment-attestation.env
readonly ACTUATOR=/usr/local/libexec/campus-link-relay-restart-actuator
readonly AUTHORIZED_COMMAND=/usr/local/libexec/campus-link-relay-restart-authorized
readonly PERMIT_AUTHORIZER=/usr/local/libexec/campus-link-relay-restart-permit-authorize
readonly PERMIT_PUBLIC_KEY=/etc/ssh/campus-link-relay-fault-permit-ed25519.pub.pem
readonly OPEN_FRAME_BYTES=103
readonly RELEASE_FRAME_BYTES=195
readonly COMMIT_FRAME_BYTES=194

[[ ${EUID} -eq 0 ]]
[[ $# -eq 0 ]]
[[ ${BASH_SOURCE[0]} == "${ACTUATOR}" ]]
[[ ! -t 0 && ! -t 1 && ! -t 2 ]]

monotonic_ms() {
  local uptime whole fraction
  read -r uptime _ < /proc/uptime || return 1
  [[ ${uptime} =~ ^([0-9]+)\.([0-9]+)$ ]] || return 1
  whole=${BASH_REMATCH[1]}
  fraction=${BASH_REMATCH[2]}000
  fraction=${fraction:0:3}
  printf '%s\n' "$((10#${whole} * 1000 + 10#${fraction}))"
}

require_root_dir() {
  local path=$1 mode=$2 metadata
  [[ -d ${path} && ! -L ${path} ]] || return 1
  metadata=$(stat -c '%u:%g:%a' -- "${path}") || return 1
  [[ ${metadata} == "0:0:${mode}" ]] || return 1
  return 0
}

require_root_file() {
  local path=$1 mode=$2 metadata
  [[ -f ${path} && ! -L ${path} ]] || return 1
  metadata=$(stat -c '%u:%g:%a:%h' -- "${path}") || return 1
  [[ ${metadata} == "0:0:${mode}:1" ]] || \
    return 1
  return 0
}

validate_used_ledger() {
  local path name find_pid
  local -a paths=()
  mapfile -d '' -t paths < <(find "${USED_DIR}" -mindepth 1 -maxdepth 1 -print0)
  find_pid=$!
  wait "${find_pid}" || return 1
  for path in "${paths[@]}"; do
    name=$(basename -- "${path}") || return 1
    [[ ${name} =~ ^[a-f0-9]{32}$ ]] || return 1
    require_root_file "${path}" 600 || return 1
  done
  printf '%s\n' "${#paths[@]}" || return 1
  return 0
}

run_bounded() {
  local deadline_ms=$1 total_cap_ms=$2 grace_ms=$3
  local now_ms remaining_ms total_ms command_ms duration grace_duration
  shift 3
  now_ms=$(monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 1
  remaining_ms=$((deadline_ms - now_ms))
  total_ms=${remaining_ms}
  (( total_ms <= total_cap_ms )) || total_ms=${total_cap_ms}
  (( total_ms > grace_ms )) || return 1
  command_ms=$((total_ms - grace_ms))
  printf -v duration '%d.%03ds' $((command_ms / 1000)) $((command_ms % 1000))
  printf -v grace_duration '%d.%03ds' $((grace_ms / 1000)) $((grace_ms % 1000))
  timeout --signal=TERM --kill-after="${grace_duration}" "${duration}" "$@"
}

sleep_bounded() {
  local requested_ms=$1 deadline_ms=$2 now_ms remaining_ms sleep_ms duration
  now_ms=$(monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 1
  remaining_ms=$((deadline_ms - now_ms))
  sleep_ms=${requested_ms}
  (( sleep_ms <= remaining_ms )) || sleep_ms=${remaining_ms}
  (( sleep_ms > 0 )) || return 1
  printf -v duration '%d.%03ds' $((sleep_ms / 1000)) $((sleep_ms % 1000))
  sleep "${duration}"
}

systemctl_query() {
  [[ ${operation_deadline_ms:-} =~ ^[1-9][0-9]*$ ]] || return 1
  run_bounded "${operation_deadline_ms}" "${QUERY_TIMEOUT_MILLISECONDS}" \
    "${QUERY_KILL_GRACE_MILLISECONDS}" systemctl "$@"
}

systemctl_mutate() {
  [[ ${operation_deadline_ms:-} =~ ^[1-9][0-9]*$ ]] || return 1
  run_bounded "${operation_deadline_ms}" "${MUTATION_TIMEOUT_MILLISECONDS}" \
    "${COMMAND_KILL_GRACE_MILLISECONDS}" systemctl "$@"
}

assert_no_relay_listeners() {
  local tcp_listeners udp_listeners
  [[ ${operation_deadline_ms:-} =~ ^[1-9][0-9]*$ ]] || return 1
  tcp_listeners=$(run_bounded "${operation_deadline_ms}" \
    "${SOCKET_QUERY_TIMEOUT_MILLISECONDS}" "${SOCKET_KILL_GRACE_MILLISECONDS}" \
    ss -H -ltn '( sport = :443 )') || return 1
  udp_listeners=$(run_bounded "${operation_deadline_ms}" \
    "${SOCKET_QUERY_TIMEOUT_MILLISECONDS}" "${SOCKET_KILL_GRACE_MILLISECONDS}" \
    ss -H -lun '( sport = :443 )') || return 1
  [[ -z ${tcp_listeners} && -z ${udp_listeners} ]] || return 1
  return 0
}

read_unit_restarts() {
  local value
  value=$(systemctl_query show -p NRestarts --value "${UNIT}") || return 1
  [[ ${value} =~ ^(0|[1-9][0-9]{0,15})$ ]] || return 1
  printf '%s\n' "${value}"
}

read_exact_frame() {
  local destination=$1 expected_bytes=$2 deadline_ms=$3 now_ms remaining_ms status actual_bytes
  now_ms=$(monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 1
  remaining_ms=$((deadline_ms - now_ms))
  if run_bounded "${deadline_ms}" "${remaining_ms}" \
    "${COMMAND_KILL_GRACE_MILLISECONDS}" \
    dd iflag=fullblock bs="${expected_bytes}" count=1 status=none \
    > "${destination}"; then
    status=0
  else
    status=$?
  fi
  (( status == 0 )) || return 1
  actual_bytes=$(stat -c '%s' -- "${destination}") || return 1
  [[ ${actual_bytes} -eq ${expected_bytes} ]] || return 1
}

assert_no_buffered_input() {
  local probe=$1 deadline_ms=$2 status
  : > "${probe}"
  if run_bounded "${deadline_ms}" 150 100 \
    dd bs=1 count=1 status=none > "${probe}"; then
    status=0
  else
    status=$?
  fi
  # timeout(1) returning 124 with an empty retained file proves the channel is
  # still open and no byte from a future phase was prequeued.
  (( status == 124 )) || return 1
  [[ ! -s ${probe} ]] || return 1
}

assert_exact_eof() {
  local probe=$1 deadline_ms=$2 status
  : > "${probe}"
  if run_bounded "${deadline_ms}" 6000 1000 \
    dd bs=1 count=1 status=none > "${probe}"; then
    status=0
  else
    status=$?
  fi
  # dd returns zero with an empty file only for EOF.  A retained byte is
  # trailing data; timeout means the client failed to close its write half.
  (( status == 0 )) || return 1
  [[ ! -s ${probe} ]] || return 1
}

random_hex_256() {
  local value
  [[ ${operation_deadline_ms:-} =~ ^[1-9][0-9]*$ ]] || return 1
  value=$(run_bounded "${operation_deadline_ms}" \
    "${RANDOM_TIMEOUT_MILLISECONDS}" "${COMMAND_KILL_GRACE_MILLISECONDS}" \
    openssl rand -hex 32) || return 1
  [[ ${value} =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s\n' "${value}"
}

assert_manifest_bound_start_inhibit() {
  local fragment reload_state manifest_digest unit_digest expected_digest dropins
  local manifest_size grep_status grep_pid consumer_status=0 producer_status=0
  local inhibit_count condition_count load_state
  local -a matches=()
  require_root_file "${UNIT_FRAGMENT}" 644 || return 1
  require_root_file "${RELEASE_MANIFEST}" 600 || return 1
  manifest_size=$(stat -c '%s' -- "${RELEASE_MANIFEST}") || return 1
  [[ ${manifest_size} =~ ^[0-9]+$ ]] || return 1
  (( manifest_size > 0 && manifest_size <= 65536 )) || return 1
  if grep -aEvq '^[a-f0-9]{64}  [A-Za-z0-9._/-]+$' \
    "${RELEASE_MANIFEST}"; then
    return 1
  else
    grep_status=$?
    (( grep_status == 1 )) || return 1
  fi
  manifest_digest=$(sha256sum -- "${RELEASE_MANIFEST}" | awk '{print $1}') || \
    return 1
  [[ ${manifest_digest} == "${run_manifest_sha256}" ]] || return 1
  mapfile -t matches < <(grep -F '  systemd/campus-link-relay.service' \
    "${RELEASE_MANIFEST}") || consumer_status=$?
  grep_pid=$!
  wait "${grep_pid}" || producer_status=$?
  (( consumer_status == 0 && producer_status == 0 )) || return 1
  [[ ${#matches[@]} -eq 1 && \
    ${matches[0]#*  } == systemd/campus-link-relay.service ]] || return 1
  expected_digest=${matches[0]%% *}
  [[ ${expected_digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  unit_digest=$(sha256sum -- "${UNIT_FRAGMENT}" | awk '{print $1}') || return 1
  [[ ${unit_digest} == "${expected_digest}" ]] || return 1
  inhibit_count=$(grep -aFxc "ConditionPathExists=!${START_INHIBIT}" \
    "${UNIT_FRAGMENT}") || return 1
  condition_count=$(grep -aEc '^[[:space:]]*Condition[A-Za-z0-9]+[[:space:]]*=' \
    "${UNIT_FRAGMENT}") || return 1
  [[ ${inhibit_count} -eq 1 && ${condition_count} -eq 1 ]] || return 1
  fragment=$(systemctl_query show -p FragmentPath --value "${UNIT}") || return 1
  [[ ${fragment} == "${UNIT_FRAGMENT}" ]] || return 1
  reload_state=$(systemctl_query show -p NeedDaemonReload --value "${UNIT}") || \
    return 1
  [[ ${reload_state} == no ]] || return 1
  load_state=$(systemctl_query show -p LoadState --value "${UNIT}") || return 1
  [[ ${load_state} == loaded ]] || return 1
  dropins=$(systemctl_query show -p DropInPaths --value "${UNIT}") || return 1
  [[ -z ${dropins} ]] || return 1
  return 0
}

assert_no_recovery_units() {
  local suffix load_state
  for suffix in timer service; do
    load_state=$(systemctl_query show -p LoadState --value \
      "${RECOVERY_BASE}.${suffix}") || return 1
    [[ ${load_state} == not-found ]] || return 1
  done
  return 0
}

assert_start_inhibit() {
  local digest
  [[ ${inhibit_sha256:-} =~ ^[a-f0-9]{64}$ ]] || return 1
  require_root_file "${START_INHIBIT}" 600 || return 1
  digest=$(sha256sum -- "${START_INHIBIT}" | awk '{print $1}') || return 1
  [[ ${digest} == "${inhibit_sha256}" ]] || return 1
  return 0
}

remove_start_inhibit() {
  if [[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]]; then
    start_inhibited=0
    return 0
  fi
  assert_start_inhibit || return 1
  rm -f -- "${START_INHIBIT}" || return 1
  [[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]] || return 1
  start_inhibited=0
  return 0
}

for executable in "${ACTUATOR}" "${AUTHORIZED_COMMAND}" "${PERMIT_AUTHORIZER}"; do
  require_root_file "${executable}" 755
done
require_root_file "${PERMIT_PUBLIC_KEY}" 600
require_root_file "${DEPLOYMENT_ATTESTATION}" 600
require_root_file "${RELEASE_MANIFEST}" 600
permit_key_type=$(openssl pkey -pubin -in "${PERMIT_PUBLIC_KEY}" \
  -text_pub -noout 2>/dev/null | sed -n '1p') || exit 1
[[ ${permit_key_type} == 'ED25519 Public-Key:' ]]
actuator_digest=$(sha256sum -- "${ACTUATOR}" | awk '{print $1}') || exit 1
authorized_command_digest=$(sha256sum -- "${AUTHORIZED_COMMAND}" | awk '{print $1}') || exit 1
permit_authorizer_digest=$(sha256sum -- "${PERMIT_AUTHORIZER}" | awk '{print $1}') || exit 1
local_permit_key_sha256=$(sha256sum -- "${PERMIT_PUBLIC_KEY}" | awk '{print $1}') || exit 1
local_deployment_sha256=$(sha256sum -- "${DEPLOYMENT_ATTESTATION}" | awk '{print $1}') || exit 1
for digest in "${actuator_digest}" "${authorized_command_digest}" \
  "${permit_authorizer_digest}" "${local_permit_key_sha256}" \
  "${local_deployment_sha256}"; do
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]]
done

for directory in "${RUNTIME_DIR}" "${STATE_DIR}" "${USED_DIR}"; do
  [[ ! -L ${directory} ]]
done
install -d -m 0700 -o root -g root "${RUNTIME_DIR}" "${STATE_DIR}" "${USED_DIR}"
require_root_dir "${RUNTIME_DIR}" 700
require_root_dir "${STATE_DIR}" 700
require_root_dir "${USED_DIR}" 700

open_frame=$(mktemp "${RUNTIME_DIR}/.open-frame.XXXXXX")
canonical_frame=$(mktemp "${RUNTIME_DIR}/.canonical-frame.XXXXXX")
input_probe=$(mktemp "${RUNTIME_DIR}/.input-probe.XXXXXX")
phase_frame=$(mktemp "${RUNTIME_DIR}/.phase-frame.XXXXXX")
phase_payload=$(mktemp "${RUNTIME_DIR}/.phase-payload.XXXXXX")
signature_text=$(mktemp "${RUNTIME_DIR}/.phase-signature-text.XXXXXX")
signature=$(mktemp "${RUNTIME_DIR}/.phase-signature.XXXXXX")
signature_canonical=$(mktemp "${RUNTIME_DIR}/.phase-signature-canonical.XXXXXX")
cooldown_source=$(mktemp "${RUNTIME_DIR}/.cooldown.XXXXXX")
inhibit_source=$(mktemp "${RUNTIME_DIR}/.inhibit.XXXXXX")
monitor_failure=$(mktemp "${RUNTIME_DIR}/.monitor-failure.XXXXXX")
monitor_pid=
recovery_armed=0
relay_stop_requested=0
start_inhibited=0
inhibit_sha256=
operation_deadline_ms=

cancel_monitor() {
  local watchdog_pid
  if [[ -n ${monitor_pid:-} ]]; then
    kill "${monitor_pid}" 2>/dev/null || true
    sleep 1 &
    watchdog_pid=$!
    # Reap whichever child finishes first. If the monitor did not terminate
    # after TERM, bound cancellation with KILL before reaping both children.
    if wait -n "${monitor_pid}" "${watchdog_pid}" 2>/dev/null; then
      :
    else
      :
    fi
    if kill -0 "${monitor_pid}" 2>/dev/null; then
      kill -KILL "${monitor_pid}" 2>/dev/null || true
    fi
    kill "${watchdog_pid}" 2>/dev/null || true
    wait "${monitor_pid}" 2>/dev/null || true
    wait "${watchdog_pid}" 2>/dev/null || true
    monitor_pid=
  fi
  return 0
}

cancel_recovery() {
  local suffix load_state active_state recovery_present=0
  (( recovery_armed != 0 )) || return 0
  for suffix in timer service; do
    load_state=$(systemctl_query show -p LoadState --value \
      "${RECOVERY_BASE}.${suffix}") || return 1
    [[ ${load_state} == not-found ]] || recovery_present=1
  done
  if (( recovery_present == 0 )); then
    return 0
  fi
  run_bounded "${operation_deadline_ms}" \
    "${RECOVERY_CANCEL_TIMEOUT_MILLISECONDS}" \
    "${COMMAND_KILL_GRACE_MILLISECONDS}" systemctl stop \
    "${RECOVERY_BASE}.timer" "${RECOVERY_BASE}.service" >/dev/null 2>&1 || true
  for suffix in timer service; do
    load_state=$(systemctl_query show -p LoadState --value \
      "${RECOVERY_BASE}.${suffix}") || return 1
    active_state=$(systemctl_query show -p ActiveState --value \
      "${RECOVERY_BASE}.${suffix}") || return 1
    if [[ ${load_state} == not-found ]]; then
      [[ -z ${active_state} || ${active_state} == inactive ]] || return 1
    else
      [[ ${active_state} == inactive ]] || return 1
    fi
  done
  return 0
}

cleanup_files() {
  rm -f -- "${open_frame:-}" "${canonical_frame:-}" "${input_probe:-}" \
    "${phase_frame:-}" "${phase_payload:-}" "${signature_text:-}" \
    "${signature:-}" "${signature_canonical:-}" "${cooldown_source:-}" \
    "${inhibit_source:-}" "${monitor_failure:-}"
}

restore_relay() {
  local status=$? restored=0 cleanup_clock_ms
  trap - EXIT HUP INT TERM
  if cleanup_clock_ms=$(monotonic_ms); then
    operation_deadline_ms=$((cleanup_clock_ms + ACTUATOR_CLEANUP_TIMEOUT_MILLISECONDS))
  else
    operation_deadline_ms=1
    status=1
  fi
  cancel_monitor
  if (( start_inhibited == 0 )) && [[ -n ${inhibit_sha256:-} ]] && \
    [[ -e ${START_INHIBIT} || -L ${START_INHIBIT} ]] && \
    assert_start_inhibit; then
    start_inhibited=1
  fi
  if (( relay_stop_requested != 0 || start_inhibited != 0 )); then
    if remove_start_inhibit && \
      systemctl_mutate start "${UNIT}" >/dev/null 2>&1 && \
      systemctl_query is-active --quiet "${UNIT}"; then
      restored=1
    else
      echo 'Relay restart recovery could not verify an active relay; delayed recovery remains armed.' >&2
    fi
  else
    restored=1
  fi
  if (( restored != 0 )); then
    if ! cancel_recovery; then
      echo 'Relay is active but the redundant delayed recovery action could not be disarmed.' >&2
      (( status != 0 )) || status=1
    fi
  fi
  cleanup_files
  exit "${status}"
}
trap restore_relay EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Read and validate the secret-bearing open frame before taking the shared
# mutation lock.  An idle holder of only the transport key therefore cannot
# starve deployment or a valid signed transaction.
open_started_ms=$(monotonic_ms) || exit 1
open_deadline_ms=$((open_started_ms + OPEN_TIMEOUT_MILLISECONDS))
read_exact_frame "${open_frame}" "${OPEN_FRAME_BYTES}" "${open_deadline_ms}"
grep -aEq '^open [a-f0-9]{32} [a-f0-9]{64}$' "${open_frame}"
open_frame_lines=$(wc -l < "${open_frame}") || exit 1
[[ ${open_frame_lines} -eq 1 ]]
read -r open_action run_id session_secret < "${open_frame}"
[[ ${open_action} == open && ${run_id} =~ ^[a-f0-9]{32}$ && \
  ${session_secret} =~ ^[a-f0-9]{64}$ ]]
printf 'open %s %s\n' "${run_id}" "${session_secret}" > "${canonical_frame}"
cmp -s -- "${open_frame}" "${canonical_frame}"
session_sha256=$(printf '%s' "${session_secret}" | sha256sum | awk '{print $1}') || exit 1
[[ ${session_sha256} =~ ^[a-f0-9]{64}$ ]]
assert_no_buffered_input "${input_probe}" "${open_deadline_ms}"

exec 9<>"${RUNTIME_DIR}/actuator.lock"
flock -n 9
lock_metadata=$(stat -c '%u:%g:%a:%h' -- "${RUNTIME_DIR}/actuator.lock") || exit 1
[[ ${lock_metadata} == 0:0:600:1 ]]
readonly used_marker=${USED_DIR}/${run_id}
[[ ! -e ${used_marker} && ! -L ${used_marker} ]]
require_root_file "${EXPECTED_PERMIT}" 600
mapfile -t permit_lines < "${EXPECTED_PERMIT}" || exit 1
[[ ${#permit_lines[@]} -eq 13 ]]
[[ ${permit_lines[0]} == FORMAT=1 ]]
[[ ${permit_lines[1]} == STATUS=expected ]]
[[ ${permit_lines[2]} == ACTION=relay-restart ]]
[[ ${permit_lines[3]} == "RUN_ID=${run_id}" ]]
[[ ${permit_lines[4]} =~ ^CANDIDATE_SHA256=([a-f0-9]{64})$ ]]
candidate_sha256=${BASH_REMATCH[1]}
[[ ${permit_lines[5]} =~ ^RUN_MANIFEST_SHA256=([a-f0-9]{64})$ ]]
run_manifest_sha256=${BASH_REMATCH[1]}
[[ ${permit_lines[6]} == "DEPLOYMENT_ATTESTATION_SHA256=${local_deployment_sha256}" ]]
[[ ${permit_lines[7]} == "PERMIT_KEY_SHA256=${local_permit_key_sha256}" ]]
[[ ${permit_lines[8]} == "SESSION_SHA256=${session_sha256}" ]]
[[ ${permit_lines[9]} =~ ^ISSUED_UNIX=([1-9][0-9]{9,10})$ ]]
permit_issued_unix=${BASH_REMATCH[1]}
[[ ${permit_lines[10]} =~ ^NOT_AFTER_UNIX=([1-9][0-9]{9,10})$ ]]
permit_not_after_unix=${BASH_REMATCH[1]}
[[ ${permit_lines[11]} =~ ^PERMIT_SHA256=[a-f0-9]{64}$ ]]
[[ ${permit_lines[12]} == "PERMIT_AUTHORIZER_SHA256=${permit_authorizer_digest}" ]]
now_unix=$(date +%s) || exit 1
[[ ${now_unix} =~ ^[1-9][0-9]{9,10}$ ]]
(( permit_not_after_unix - permit_issued_unix == 600 ))
(( permit_issued_unix <= now_unix + 30 && now_unix <= permit_not_after_unix ))
used_count=$(validate_used_ledger) || exit 1
(( used_count < MAX_USED_RUNS ))

started_ms=$(monotonic_ms) || exit 1
transaction_deadline_ms=$((started_ms + TRANSACTION_TIMEOUT_MILLISECONDS))
operation_deadline_ms=${transaction_deadline_ms}
readonly cooldown_marker=${RUNTIME_DIR}/last-monotonic-ms
if [[ -e ${cooldown_marker} || -L ${cooldown_marker} ]]; then
  require_root_file "${cooldown_marker}" 600
  read -r prior_ms < "${cooldown_marker}"
  [[ ${prior_ms} =~ ^(0|[1-9][0-9]{0,15})$ ]]
  (( started_ms >= prior_ms && started_ms - prior_ms >= COOLDOWN_MILLISECONDS ))
fi

systemctl_query is-active --quiet "${UNIT}"
assert_manifest_bound_start_inhibit
[[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]]
assert_no_recovery_units
before_invocation=$(systemctl_query show -p InvocationID --value "${UNIT}") || exit 1
[[ ${before_invocation} =~ ^[a-f0-9]{32}$ ]]
before_digest=$(printf '%s' "${before_invocation}" | sha256sum | awk '{print $1}') || exit 1
[[ ${before_digest} =~ ^[a-f0-9]{64}$ ]]

# Consume and flush the one-time authority before arming any destructive phase.
mv -T -- "${EXPECTED_PERMIT}" "${used_marker}"
sync -f -- "${STATE_DIR}"
printf '%s\n' "${started_ms}" > "${cooldown_source}"
install -m 0600 -o root -g root "${cooldown_source}" "${cooldown_marker}"
unset session_secret

recovery_armed=1
run_bounded "${transaction_deadline_ms}" "${MUTATION_TIMEOUT_MILLISECONDS}" \
  "${COMMAND_KILL_GRACE_MILLISECONDS}" systemd-run --quiet --collect \
  --unit="${RECOVERY_BASE}" --on-active="${RECOVERY_DELAY_SECONDS}s" \
  --timer-property=AccuracySec=1s --property=Type=oneshot \
  --property="TimeoutStartSec=${RECOVERY_ACTION_TIMEOUT_SECONDS}s" \
  --property="ExecStartPre=/usr/bin/rm -f -- ${START_INHIBIT}" \
  -- /usr/bin/systemctl start "${UNIT}"
systemctl_query is-active --quiet "${RECOVERY_BASE}.timer"

printf 'inhibit %s\n' "${run_id}" > "${inhibit_source}"
chmod 0600 "${inhibit_source}"
inhibit_sha256=$(sha256sum -- "${inhibit_source}" | awk '{print $1}') || exit 1
[[ ${inhibit_sha256} =~ ^[a-f0-9]{64}$ ]]
[[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]]
mv -T -- "${inhibit_source}" "${START_INHIBIT}"
inhibit_source=
start_inhibited=1
assert_start_inhibit
systemctl_query is-active --quiet "${RECOVERY_BASE}.timer"
restart_started_ms=$(monotonic_ms) || exit 1
restart_deadline_ms=$((restart_started_ms + MAX_RESTART_DURATION_MILLISECONDS))
(( restart_deadline_ms <= transaction_deadline_ms )) || \
  restart_deadline_ms=${transaction_deadline_ms}
operation_deadline_ms=${restart_deadline_ms}
relay_stop_requested=1
systemctl_mutate stop "${UNIT}"
relay_active_state=$(systemctl_query show -p ActiveState --value "${UNIT}") || exit 1
[[ ${relay_active_state} == inactive ]]
assert_start_inhibit
assert_no_relay_listeners
stopped_ms=$(monotonic_ms) || exit 1
assert_no_buffered_input "${input_probe}" "${restart_deadline_ms}"
stopped_challenge=$(random_hex_256)
printf 'FORMAT=1\nACTION=relay-restart\nACTUATOR_SHA256=%s\nAUTHORIZED_COMMAND_SHA256=%s\nPERMIT_AUTHORIZER_SHA256=%s\nRUN_ID=%s\nBEFORE_INVOCATION_SHA256=%s\nHOLD_MILLISECONDS=%s\nSTOPPED=1\nSTOPPED_CHALLENGE=%s\n' \
  "${actuator_digest}" "${authorized_command_digest}" "${permit_authorizer_digest}" \
  "${run_id}" "${before_digest}" "${HOLD_MILLISECONDS}" "${stopped_challenge}"

# The monitor signals the parent PID captured outside its subshell.
actuator_pid=${BASHPID}
monitor_stopped() {
  local active_state
  while :; do
    assert_start_inhibit || {
      printf 'failed\n' > "${monitor_failure}"
      kill -TERM "${actuator_pid}" 2>/dev/null || true
      return 1
    }
    active_state=$(systemctl_query show -p ActiveState --value "${UNIT}") || {
      printf 'failed\n' > "${monitor_failure}"
      kill -TERM "${actuator_pid}" 2>/dev/null || true
      return 1
    }
    [[ ${active_state} == inactive ]] || {
      printf 'failed\n' > "${monitor_failure}"
      kill -TERM "${actuator_pid}" 2>/dev/null || true
      return 1
    }
    assert_no_relay_listeners || {
      printf 'failed\n' > "${monitor_failure}"
      kill -TERM "${actuator_pid}" 2>/dev/null || true
      return 1
    }
    sleep_bounded 100 "${restart_deadline_ms}" || {
      printf 'failed\n' > "${monitor_failure}"
      kill -TERM "${actuator_pid}" 2>/dev/null || true
      return 1
    }
  done
}
: > "${monitor_failure}"
monitor_stopped &
monitor_pid=$!
release_deadline_ms=$((stopped_ms + RELEASE_TIMEOUT_MILLISECONDS))
(( release_deadline_ms <= transaction_deadline_ms )) || release_deadline_ms=${transaction_deadline_ms}
(( release_deadline_ms <= restart_deadline_ms )) || release_deadline_ms=${restart_deadline_ms}
read_exact_frame "${phase_frame}" "${RELEASE_FRAME_BYTES}" "${release_deadline_ms}"
grep -aEq '^release [a-f0-9]{32} [a-f0-9]{64} [A-Za-z0-9+/]{86}==$' "${phase_frame}"
phase_frame_lines=$(wc -l < "${phase_frame}") || exit 1
[[ ${phase_frame_lines} -eq 1 ]]
read -r phase_action phase_run phase_challenge phase_signature_base64 < "${phase_frame}"
[[ ${phase_action} == release && ${phase_run} == "${run_id}" && \
  ${phase_challenge} == "${stopped_challenge}" ]]
printf 'release %s %s %s\n' "${run_id}" "${stopped_challenge}" \
  "${phase_signature_base64}" > "${canonical_frame}"
cmp -s -- "${phase_frame}" "${canonical_frame}"
printf 'FORMAT=1\nACTION=relay-restart-release\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nDEPLOYMENT_ATTESTATION_SHA256=%s\nPERMIT_KEY_SHA256=%s\nSESSION_SHA256=%s\nACTUATOR_SHA256=%s\nAUTHORIZED_COMMAND_SHA256=%s\nPERMIT_AUTHORIZER_SHA256=%s\nBEFORE_INVOCATION_SHA256=%s\nSTOPPED_CHALLENGE=%s\nHOLD_MILLISECONDS=%s\n' \
  "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${local_deployment_sha256}" "${local_permit_key_sha256}" "${session_sha256}" \
  "${actuator_digest}" "${authorized_command_digest}" "${permit_authorizer_digest}" \
  "${before_digest}" "${stopped_challenge}" "${HOLD_MILLISECONDS}" > "${phase_payload}"
printf '%s' "${phase_signature_base64}" > "${signature_text}"
base64 -d -- "${signature_text}" > "${signature}"
signature_size=$(stat -c '%s' -- "${signature}") || exit 1
[[ ${signature_size} -eq 64 ]]
base64 -w 0 -- "${signature}" > "${signature_canonical}"
cmp -s -- "${signature_text}" "${signature_canonical}"
run_bounded "${operation_deadline_ms}" "${CRYPTO_TIMEOUT_MILLISECONDS}" \
  "${COMMAND_KILL_GRACE_MILLISECONDS}" openssl pkeyutl -verify -pubin \
  -inkey "${PERMIT_PUBLIC_KEY}" -rawin -in "${phase_payload}" \
  -sigfile "${signature}" >/dev/null

while :; do
  now_ms=$(monotonic_ms) || exit 1
  (( now_ms - stopped_ms >= HOLD_MILLISECONDS )) && break
  assert_start_inhibit
  relay_active_state=$(systemctl_query show -p ActiveState --value "${UNIT}") || exit 1
  [[ ${relay_active_state} == inactive ]]
  assert_no_relay_listeners
  sleep_bounded 50 "${restart_deadline_ms}"
done
assert_start_inhibit
relay_active_state=$(systemctl_query show -p ActiveState --value "${UNIT}") || exit 1
[[ ${relay_active_state} == inactive ]]
assert_no_relay_listeners
cancel_monitor
[[ ! -s ${monitor_failure} ]]
assert_start_inhibit
relay_active_state=$(systemctl_query show -p ActiveState --value "${UNIT}") || exit 1
[[ ${relay_active_state} == inactive ]]
assert_no_relay_listeners
restart_guard_ms=$(monotonic_ms) || exit 1
(( restart_guard_ms < restart_deadline_ms ))
remove_start_inhibit
systemctl_mutate start "${UNIT}"
systemctl_query is-active --quiet "${UNIT}"
after_invocation=$(systemctl_query show -p InvocationID --value "${UNIT}") || exit 1
[[ ${after_invocation} =~ ^[a-f0-9]{32}$ && ${after_invocation} != "${before_invocation}" ]]
after_digest=$(printf '%s' "${after_invocation}" | sha256sum | awk '{print $1}') || exit 1
[[ ${after_digest} =~ ^[a-f0-9]{64}$ && ${after_digest} != "${before_digest}" ]]
post_start_restarts=$(read_unit_restarts) || exit 1
(( post_start_restarts == 0 ))
completed_ms=$(monotonic_ms) || exit 1
(( completed_ms >= restart_started_ms ))
restart_duration_ms=$((completed_ms - restart_started_ms))
(( restart_duration_ms >= HOLD_MILLISECONDS && \
  restart_duration_ms <= MAX_RESTART_DURATION_MILLISECONDS ))
operation_deadline_ms=${transaction_deadline_ms}
assert_no_buffered_input "${input_probe}" "${transaction_deadline_ms}"
started_challenge=$(random_hex_256)
printf 'STARTED=1\nAFTER_INVOCATION_SHA256=%s\nRESTART_DURATION_MS=%s\nACTIVE=1\nSTARTED_CHALLENGE=%s\n' \
  "${after_digest}" "${restart_duration_ms}" "${started_challenge}"

assert_started_instance() {
  local active_invocation active_restarts
  systemctl_query is-active --quiet "${UNIT}" || return 1
  active_invocation=$(systemctl_query show -p InvocationID --value \
    "${UNIT}") || return 1
  [[ ${active_invocation} == "${after_invocation}" ]] || return 1
  active_restarts=$(read_unit_restarts) || return 1
  [[ ${active_restarts} == "${post_start_restarts}" ]] || return 1
  return 0
}

monitor_started() {
  while :; do
    assert_started_instance || {
      printf 'failed\n' > "${monitor_failure}"
      kill -TERM "${actuator_pid}" 2>/dev/null || true
      return 1
    }
    sleep_bounded 100 "${transaction_deadline_ms}" || {
      printf 'failed\n' > "${monitor_failure}"
      kill -TERM "${actuator_pid}" 2>/dev/null || true
      return 1
    }
  done
}
: > "${monitor_failure}"
monitor_started &
monitor_pid=$!
commit_deadline_ms=$((completed_ms + COMMIT_TIMEOUT_MILLISECONDS))
(( commit_deadline_ms <= transaction_deadline_ms )) || commit_deadline_ms=${transaction_deadline_ms}
read_exact_frame "${phase_frame}" "${COMMIT_FRAME_BYTES}" "${commit_deadline_ms}"
grep -aEq '^commit [a-f0-9]{32} [a-f0-9]{64} [A-Za-z0-9+/]{86}==$' "${phase_frame}"
phase_frame_lines=$(wc -l < "${phase_frame}") || exit 1
[[ ${phase_frame_lines} -eq 1 ]]
read -r phase_action phase_run phase_challenge phase_signature_base64 < "${phase_frame}"
[[ ${phase_action} == commit && ${phase_run} == "${run_id}" && \
  ${phase_challenge} == "${started_challenge}" ]]
printf 'commit %s %s %s\n' "${run_id}" "${started_challenge}" \
  "${phase_signature_base64}" > "${canonical_frame}"
cmp -s -- "${phase_frame}" "${canonical_frame}"
printf 'FORMAT=1\nACTION=relay-restart-commit\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nDEPLOYMENT_ATTESTATION_SHA256=%s\nPERMIT_KEY_SHA256=%s\nSESSION_SHA256=%s\nACTUATOR_SHA256=%s\nAUTHORIZED_COMMAND_SHA256=%s\nPERMIT_AUTHORIZER_SHA256=%s\nBEFORE_INVOCATION_SHA256=%s\nSTOPPED_CHALLENGE=%s\nAFTER_INVOCATION_SHA256=%s\nSTARTED_CHALLENGE=%s\nRESTART_DURATION_MS=%s\nACTIVE=1\n' \
  "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${local_deployment_sha256}" "${local_permit_key_sha256}" "${session_sha256}" \
  "${actuator_digest}" "${authorized_command_digest}" "${permit_authorizer_digest}" \
  "${before_digest}" "${stopped_challenge}" "${after_digest}" \
  "${started_challenge}" "${restart_duration_ms}" > "${phase_payload}"
printf '%s' "${phase_signature_base64}" > "${signature_text}"
base64 -d -- "${signature_text}" > "${signature}"
signature_size=$(stat -c '%s' -- "${signature}") || exit 1
[[ ${signature_size} -eq 64 ]]
base64 -w 0 -- "${signature}" > "${signature_canonical}"
cmp -s -- "${signature_text}" "${signature_canonical}"
run_bounded "${operation_deadline_ms}" "${CRYPTO_TIMEOUT_MILLISECONDS}" \
  "${COMMAND_KILL_GRACE_MILLISECONDS}" openssl pkeyutl -verify -pubin \
  -inkey "${PERMIT_PUBLIC_KEY}" -rawin -in "${phase_payload}" \
  -sigfile "${signature}" >/dev/null
assert_exact_eof "${input_probe}" "${transaction_deadline_ms}"

commit_received_ms=$(monotonic_ms) || exit 1
commit_stability_deadline_ms=$((commit_received_ms + COMMIT_STABILITY_MILLISECONDS))
(( commit_stability_deadline_ms < transaction_deadline_ms ))
while :; do
  assert_started_instance
  now_ms=$(monotonic_ms) || exit 1
  (( now_ms >= commit_stability_deadline_ms )) && break
  sleep_bounded 50 "${transaction_deadline_ms}"
done
final_invocation=$(systemctl_query show -p InvocationID --value "${UNIT}") || exit 1
[[ ${final_invocation} == "${after_invocation}" ]]
final_digest=$(printf '%s' "${final_invocation}" | sha256sum | awk '{print $1}') || exit 1
[[ ${final_digest} == "${after_digest}" ]]
final_restarts=$(read_unit_restarts) || exit 1
(( final_restarts == post_start_restarts && final_restarts == 0 ))
cancel_recovery
assert_started_instance
cancel_monitor
[[ ! -s ${monitor_failure} ]]
assert_started_instance
transaction_guard_ms=$(monotonic_ms) || exit 1
(( transaction_guard_ms < transaction_deadline_ms ))
recovery_armed=0
relay_stop_requested=0
printf 'STATUS=pass\nCOMMITTED=1\nSIGNED_RELEASE=1\nSIGNED_COMMIT=1\nFINAL_INVOCATION_SHA256=%s\nNRESTARTS_DELTA=0\nCOMMIT_STABILITY_MILLISECONDS=%s\n' \
  "${final_digest}" "${COMMIT_STABILITY_MILLISECONDS}"
