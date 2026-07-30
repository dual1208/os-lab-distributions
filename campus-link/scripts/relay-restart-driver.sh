#!/bin/bash -p
set -euo pipefail
umask 077

[[ $- == *p* ]]
[[ -z ${BASH_ENV+x} && -z ${ENV+x} ]]
[[ -z ${LD_PRELOAD+x} && -z ${LD_LIBRARY_PATH+x} && -z ${LD_AUDIT+x} ]]
[[ -z ${OPENSSL_CONF+x} && -z ${OPENSSL_MODULES+x} && -z ${OPENSSL_ENGINES+x} ]]
readonly inherited_run_manifest=${CAMPUS_LINK_RUN_MANIFEST:-}

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

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
readonly SCRIPT_DIR
if [[ -f ${SCRIPT_DIR}/campus-link-gate-evidence ]]; then
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/campus-link-gate-evidence
else
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/gate-evidence.sh
fi
if [[ -f ${SCRIPT_DIR}/campus-link-relay-restart-transport ]]; then
  readonly TRANSPORT=${SCRIPT_DIR}/campus-link-relay-restart-transport
else
  readonly TRANSPORT=${SCRIPT_DIR}/relay-restart-transport.sh
fi
readonly ACCESS_DIR=/etc/campus-link/relay-fault
readonly TARGET_FILE=${ACCESS_DIR}/target
readonly PRIVATE_KEY=${ACCESS_DIR}/id_ed25519
readonly KNOWN_HOSTS=${ACCESS_DIR}/known_hosts
readonly PERMIT_PRIVATE_KEY=${ACCESS_DIR}/permit_ed25519.pem
readonly PERMIT_PUBLIC_KEY=${ACCESS_DIR}/permit_ed25519.pub.pem
readonly LOCK=/run/campus-link/relay-restart-driver.lock
readonly RELEASE_MANIFEST=/var/lib/campus-link/installed-release-manifest.sha256
readonly DEPLOYMENT_ATTESTATION=/var/lib/campus-link/deployment-attestation.env
readonly PERMIT_LIFETIME_SECONDS=600
readonly PERMIT_ATTEMPTS=2
readonly DRIVER_TIMEOUT_MILLISECONDS=360000
readonly PERMIT_COMMAND_TIMEOUT_MILLISECONDS=35000
readonly DRIVER_COMMAND_KILL_GRACE_MILLISECONDS=5000
readonly TRANSPORT_BUDGET_MILLISECONDS=260000
readonly TRANSPORT_TERM_GRACE_MILLISECONDS=7000
readonly TRANSPORT_KILL_REAP_MILLISECONDS=3000
readonly DRIVER_CLEANUP_BUDGET_MILLISECONDS=14000
readonly RAW_ACK_MAX_BYTES=4096
readonly RAW_PHASE_STABILITY_MILLISECONDS=150
readonly RAW_COMPARE_TIMEOUT_MILLISECONDS=2000
readonly RAW_COMPARE_KILL_GRACE_MILLISECONDS=500
(( PERMIT_ATTEMPTS * PERMIT_COMMAND_TIMEOUT_MILLISECONDS + \
  TRANSPORT_BUDGET_MILLISECONDS < DRIVER_TIMEOUT_MILLISECONDS ))
(( TRANSPORT_TERM_GRACE_MILLISECONDS + \
  2 * TRANSPORT_KILL_REAP_MILLISECONDS < DRIVER_CLEANUP_BUDGET_MILLISECONDS ))

[[ ${EUID} -eq 0 ]]
[[ $# -eq 5 ]]
readonly run_id=$1
readonly active_marker=$2
readonly release_marker=$3
readonly started_marker=$4
readonly commit_marker=$5
readonly run_manifest=${inherited_run_manifest}
[[ ${run_id} =~ ^[a-f0-9]{32}$ ]]
[[ ${active_marker} =~ ^/run/campus-link/\.fault-in-stream\.[A-Za-z0-9]+/relay-restart-active\.env$ ]]
[[ ${release_marker} =~ ^/run/campus-link/\.fault-in-stream\.[A-Za-z0-9]+/relay-restart-release\.env$ ]]
[[ ${started_marker} =~ ^/run/campus-link/\.fault-in-stream\.[A-Za-z0-9]+/relay-restart-started\.env$ ]]
[[ ${commit_marker} =~ ^/run/campus-link/\.fault-in-stream\.[A-Za-z0-9]+/relay-restart-commit\.env$ ]]
readonly marker_parent=${active_marker%/*}
for marker in "${release_marker}" "${started_marker}" "${commit_marker}"; do
  [[ ${marker%/*} == "${marker_parent}" ]]
done
[[ -d ${marker_parent} && ! -L ${marker_parent} ]]
marker_parent_metadata=$(stat -c '%u:%g:%a' -- "${marker_parent}") || exit 1
[[ ${marker_parent_metadata} == 0:0:700 ]]
for marker in "${active_marker}" "${release_marker}" "${started_marker}" "${commit_marker}"; do
  [[ ! -e ${marker} && ! -L ${marker} ]]
done
[[ -f ${EVIDENCE_HELPER} && ! -L ${EVIDENCE_HELPER} ]]
# shellcheck source=gate-evidence.sh
source "${EVIDENCE_HELPER}"
campus_link_require_root_file "${RELEASE_MANIFEST}" 600
campus_link_validate_release_manifest "${RELEASE_MANIFEST}"

release_digest() {
  local logical=$1 line digest
  local -a lines=() matches=()
  mapfile -t lines < "${RELEASE_MANIFEST}" || return 1
  for line in "${lines[@]}"; do
    if [[ ${line#*  } == "${logical}" ]]; then
      matches+=("${line}")
    fi
  done
  [[ ${#matches[@]} -eq 1 ]] || return 1
  line=${matches[0]}
  [[ ${line#*  } == "${logical}" ]] || return 1
  digest=${line%% *}
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s\n' "${digest}" || return 1
  return 0
}

expected_actuator_digest=$(release_digest scripts/relay-restart-actuator.sh) || exit 1
expected_authorized_digest=$(release_digest scripts/relay-restart-authorized.sh) || exit 1
expected_permit_authorizer_digest=$(release_digest scripts/relay-restart-permit-authorize.sh) || exit 1
expected_transport_digest=$(release_digest scripts/relay-restart-transport.sh) || exit 1
for digest in "${expected_actuator_digest}" "${expected_authorized_digest}" \
  "${expected_permit_authorizer_digest}" "${expected_transport_digest}"; do
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]]
done
campus_link_require_root_file "${TRANSPORT}" 755
transport_digest=$(sha256sum -- "${TRANSPORT}" | awk '{print $1}') || exit 1
[[ ${transport_digest} == "${expected_transport_digest}" ]]

[[ -d ${ACCESS_DIR} && ! -L ${ACCESS_DIR} ]]
access_metadata=$(stat -c '%u:%g:%a' -- "${ACCESS_DIR}") || exit 1
[[ ${access_metadata} == 0:0:700 ]]
for path in "${TARGET_FILE}" "${PRIVATE_KEY}" "${KNOWN_HOSTS}" \
  "${PERMIT_PRIVATE_KEY}" "${PERMIT_PUBLIC_KEY}"; do
  campus_link_require_root_file "${path}" 600
  path_links=$(stat -c '%h' -- "${path}") || exit 1
  [[ ${path_links} == 1 ]]
done
mapfile -t target_lines < "${TARGET_FILE}" || exit 1
[[ ${#target_lines[@]} -eq 1 ]]
readonly target=${target_lines[0]}
[[ ${target} =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$ ]]
grep -Fxq -- '-----BEGIN OPENSSH PRIVATE KEY-----' "${PRIVATE_KEY}"
ssh_key_type=$(ssh-keygen -y -f "${PRIVATE_KEY}" 2>/dev/null | awk '{print $1}') || exit 1
[[ ${ssh_key_type} == ssh-ed25519 ]]
known_hosts_lines=$(wc -l < "${KNOWN_HOSTS}") || exit 1
[[ ${known_hosts_lines} -eq 1 ]]
grep -Eq '^campus-link-relay-fault ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' "${KNOWN_HOSTS}"
grep -Fxq -- '-----BEGIN PRIVATE KEY-----' "${PERMIT_PRIVATE_KEY}"
grep -Fxq -- '-----BEGIN PUBLIC KEY-----' "${PERMIT_PUBLIC_KEY}"
permit_private_type=$(openssl pkey -in "${PERMIT_PRIVATE_KEY}" \
  -text_pub -noout 2>/dev/null | sed -n '1p') || exit 1
permit_public_type=$(openssl pkey -pubin -in "${PERMIT_PUBLIC_KEY}" \
  -text_pub -noout 2>/dev/null | sed -n '1p') || exit 1
[[ ${permit_private_type} == 'ED25519 Public-Key:' ]]
[[ ${permit_public_type} == 'ED25519 Public-Key:' ]]
derived_permit_public=$(openssl pkey -in "${PERMIT_PRIVATE_KEY}" -pubout 2>/dev/null) || exit 1
declared_permit_public=$(<"${PERMIT_PUBLIC_KEY}") || exit 1
[[ ${derived_permit_public} == "${declared_permit_public}" ]]
permit_key_sha256=$(sha256sum -- "${PERMIT_PUBLIC_KEY}" | awk '{print $1}') || exit 1
[[ ${permit_key_sha256} =~ ^[a-f0-9]{64}$ ]]

campus_link_validate_run_manifest "${run_manifest}"
campus_link_marker_equals "${run_manifest}" RUN_ID "${run_id}"
candidate_sha256=$(campus_link_marker_value "${run_manifest}" CANDIDATE_SHA256) || exit 1
run_manifest_sha256=$(campus_link_run_manifest_sha256 "${run_manifest}") || exit 1
deployment_attestation_sha256=$(campus_link_marker_value \
  "${run_manifest}" DEPLOYMENT_ATTESTATION_SHA256) || exit 1
for digest in "${candidate_sha256}" "${run_manifest_sha256}" \
  "${deployment_attestation_sha256}"; do
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]]
done
campus_link_require_root_file "${DEPLOYMENT_ATTESTATION}" 600
current_deployment_sha256=$(sha256sum -- "${DEPLOYMENT_ATTESTATION}" | awk '{print $1}') || exit 1
[[ ${current_deployment_sha256} == "${deployment_attestation_sha256}" ]]

exec 8<>"${LOCK}"
flock -n 8
lock_metadata=$(stat -c '%u:%g:%a:%h' -- "${LOCK}") || exit 1
[[ ${lock_metadata} == 0:0:600:1 ]]

phase=$(mktemp /run/campus-link/.relay-restart-phase.XXXXXX)
ack=$(mktemp /run/campus-link/.relay-restart-ack.XXXXXX)
ssh_error=$(mktemp /run/campus-link/.relay-restart-ssh-error.XXXXXX)
raw_ack=$(mktemp /run/campus-link/.relay-restart-raw-ack.XXXXXX)
pgid_marker=$(mktemp /run/campus-link/.relay-restart-transport-pgid.XXXXXX)
permit_payload=$(mktemp /run/campus-link/.relay-restart-permit.XXXXXX)
permit_signature=$(mktemp /run/campus-link/.relay-restart-permit-signature.XXXXXX)
permit_signature_text=$(mktemp /run/campus-link/.relay-restart-permit-signature-text.XXXXXX)
permit_envelope=$(mktemp /run/campus-link/.relay-restart-permit-envelope.XXXXXX)
permit_ack=$(mktemp /run/campus-link/.relay-restart-permit-ack.XXXXXX)
permit_expected_ack=$(mktemp /run/campus-link/.relay-restart-permit-expected-ack.XXXXXX)
permit_error=$(mktemp /run/campus-link/.relay-restart-permit-error.XXXXXX)
phase_payload=$(mktemp /run/campus-link/.relay-restart-phase-payload.XXXXXX)
phase_signature=$(mktemp /run/campus-link/.relay-restart-phase-signature.XXXXXX)
phase_signature_text=$(mktemp /run/campus-link/.relay-restart-phase-signature-text.XXXXXX)
phase_command=$(mktemp /run/campus-link/.relay-restart-phase-command.XXXXXX)
relay_ssh_pid=
relay_ssh_start_ticks=
transport_pgid=
transport_start_ticks=

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

sleep_bounded() {
  local requested_ms=$1 deadline_ms=$2 now_ms remaining_ms sleep_ms duration
  now_ms=$(campus_link_monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 1
  remaining_ms=$((deadline_ms - now_ms))
  sleep_ms=${requested_ms}
  (( sleep_ms <= remaining_ms )) || sleep_ms=${remaining_ms}
  (( sleep_ms > 0 )) || return 1
  printf -v duration '%d.%03ds' $((sleep_ms / 1000)) $((sleep_ms % 1000))
  sleep "${duration}"
}

bounded_deadline() {
  local requested_ms=$1 now_ms deadline_ms
  now_ms=$(campus_link_monotonic_ms) || return 1
  (( now_ms < driver_deadline_ms )) || return 1
  deadline_ms=$((now_ms + requested_ms))
  (( deadline_ms <= driver_deadline_ms )) || deadline_ms=${driver_deadline_ms}
  printf '%s\n' "${deadline_ms}"
}

run_bounded() {
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
  printf -v duration '%d.%03ds' $((command_ms / 1000)) $((command_ms % 1000))
  printf -v grace_duration '%d.%03ds' $((grace_ms / 1000)) $((grace_ms % 1000))
  timeout --signal=TERM --kill-after="${grace_duration}" "${duration}" "$@"
}

require_driver_temp_file() {
  local path=$1 metadata
  [[ -f ${path} && ! -L ${path} ]] || return 1
  metadata=$(stat -c '%u:%g:%a:%h' -- "${path}") || return 1
  [[ ${metadata} == 0:0:600:1 ]] || return 1
  return 0
}

# Bash variables cannot retain NUL bytes.  The line parser is therefore only a
# schema parser: no phase transition may trust it until the independently
# captured SSH stdout is byte-for-byte identical to the canonical phase and
# remains unchanged for the anti-prequeue interval.
assert_raw_phase_exact() {
  local expected=$1 deadline_ms=$2 expected_size raw_size now_ms stability_deadline_ms
  require_driver_temp_file "${expected}" || return 1
  require_driver_temp_file "${raw_ack}" || return 1
  expected_size=$(stat -c '%s' -- "${expected}") || return 1
  [[ ${expected_size} =~ ^[1-9][0-9]*$ ]] || return 1
  (( expected_size <= RAW_ACK_MAX_BYTES )) || return 1

  while :; do
    require_driver_temp_file "${raw_ack}" || return 1
    raw_size=$(stat -c '%s' -- "${raw_ack}") || return 1
    [[ ${raw_size} =~ ^[0-9]+$ ]] || return 1
    (( raw_size <= RAW_ACK_MAX_BYTES )) || return 1
    (( raw_size < expected_size )) || break
    relay_child_matches || return 1
    sleep_bounded 10 "${deadline_ms}" || return 1
  done
  (( raw_size == expected_size )) || return 1
  run_bounded "${deadline_ms}" "${RAW_COMPARE_TIMEOUT_MILLISECONDS}" \
    "${RAW_COMPARE_KILL_GRACE_MILLISECONDS}" cmp -s -- \
    "${raw_ack}" "${expected}" || return 1

  now_ms=$(campus_link_monotonic_ms) || return 1
  stability_deadline_ms=$((now_ms + RAW_PHASE_STABILITY_MILLISECONDS))
  (( stability_deadline_ms < deadline_ms )) || return 1
  while :; do
    now_ms=$(campus_link_monotonic_ms) || return 1
    (( now_ms < stability_deadline_ms )) || break
    relay_child_matches || return 1
    require_driver_temp_file "${raw_ack}" || return 1
    raw_size=$(stat -c '%s' -- "${raw_ack}") || return 1
    [[ ${raw_size} =~ ^[0-9]+$ ]] || return 1
    (( raw_size == expected_size )) || return 1
    if ! sleep_bounded 10 "${stability_deadline_ms}"; then
      now_ms=$(campus_link_monotonic_ms) || return 1
      (( now_ms >= stability_deadline_ms && now_ms < deadline_ms )) || return 1
      break
    fi
  done
  relay_child_matches || return 1
  require_driver_temp_file "${raw_ack}" || return 1
  raw_size=$(stat -c '%s' -- "${raw_ack}") || return 1
  [[ ${raw_size} =~ ^[0-9]+$ ]] || return 1
  (( raw_size == expected_size )) || return 1
  run_bounded "${deadline_ms}" "${RAW_COMPARE_TIMEOUT_MILLISECONDS}" \
    "${RAW_COMPARE_KILL_GRACE_MILLISECONDS}" cmp -s -- \
    "${raw_ack}" "${expected}" || return 1
  return 0
}

relay_child_matches() {
  local state
  [[ -n ${relay_ssh_pid:-} && -n ${relay_ssh_start_ticks:-} ]] || return 1
  inspect_process_identity "${relay_ssh_pid}" "${relay_ssh_start_ticks}" state
  [[ ${state} == live ]]
}

load_transport_group() {
  local own_pgid
  local -a pgid_lines=()
  if [[ -n ${transport_pgid:-} ]]; then
    return 0
  fi
  [[ -f ${pgid_marker} && ! -L ${pgid_marker} ]] || return 1
  mapfile -t pgid_lines < "${pgid_marker}" || return 1
  [[ ${#pgid_lines[@]} -eq 1 && ${pgid_lines[0]} =~ ^[1-9][0-9]*$ ]] || return 1
  own_pgid=$(ps -o pgid= -p "${BASHPID}" | tr -d '[:space:]') || return 1
  [[ ${own_pgid} =~ ^[1-9][0-9]*$ && ${pgid_lines[0]} != "${own_pgid}" ]] || return 1
  transport_pgid=${pgid_lines[0]}
  transport_start_ticks=$(process_start_ticks "${transport_pgid}") || return 1
  return 0
}

transport_group_matches() {
  local identity_state leader_record leader_pgid leader_sid extra
  [[ -n ${transport_pgid:-} && -n ${transport_start_ticks:-} ]] || return 1
  inspect_process_identity "${transport_pgid}" "${transport_start_ticks}" \
    identity_state
  [[ ${identity_state} == live || ${identity_state} == zombie ]] || return 1
  leader_record=$(ps -o pgid=,sid= -p "${transport_pgid}") || return 1
  [[ ${leader_record} != *$'\n'* ]] || return 1
  read -r leader_pgid leader_sid extra <<< "${leader_record}" || return 1
  [[ ${leader_pgid} == "${transport_pgid}" && \
    ${leader_sid} == "${transport_pgid}" && -z ${extra} ]] || return 1
  # Re-read the immutable start time after ps and immediately before the
  # caller's group signal.  A missing, recycled, or ambiguous leader forbids
  # the negative-PGID signal.
  inspect_process_identity "${transport_pgid}" "${transport_start_ticks}" \
    identity_state
  [[ ${identity_state} == live || ${identity_state} == zombie ]] || return 1
  return 0
}

signal_transport_group() {
  local signal=$1
  transport_group_matches || return 2
  case ${signal} in
    TERM) kill -TERM -- "-${transport_pgid}" || return 2 ;;
    KILL) kill -KILL -- "-${transport_pgid}" || return 2 ;;
    *) return 2 ;;
  esac
  return 0
}

transport_group_exists() {
  local groups
  [[ -n ${transport_pgid:-} && ${transport_pgid} =~ ^[1-9][0-9]*$ ]] || return 2
  groups=$(ps -eo pid=,pgid=,sid=) || return 2
  awk -v expected="${transport_pgid}" '
    NF == 0 { next }
    NF != 3 || $1 !~ /^[1-9][0-9]*$/ || $2 !~ /^[1-9][0-9]*$/ ||
      $3 !~ /^[1-9][0-9]*$/ { invalid=1; next }
    $3 == expected { found=1 }
    END {
      if (invalid) exit 2
      exit(found ? 0 : 1)
    }
  ' <<< "${groups}"
}

inspect_transport_group() {
  local destination=$1 status state
  if transport_group_exists; then
    state=live
  else
    status=$?
    case ${status} in
      1) state=absent ;;
      *) state=inspection-error ;;
    esac
  fi
  printf -v "${destination}" '%s' "${state}"
}

wait_child_until() {
  local pid=$1 start_ticks=$2 deadline_ms=$3 destination=$4
  local now_ms status state
  while :; do
    now_ms=$(campus_link_monotonic_ms) || return 1
    (( now_ms < deadline_ms )) || return 124
    inspect_process_identity "${pid}" "${start_ticks}" state
    case ${state} in
      live) sleep_bounded 50 "${deadline_ms}" || return 124 ;;
      zombie|gone) break ;;
      *) return 125 ;;
    esac
  done
  now_ms=$(campus_link_monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 124
  if wait "${pid}"; then
    status=0
  else
    status=$?
  fi
  printf -v "${destination}" '%s' "${status}"
  return 0
}

terminate_transport() {
  local cleanup_started_ms cleanup_deadline_ms kill_at_ms now_ms ignored_status
  local child_state group_state
  local child_reaped=0 group_owned=0 group_absent=0 kill_sent=0 cleanup_ok=1
  { exec 7>&-; } 2>/dev/null || true
  { exec 6<&-; } 2>/dev/null || true
  cleanup_started_ms=$(campus_link_monotonic_ms) || return 1
  cleanup_deadline_ms=$((cleanup_started_ms + DRIVER_CLEANUP_BUDGET_MILLISECONDS))
  kill_at_ms=$((cleanup_started_ms + TRANSPORT_TERM_GRACE_MILLISECONDS))

  if [[ -n ${transport_pgid:-} ]]; then
    group_owned=1
  elif [[ -s ${pgid_marker:-} ]]; then
    if load_transport_group 2>/dev/null; then
      group_owned=1
    else
      cleanup_ok=0
    fi
  elif [[ ! -f ${pgid_marker:-} || -L ${pgid_marker:-} ]]; then
    cleanup_ok=0
  fi

  if (( group_owned != 0 )); then
    inspect_transport_group group_state
    case ${group_state} in
      live) signal_transport_group TERM 2>/dev/null || cleanup_ok=0 ;;
      absent) group_absent=1 ;;
      *) cleanup_ok=0 ;;
    esac
  fi
  if [[ -n ${relay_ssh_pid:-} && -n ${relay_ssh_start_ticks:-} ]]; then
    inspect_process_identity "${relay_ssh_pid}" "${relay_ssh_start_ticks}" child_state
    case ${child_state} in
      live) kill -TERM "${relay_ssh_pid}" 2>/dev/null || true ;;
      zombie|gone) ;;
      *) cleanup_ok=0 ;;
    esac
  elif [[ -n ${relay_ssh_pid:-} || -n ${relay_ssh_start_ticks:-} ]]; then
    cleanup_ok=0
  else
    child_reaped=1
  fi

  while :; do
    now_ms=$(campus_link_monotonic_ms) || { cleanup_ok=0; break; }
    (( now_ms < cleanup_deadline_ms )) || break

    if (( group_owned == 0 && cleanup_ok != 0 )); then
      if [[ -s ${pgid_marker} ]]; then
        if load_transport_group 2>/dev/null; then
          group_owned=1
        else
          cleanup_ok=0
        fi
      elif [[ ! -f ${pgid_marker} || -L ${pgid_marker} ]]; then
        cleanup_ok=0
      fi
    fi

    if (( group_owned != 0 )); then
      inspect_transport_group group_state
      case ${group_state} in
        live) group_absent=0 ;;
        absent) group_absent=1 ;;
        *) cleanup_ok=0; group_absent=0 ;;
      esac
    fi

    if (( child_reaped == 0 )); then
      inspect_process_identity "${relay_ssh_pid}" "${relay_ssh_start_ticks}" child_state
      case ${child_state} in
        live) ;;
        zombie|gone)
          now_ms=$(campus_link_monotonic_ms) || { cleanup_ok=0; break; }
          (( now_ms < cleanup_deadline_ms )) || break
          wait "${relay_ssh_pid}" 2>/dev/null || ignored_status=$?
          child_reaped=1
          ;;
        *) cleanup_ok=0 ;;
      esac
    fi

    if (( group_owned == 0 && child_reaped != 0 && cleanup_ok != 0 )); then
      if [[ ! -s ${pgid_marker} && -f ${pgid_marker} && ! -L ${pgid_marker} ]]; then
        group_absent=1
      fi
    fi
    (( child_reaped != 0 && group_absent != 0 )) && break

    if (( kill_sent == 0 && now_ms >= kill_at_ms )); then
      if (( group_owned != 0 )); then
        inspect_transport_group group_state
        case ${group_state} in
          live) signal_transport_group KILL 2>/dev/null || cleanup_ok=0 ;;
          absent) group_absent=1 ;;
          *) cleanup_ok=0 ;;
        esac
      fi
      if (( child_reaped == 0 )); then
        inspect_process_identity "${relay_ssh_pid}" "${relay_ssh_start_ticks}" child_state
        case ${child_state} in
          live) kill -KILL "${relay_ssh_pid}" 2>/dev/null || true ;;
          zombie|gone) ;;
          *) cleanup_ok=0 ;;
        esac
      fi
      kill_sent=1
    fi
    sleep_bounded 50 "${cleanup_deadline_ms}" || break
  done

  local cleanup_result=1
  if (( child_reaped != 0 && group_absent != 0 && cleanup_ok != 0 )); then
    cleanup_result=0
  fi
  relay_ssh_pid=
  relay_ssh_start_ticks=
  transport_pgid=
  transport_start_ticks=
  return "${cleanup_result}"
}

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT HUP INT TERM
  set +e
  terminate_transport || cleanup_status=$?
  if (( status == 0 && cleanup_status != 0 )); then
    status=${cleanup_status}
  fi
  rm -f -- "${phase:-}" "${ack:-}" "${ssh_error:-}" "${raw_ack:-}" \
    "${pgid_marker:-}" "${permit_payload:-}" "${permit_signature:-}" \
    "${permit_signature_text:-}" "${permit_envelope:-}" "${permit_ack:-}" \
    "${permit_expected_ack:-}" "${permit_error:-}" "${phase_payload:-}" \
    "${phase_signature:-}" "${phase_signature_text:-}" "${phase_command:-}"
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

read_protocol_line() {
  local destination=$1 deadline_ms=$2 value now_ms remaining_ms duration
  now_ms=$(campus_link_monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 1
  remaining_ms=$((deadline_ms - now_ms))
  printf -v duration '%d.%03d' $((remaining_ms / 1000)) \
    $((remaining_ms % 1000)) || return 1
  IFS= read -r -t "${duration}" -n 257 value <&6 || return 1
  (( ${#value} <= 256 )) || return 1
  [[ ${value} != *$'\r'* && ${value} != *$'\n'* ]] || return 1
  printf -v "${destination}" '%s' "${value}" || return 1
  return 0
}

driver_started_ms=$(campus_link_monotonic_ms) || exit 1
driver_deadline_ms=$((driver_started_ms + DRIVER_TIMEOUT_MILLISECONDS))

readonly -a SSH_OPTIONS=(
  -F /dev/null -T
  -i "${PRIVATE_KEY}"
  -o BatchMode=yes
  -o CanonicalizeHostname=no
  -o ClearAllForwardings=yes
  -o ConnectionAttempts=1
  -o ConnectTimeout=10
  -o ExitOnForwardFailure=yes
  -o GlobalKnownHostsFile=/dev/null
  -o HostKeyAlias=campus-link-relay-fault
  -o IdentitiesOnly=yes
  -o KbdInteractiveAuthentication=no
  -o LogLevel=ERROR
  -o PasswordAuthentication=no
  -o PermitLocalCommand=no
  -o PreferredAuthentications=publickey
  -o ProxyCommand=none
  -o PubkeyAuthentication=yes
  -o RequestTTY=no
  -o StrictHostKeyChecking=yes
  -o UpdateHostKeys=no
  -o "UserKnownHostsFile=${KNOWN_HOSTS}"
)

session_secret=$(openssl rand -hex 32) || exit 1
[[ ${session_secret} =~ ^[a-f0-9]{64}$ ]]
session_sha256=$(printf '%s' "${session_secret}" | sha256sum | awk '{print $1}') || exit 1
[[ ${session_sha256} =~ ^[a-f0-9]{64}$ ]]
issued_unix=$(date +%s) || exit 1
[[ ${issued_unix} =~ ^[1-9][0-9]{9,10}$ ]]
not_after_unix=$((issued_unix + PERMIT_LIFETIME_SECONDS))
printf 'FORMAT=1\nACTION=relay-restart-permit\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nDEPLOYMENT_ATTESTATION_SHA256=%s\nPERMIT_KEY_SHA256=%s\nSESSION_SHA256=%s\nISSUED_UNIX=%s\nNOT_AFTER_UNIX=%s\n' \
  "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${deployment_attestation_sha256}" "${permit_key_sha256}" \
  "${session_sha256}" "${issued_unix}" "${not_after_unix}" > "${permit_payload}"
openssl pkeyutl -sign -inkey "${PERMIT_PRIVATE_KEY}" -rawin \
  -in "${permit_payload}" -out "${permit_signature}"
permit_signature_size=$(stat -c '%s' -- "${permit_signature}") || exit 1
[[ ${permit_signature_size} -eq 64 ]]
base64 -w 0 -- "${permit_signature}" > "${permit_signature_text}"
permit_signature_text_size=$(stat -c '%s' -- "${permit_signature_text}") || exit 1
[[ ${permit_signature_text_size} -eq 88 ]]
{ cat -- "${permit_payload}"; printf 'SIGNATURE_BASE64='; \
  cat -- "${permit_signature_text}"; printf '\n'; } > "${permit_envelope}"
permit_sha256=$({ cat -- "${permit_payload}"; cat -- "${permit_signature}"; } | sha256sum | awk '{print $1}') || exit 1
[[ ${permit_sha256} =~ ^[a-f0-9]{64}$ ]]
printf 'FORMAT=1\nSTATUS=pass\nACTION=relay-restart-permit\nPERMIT_AUTHORIZER_SHA256=%s\nRUN_ID=%s\nPERMIT_SHA256=%s\nNOT_AFTER_UNIX=%s\nSESSION_BOUND=1\n' \
  "${expected_permit_authorizer_digest}" "${run_id}" "${permit_sha256}" \
  "${not_after_unix}" > "${permit_expected_ack}"

permit_ok=0
for ((attempt = 1; attempt <= PERMIT_ATTEMPTS; attempt++)); do
  : > "${permit_ack}"
  : > "${permit_error}"
  if (
    ulimit -f 8 || exit 125
    file_limit=$(ulimit -f) || exit 125
    [[ ${file_limit} == 8 ]] || exit 125
    run_bounded "${driver_deadline_ms}" "${PERMIT_COMMAND_TIMEOUT_MILLISECONDS}" \
      "${DRIVER_COMMAND_KILL_GRACE_MILLISECONDS}" ssh "${SSH_OPTIONS[@]}" -- \
      "campus-link-fault@${target}" permit < "${permit_envelope}"
  ) > "${permit_ack}" 2> "${permit_error}" && \
    [[ ! -s ${permit_error} ]] && cmp -s -- "${permit_ack}" "${permit_expected_ack}"; then
    permit_ok=1
    break
  fi
done
(( permit_ok == 1 ))

coproc RELAY_SSH {
  exec setsid --wait "${TRANSPORT}" "${pgid_marker}" "${raw_ack}" \
    "${ssh_error}" "${PRIVATE_KEY}" "${KNOWN_HOSTS}" "${target}"
}
relay_ssh_pid=${RELAY_SSH_PID}
relay_ssh_start_ticks=$(process_start_ticks "${relay_ssh_pid}") || exit 1
exec 6<&"${RELAY_SSH[0]}"
exec 7>&"${RELAY_SSH[1]}"

pgid_deadline_ms=$(bounded_deadline 5000)
while ! grep -Eq '^[1-9][0-9]*$' "${pgid_marker}"; do
  pgid_poll_ms=$(campus_link_monotonic_ms) || exit 1
  (( pgid_poll_ms < pgid_deadline_ms ))
  relay_child_matches
  sleep_bounded 10 "${pgid_deadline_ms}"
done
load_transport_group
transport_group_matches
transport_group_exists

printf 'START\n' >&7
printf 'open %s %s\n' "${run_id}" "${session_secret}" >&7
unset session_secret

stopped_deadline_ms=$(bounded_deadline 70000)
for key in FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \
  PERMIT_AUTHORIZER_SHA256 RUN_ID BEFORE_INVOCATION_SHA256 \
  HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE; do
  read_protocol_line line "${stopped_deadline_ms}" || {
    echo 'Authenticated relay restart stopped-phase proof failed.' >&2
    exit 1
  }
  printf '%s\n' "${line}" >> "${phase}"
done
campus_link_validate_schema "${phase}" \
  FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \
  PERMIT_AUTHORIZER_SHA256 RUN_ID BEFORE_INVOCATION_SHA256 \
  HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE
campus_link_marker_equals "${phase}" FORMAT 1
campus_link_marker_equals "${phase}" ACTION relay-restart
campus_link_marker_equals "${phase}" ACTUATOR_SHA256 "${expected_actuator_digest}"
campus_link_marker_equals "${phase}" AUTHORIZED_COMMAND_SHA256 \
  "${expected_authorized_digest}"
campus_link_marker_equals "${phase}" PERMIT_AUTHORIZER_SHA256 \
  "${expected_permit_authorizer_digest}"
campus_link_marker_equals "${phase}" RUN_ID "${run_id}"
before_digest=$(campus_link_marker_value "${phase}" BEFORE_INVOCATION_SHA256) || exit 1
stopped_challenge=$(campus_link_marker_value "${phase}" STOPPED_CHALLENGE) || exit 1
[[ ${before_digest} =~ ^[a-f0-9]{64}$ && ${stopped_challenge} =~ ^[a-f0-9]{64}$ ]]
phase_hold_ms=$(campus_link_marker_uint "${phase}" HOLD_MILLISECONDS) || exit 1
[[ ${phase_hold_ms} == 15000 ]]
campus_link_marker_equals "${phase}" STOPPED 1
assert_raw_phase_exact "${phase}" "${stopped_deadline_ms}"
campus_link_atomic_marker "${active_marker}" "${phase}"

release_deadline_ms=$(bounded_deadline 35000)
while [[ ! -e ${release_marker} && ! -L ${release_marker} ]]; do
  release_poll_ms=$(campus_link_monotonic_ms) || exit 1
  (( release_poll_ms < release_deadline_ms )) || {
    echo 'Relay restart release proof timed out.' >&2
    exit 1
  }
  relay_child_matches || {
    echo 'Authenticated relay restart ended before release.' >&2
    exit 1
  }
  sleep_bounded 50 "${release_deadline_ms}"
done
campus_link_validate_schema "${release_marker}" FORMAT RUN_ID RELEASE
campus_link_marker_equals "${release_marker}" FORMAT 1
campus_link_marker_equals "${release_marker}" RUN_ID "${run_id}"
campus_link_marker_equals "${release_marker}" RELEASE 1
printf 'FORMAT=1\nACTION=relay-restart-release\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nDEPLOYMENT_ATTESTATION_SHA256=%s\nPERMIT_KEY_SHA256=%s\nSESSION_SHA256=%s\nACTUATOR_SHA256=%s\nAUTHORIZED_COMMAND_SHA256=%s\nPERMIT_AUTHORIZER_SHA256=%s\nBEFORE_INVOCATION_SHA256=%s\nSTOPPED_CHALLENGE=%s\nHOLD_MILLISECONDS=15000\n' \
  "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${deployment_attestation_sha256}" "${permit_key_sha256}" "${session_sha256}" \
  "${expected_actuator_digest}" "${expected_authorized_digest}" \
  "${expected_permit_authorizer_digest}" "${before_digest}" \
  "${stopped_challenge}" > "${phase_payload}"
openssl pkeyutl -sign -inkey "${PERMIT_PRIVATE_KEY}" -rawin \
  -in "${phase_payload}" -out "${phase_signature}"
base64 -w 0 -- "${phase_signature}" > "${phase_signature_text}"
phase_signature_size=$(stat -c '%s' -- "${phase_signature}") || exit 1
phase_signature_text_size=$(stat -c '%s' -- "${phase_signature_text}") || exit 1
[[ ${phase_signature_size} -eq 64 && ${phase_signature_text_size} -eq 88 ]]
{ printf 'release %s %s ' "${run_id}" "${stopped_challenge}"; \
  cat -- "${phase_signature_text}"; printf '\n'; } > "${phase_command}"
phase_command_size=$(stat -c '%s' -- "${phase_command}") || exit 1
[[ ${phase_command_size} -eq 195 ]]
assert_raw_phase_exact "${phase}" "${release_deadline_ms}"
cat -- "${phase_command}" >&7

cat -- "${phase}" > "${ack}"
started_deadline_ms=$(bounded_deadline 45000)
for key in STARTED AFTER_INVOCATION_SHA256 RESTART_DURATION_MS ACTIVE \
  STARTED_CHALLENGE; do
  read_protocol_line line "${started_deadline_ms}" || {
    echo 'Authenticated relay restart started-phase proof failed.' >&2
    exit 1
  }
  printf '%s\n' "${line}" >> "${ack}"
done
campus_link_validate_schema "${ack}" \
  FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \
  PERMIT_AUTHORIZER_SHA256 RUN_ID BEFORE_INVOCATION_SHA256 \
  HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE STARTED \
  AFTER_INVOCATION_SHA256 RESTART_DURATION_MS ACTIVE STARTED_CHALLENGE
campus_link_marker_equals "${ack}" STARTED 1
campus_link_marker_equals "${ack}" ACTIVE 1
after_digest=$(campus_link_marker_value "${ack}" AFTER_INVOCATION_SHA256) || exit 1
started_challenge=$(campus_link_marker_value "${ack}" STARTED_CHALLENGE) || exit 1
restart_duration_ms=$(campus_link_marker_uint "${ack}" RESTART_DURATION_MS) || exit 1
[[ ${after_digest} =~ ^[a-f0-9]{64}$ && ${after_digest} != "${before_digest}" ]]
[[ ${started_challenge} =~ ^[a-f0-9]{64}$ ]]
(( restart_duration_ms >= 15000 && restart_duration_ms <= 120000 ))
assert_raw_phase_exact "${ack}" "${started_deadline_ms}"
campus_link_atomic_marker "${started_marker}" "${ack}"

commit_deadline_ms=$(bounded_deadline 70000)
while [[ ! -e ${commit_marker} && ! -L ${commit_marker} ]]; do
  commit_poll_ms=$(campus_link_monotonic_ms) || exit 1
  (( commit_poll_ms < commit_deadline_ms )) || {
    echo 'Relay restart commit proof timed out.' >&2
    exit 1
  }
  relay_child_matches || {
    echo 'Authenticated relay restart ended before commit.' >&2
    exit 1
  }
  sleep_bounded 50 "${commit_deadline_ms}"
done
campus_link_validate_schema "${commit_marker}" FORMAT RUN_ID COMMIT
campus_link_marker_equals "${commit_marker}" FORMAT 1
campus_link_marker_equals "${commit_marker}" RUN_ID "${run_id}"
campus_link_marker_equals "${commit_marker}" COMMIT 1
printf 'FORMAT=1\nACTION=relay-restart-commit\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nDEPLOYMENT_ATTESTATION_SHA256=%s\nPERMIT_KEY_SHA256=%s\nSESSION_SHA256=%s\nACTUATOR_SHA256=%s\nAUTHORIZED_COMMAND_SHA256=%s\nPERMIT_AUTHORIZER_SHA256=%s\nBEFORE_INVOCATION_SHA256=%s\nSTOPPED_CHALLENGE=%s\nAFTER_INVOCATION_SHA256=%s\nSTARTED_CHALLENGE=%s\nRESTART_DURATION_MS=%s\nACTIVE=1\n' \
  "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${deployment_attestation_sha256}" "${permit_key_sha256}" "${session_sha256}" \
  "${expected_actuator_digest}" "${expected_authorized_digest}" \
  "${expected_permit_authorizer_digest}" "${before_digest}" \
  "${stopped_challenge}" "${after_digest}" "${started_challenge}" \
  "${restart_duration_ms}" > "${phase_payload}"
openssl pkeyutl -sign -inkey "${PERMIT_PRIVATE_KEY}" -rawin \
  -in "${phase_payload}" -out "${phase_signature}"
base64 -w 0 -- "${phase_signature}" > "${phase_signature_text}"
phase_signature_size=$(stat -c '%s' -- "${phase_signature}") || exit 1
phase_signature_text_size=$(stat -c '%s' -- "${phase_signature_text}") || exit 1
[[ ${phase_signature_size} -eq 64 && ${phase_signature_text_size} -eq 88 ]]
{ printf 'commit %s %s ' "${run_id}" "${started_challenge}"; \
  cat -- "${phase_signature_text}"; printf '\n'; } > "${phase_command}"
phase_command_size=$(stat -c '%s' -- "${phase_command}") || exit 1
[[ ${phase_command_size} -eq 194 ]]
assert_raw_phase_exact "${ack}" "${commit_deadline_ms}"
cat -- "${phase_command}" >&7
exec 7>&-

final_deadline_ms=$(bounded_deadline 80000)
for key in STATUS COMMITTED SIGNED_RELEASE SIGNED_COMMIT \
  FINAL_INVOCATION_SHA256 NRESTARTS_DELTA COMMIT_STABILITY_MILLISECONDS; do
  read_protocol_line line "${final_deadline_ms}" || {
    echo 'Authenticated relay restart completion proof failed.' >&2
    exit 1
  }
  printf '%s\n' "${line}" >> "${ack}"
done
trailing_byte=
eof_deadline_ms=$(bounded_deadline 5000)
eof_now_ms=$(campus_link_monotonic_ms) || exit 1
(( eof_now_ms < eof_deadline_ms ))
eof_remaining_ms=$((eof_deadline_ms - eof_now_ms))
printf -v eof_duration '%d.%03d' $((eof_remaining_ms / 1000)) \
  $((eof_remaining_ms % 1000))
if IFS= read -r -t "${eof_duration}" -n 1 trailing_byte <&6; then
  echo 'Authenticated relay restart acknowledgement has trailing data.' >&2
  exit 1
else
  eof_status=$?
fi
(( eof_status == 1 ))
[[ -z ${trailing_byte} ]]
exec 6<&-
wait_child_until "${relay_ssh_pid}" "${relay_ssh_start_ticks}" \
  "${driver_deadline_ms}" relay_ssh_status || {
  echo 'Authenticated relay restart transport exceeded the driver deadline.' >&2
  exit 1
}
inspect_transport_group transport_group_state
case ${transport_group_state} in
  absent) ;;
  live)
    echo 'Authenticated relay restart transport left a live session group.' >&2
    exit 1
    ;;
  *)
    echo 'Authenticated relay restart transport group could not be inspected.' >&2
    exit 1
    ;;
esac
relay_ssh_pid=
relay_ssh_start_ticks=
transport_pgid=
transport_start_ticks=
(( relay_ssh_status == 0 )) || {
  echo 'Authenticated relay restart failed.' >&2
  exit 1
}

[[ ! -s ${ssh_error} ]]
raw_ack_size=$(stat -c '%s' -- "${raw_ack}") || exit 1
[[ ${raw_ack_size} -le 4096 ]]
cmp -s -- "${raw_ack}" "${ack}"
campus_link_validate_schema "${ack}" \
  FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \
  PERMIT_AUTHORIZER_SHA256 RUN_ID BEFORE_INVOCATION_SHA256 \
  HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE STARTED \
  AFTER_INVOCATION_SHA256 RESTART_DURATION_MS ACTIVE STARTED_CHALLENGE \
  STATUS COMMITTED SIGNED_RELEASE SIGNED_COMMIT FINAL_INVOCATION_SHA256 \
  NRESTARTS_DELTA COMMIT_STABILITY_MILLISECONDS
campus_link_marker_equals "${ack}" FORMAT 1
campus_link_marker_equals "${ack}" STATUS pass
campus_link_marker_equals "${ack}" ACTION relay-restart
campus_link_marker_equals "${ack}" ACTUATOR_SHA256 "${expected_actuator_digest}"
campus_link_marker_equals "${ack}" AUTHORIZED_COMMAND_SHA256 \
  "${expected_authorized_digest}"
campus_link_marker_equals "${ack}" PERMIT_AUTHORIZER_SHA256 \
  "${expected_permit_authorizer_digest}"
campus_link_marker_equals "${ack}" RUN_ID "${run_id}"
final_digest=$(campus_link_marker_value "${ack}" FINAL_INVOCATION_SHA256) || exit 1
[[ ${final_digest} == "${after_digest}" ]]
campus_link_marker_equals "${ack}" STOPPED 1
campus_link_marker_equals "${ack}" STARTED 1
campus_link_marker_equals "${ack}" ACTIVE 1
campus_link_marker_equals "${ack}" COMMITTED 1
campus_link_marker_equals "${ack}" SIGNED_RELEASE 1
campus_link_marker_equals "${ack}" SIGNED_COMMIT 1
ack_nrestarts_delta=$(campus_link_marker_uint "${ack}" NRESTARTS_DELTA) || exit 1
ack_stability_ms=$(campus_link_marker_uint \
  "${ack}" COMMIT_STABILITY_MILLISECONDS) || exit 1
[[ ${ack_nrestarts_delta} == 0 && ${ack_stability_ms} == 5000 ]]
cat -- "${ack}"
