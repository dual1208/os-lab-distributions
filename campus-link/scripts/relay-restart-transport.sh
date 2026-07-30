#!/bin/bash -p
set -euo pipefail
umask 077

[[ $- == *p* ]]
[[ -z ${BASH_ENV+x} && -z ${ENV+x} ]]
[[ -z ${LD_PRELOAD+x} && -z ${LD_LIBRARY_PATH+x} && -z ${LD_AUDIT+x} ]]
[[ -z ${OPENSSL_CONF+x} && -z ${OPENSSL_MODULES+x} && -z ${OPENSSL_ENGINES+x} ]]
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
HOME=/nonexistent
IFS=$' \t\n'
readonly PATH LC_ALL HOME IFS
export PATH LC_ALL HOME
ulimit -S -c 0
ulimit -H -c 0

readonly TRANSPORT=/usr/local/libexec/campus-link-relay-restart-transport
readonly PRIVATE_KEY=/etc/campus-link/relay-fault/id_ed25519
readonly KNOWN_HOSTS=/etc/campus-link/relay-fault/known_hosts
readonly TRANSPORT_TIMEOUT_SECONDS=260
readonly TRANSPORT_OPERATION_TIMEOUT_SECONDS=250
readonly SSH_TIMEOUT_SECONDS=235
readonly SSH_KILL_GRACE_SECONDS=5
readonly CHILD_REAP_GRACE_MILLISECONDS=5000
readonly CHILD_TERM_GRACE_MILLISECONDS=2500
(( 6 + SSH_TIMEOUT_SECONDS + SSH_KILL_GRACE_SECONDS < \
  TRANSPORT_OPERATION_TIMEOUT_SECONDS ))
(( TRANSPORT_OPERATION_TIMEOUT_SECONDS + \
  CHILD_REAP_GRACE_MILLISECONDS / 1000 < TRANSPORT_TIMEOUT_SECONDS ))
(( CHILD_TERM_GRACE_MILLISECONDS < CHILD_REAP_GRACE_MILLISECONDS ))

[[ ${EUID} -eq 0 ]]
[[ $# -eq 6 ]]
readonly pgid_marker=$1
readonly raw_ack=$2
readonly ssh_error=$3
readonly private_key=$4
readonly known_hosts=$5
readonly target=$6
[[ ${BASH_SOURCE[0]} == "${TRANSPORT}" ]]
[[ ${private_key} == "${PRIVATE_KEY}" && ${known_hosts} == "${KNOWN_HOSTS}" ]]
[[ ${target} =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$ ]]
for path in "${pgid_marker}" "${raw_ack}" "${ssh_error}"; do
  [[ ${path} =~ ^/run/campus-link/\.relay-restart-[a-z-]+\.[A-Za-z0-9]+$ ]]
  [[ -f ${path} && ! -L ${path} ]]
  path_metadata=$(stat -c '%u:%g:%a:%h' -- "${path}") || exit 1
  [[ ${path_metadata} == 0:0:600:1 ]]
done
for path in "${PRIVATE_KEY}" "${KNOWN_HOSTS}"; do
  [[ -f ${path} && ! -L ${path} ]]
  path_metadata=$(stat -c '%u:%g:%a:%h' -- "${path}") || exit 1
  [[ ${path_metadata} == 0:0:600:1 ]]
done

process_pid=${BASHPID}
process_pgid=$(ps -o pgid= -p "${process_pid}" | tr -d '[:space:]') || exit 1
process_sid=$(ps -o sid= -p "${process_pid}" | tr -d '[:space:]') || exit 1
[[ ${process_pid} =~ ^[1-9][0-9]*$ ]]
[[ ${process_pgid} == "${process_pid}" && ${process_sid} == "${process_pid}" ]]

monotonic_ms() {
  local uptime whole fraction
  read -r uptime _ < /proc/uptime || return 1
  [[ ${uptime} =~ ^([0-9]+)\.([0-9]+)$ ]] || return 1
  whole=${BASH_REMATCH[1]}
  fraction=${BASH_REMATCH[2]}000
  fraction=${fraction:0:3}
  printf '%s\n' "$((10#${whole} * 1000 + 10#${fraction}))"
}

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

session_member_snapshot() {
  local pid=$1 path line rest state pgid sid start_ticks
  local -a fields=()
  [[ ${pid} =~ ^[1-9][0-9]*$ && ${pid} != "${process_pid}" ]] || return 2
  path=/proc/${pid}/stat
  [[ -e ${path} ]] || return 1
  [[ -r ${path} ]] || return 2
  if ! IFS= read -r line < "${path}"; then
    [[ ! -e ${path} ]] && return 1
    return 2
  fi
  rest=${line##*) }
  [[ ${rest} != "${line}" ]] || return 2
  read -r -a fields <<< "${rest}" || return 2
  (( ${#fields[@]} >= 20 )) || return 2
  state=${fields[0]}
  pgid=${fields[2]}
  sid=${fields[3]}
  start_ticks=${fields[19]}
  [[ ${state} =~ ^[A-Z]$ && ${pgid} =~ ^[1-9][0-9]*$ && \
    ${sid} =~ ^[1-9][0-9]*$ && ${start_ticks} =~ ^[1-9][0-9]*$ ]] || return 2
  [[ ${sid} == "${process_sid}" ]] || return 2
  printf '%s %s\n' "${start_ticks}" "${state}"
}

inspect_session_member_identity() {
  local pid=$1 expected_start_ticks=$2 destination=$3
  local path line rest outcome state sid start_ticks
  local -a fields=()
  outcome=inspection-error
  if [[ ${pid} =~ ^[1-9][0-9]*$ && ${pid} != "${process_pid}" && \
    ${expected_start_ticks} =~ ^[1-9][0-9]*$ ]]; then
    path=/proc/${pid}/stat
    if [[ ! -e ${path} ]]; then
      outcome=gone
    elif [[ -r ${path} ]]; then
      if IFS= read -r line < "${path}"; then
        rest=${line##*) }
        if [[ ${rest} != "${line}" ]]; then
          read -r -a fields <<< "${rest}" || fields=()
          if (( ${#fields[@]} >= 20 )); then
            state=${fields[0]}
            sid=${fields[3]}
            start_ticks=${fields[19]}
            if [[ ${state} =~ ^[A-Z]$ && ${sid} =~ ^[1-9][0-9]*$ && \
              ${start_ticks} =~ ^[1-9][0-9]*$ ]]; then
              if [[ ${start_ticks} != "${expected_start_ticks}" ]]; then
                outcome=identity-mismatch
              elif [[ ${sid} != "${process_sid}" ]]; then
                outcome=escaped
              elif [[ ${state} == Z ]]; then
                outcome=zombie
              else
                outcome=live
              fi
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

child_matches() {
  local pid=$1 start_ticks=$2 state
  [[ ${pid} =~ ^[1-9][0-9]*$ && ${start_ticks} =~ ^[1-9][0-9]*$ ]] || return 1
  inspect_process_identity "${pid}" "${start_ticks}" state
  [[ ${state} == live ]]
}

signal_session_members() {
  local signal=$1 pid sid extra members invalid=0 snapshot snapshot_status
  local start_ticks snapshot_state member_state
  members=$(ps -eo pid=,sid=) || return 2
  while read -r pid sid extra; do
    [[ -n ${pid}${sid}${extra} ]] || continue
    if [[ ! ${pid} =~ ^[1-9][0-9]*$ || ! ${sid} =~ ^[1-9][0-9]*$ || \
      -n ${extra} ]]; then
      invalid=1
      continue
    fi
    if [[ ${pid} != "${process_pid}" && ${sid} == "${process_sid}" ]]; then
      if snapshot=$(session_member_snapshot "${pid}"); then
        read -r start_ticks snapshot_state extra <<< "${snapshot}" || {
          invalid=1
          continue
        }
        if [[ ! ${start_ticks} =~ ^[1-9][0-9]*$ || \
          ! ${snapshot_state} =~ ^[A-Z]$ || -n ${extra} ]]; then
          invalid=1
          continue
        fi
        inspect_session_member_identity "${pid}" "${start_ticks}" member_state
        case ${member_state} in
          live) kill "-${signal}" "${pid}" 2>/dev/null || invalid=1 ;;
          zombie|gone) ;;
          *) invalid=1 ;;
        esac
      else
        snapshot_status=$?
        (( snapshot_status == 1 )) || invalid=1
      fi
    fi
  done <<< "${members}"
  (( invalid == 0 )) || return 2
  return 0
}

inspect_session_members() {
  local destination=$1 members status state
  if ! members=$(ps -eo pid=,sid=); then
    printf -v "${destination}" '%s' inspection-error
    return 0
  fi
  if awk -v self="${process_pid}" -v expected_sid="${process_sid}" '
      NF == 0 { next }
      NF != 2 || $1 !~ /^[1-9][0-9]*$/ || $2 !~ /^[1-9][0-9]*$/ {
        invalid=1; next
      }
      $1 != self && $2 == expected_sid { found=1 }
      END {
        if (invalid) exit 2
        exit(found ? 0 : 1)
      }
    ' <<< "${members}"; then
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
  local now_ms state status
  while :; do
    now_ms=$(monotonic_ms) || return 1
    (( now_ms < deadline_ms )) || return 124
    inspect_process_identity "${pid}" "${start_ticks}" state
    case ${state} in
      live) sleep 0.05 ;;
      zombie|gone) break ;;
      *) return 125 ;;
    esac
  done
  now_ms=$(monotonic_ms) || return 1
  (( now_ms < deadline_ms )) || return 124
  if wait "${pid}"; then
    status=0
  else
    status=$?
  fi
  printf -v "${destination}" '%s' "${status}"
  return 0
}

terminate_children() {
  local cleanup_started_ms cleanup_deadline_ms kill_at_ms now_ms
  local pid index child_state session_state ignored_status
  local kill_sent=0 cleanup_ok=1 all_reaped
  cleanup_started_ms=$(monotonic_ms) || return 1
  cleanup_deadline_ms=$((cleanup_started_ms + CHILD_REAP_GRACE_MILLISECONDS))
  kill_at_ms=$((cleanup_started_ms + CHILD_TERM_GRACE_MILLISECONDS))
  signal_session_members TERM || cleanup_ok=0
  for index in "${!child_pids[@]}"; do
    pid=${child_pids[index]}
    [[ -n ${pid} ]] || continue
    inspect_process_identity "${pid}" "${child_start_ticks[index]:-}" child_state
    case ${child_state} in
      live)
        inspect_session_member_identity "${pid}" \
          "${child_start_ticks[index]:-}" child_state
        case ${child_state} in
          live) kill -TERM "${pid}" 2>/dev/null || cleanup_ok=0 ;;
          zombie|gone) ;;
          *) cleanup_ok=0 ;;
        esac
        ;;
      zombie|gone) ;;
      *) cleanup_ok=0 ;;
    esac
  done

  while :; do
    now_ms=$(monotonic_ms) || { cleanup_ok=0; break; }
    (( now_ms < cleanup_deadline_ms )) || break
    all_reaped=1
    for index in "${!child_pids[@]}"; do
      pid=${child_pids[index]}
      [[ -n ${pid} ]] || continue
      all_reaped=0
      inspect_process_identity "${pid}" "${child_start_ticks[index]:-}" child_state
      case ${child_state} in
        live) ;;
        zombie|gone)
          now_ms=$(monotonic_ms) || { cleanup_ok=0; break 2; }
          (( now_ms < cleanup_deadline_ms )) || break 2
          wait "${pid}" 2>/dev/null || ignored_status=$?
          child_pids[index]=
          child_start_ticks[index]=
          ;;
        *) cleanup_ok=0 ;;
      esac
    done
    inspect_session_members session_state
    [[ ${session_state} != inspection-error ]] || cleanup_ok=0
    if (( all_reaped != 0 )) && [[ ${session_state} == absent ]]; then
      break
    fi

    if (( kill_sent == 0 && now_ms >= kill_at_ms )); then
      signal_session_members KILL || cleanup_ok=0
      for index in "${!child_pids[@]}"; do
        pid=${child_pids[index]}
        [[ -n ${pid} ]] || continue
        inspect_process_identity "${pid}" "${child_start_ticks[index]:-}" child_state
        case ${child_state} in
          live)
            inspect_session_member_identity "${pid}" \
              "${child_start_ticks[index]:-}" child_state
            case ${child_state} in
              live) kill -KILL "${pid}" 2>/dev/null || cleanup_ok=0 ;;
              zombie|gone) ;;
              *) cleanup_ok=0 ;;
            esac
            ;;
          zombie|gone) ;;
          *) cleanup_ok=0 ;;
        esac
      done
      kill_sent=1
    fi
    sleep 0.05
  done

  all_reaped=1
  for pid in "${child_pids[@]}"; do
    [[ -z ${pid} ]] || all_reaped=0
  done
  inspect_session_members session_state
  child_pids=()
  child_start_ticks=()
  (( all_reaped != 0 && cleanup_ok != 0 )) && [[ ${session_state} == absent ]]
}

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT HUP INT TERM
  set +e
  terminate_children || cleanup_status=$?
  if (( status == 0 && cleanup_status != 0 )); then
    status=${cleanup_status}
  fi
  rm -f -- "${transport_fifo:-}" "${launch_frame:-}" "${launch_expected:-}"
  exit "${status}"
}

child_pids=()
child_start_ticks=()
transport_fifo=${raw_ack}.pipe
launch_frame=${raw_ack}.launch
launch_expected=${raw_ack}.launch-expected
for path in "${transport_fifo}" "${launch_frame}" "${launch_expected}"; do
  [[ ! -e ${path} && ! -L ${path} ]]
done
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
transport_started_ms=$(monotonic_ms) || exit 1
transport_operation_deadline_ms=$((transport_started_ms + \
  TRANSPORT_OPERATION_TIMEOUT_SECONDS * 1000))

# The marker is published before any network child can exist.  The driver must
# validate group ownership and return this exact start frame before ssh starts.
printf '%s\n' "${process_pgid}" > "${pgid_marker}"
: > "${launch_frame}"
printf 'START\n' > "${launch_expected}"
timeout --foreground --signal=TERM --kill-after=1s 5s \
  dd iflag=fullblock bs=6 count=1 status=none > "${launch_frame}"
cmp -s -- "${launch_frame}" "${launch_expected}"

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

ulimit -f 8 || exit 125
file_limit=$(ulimit -f) || exit 125
[[ ${file_limit} == 8 ]] || exit 125
mkfifo -m 0600 -- "${transport_fifo}"
[[ -p ${transport_fifo} && ! -L ${transport_fifo} ]]
tee -- "${raw_ack}" < "${transport_fifo}" &
tee_pid=$!
child_pids+=("${tee_pid}")
tee_start_ticks=$(process_start_ticks "${tee_pid}") || exit 1
child_start_ticks+=("${tee_start_ticks}")
timeout --foreground --signal=TERM --kill-after="${SSH_KILL_GRACE_SECONDS}s" \
  "${SSH_TIMEOUT_SECONDS}s" ssh "${SSH_OPTIONS[@]}" -- \
  "campus-link-fault@${target}" restart > "${transport_fifo}" 2> "${ssh_error}" &
ssh_timeout_pid=$!
child_pids+=("${ssh_timeout_pid}")
ssh_start_ticks=$(process_start_ticks "${ssh_timeout_pid}") || exit 1
child_start_ticks+=("${ssh_start_ticks}")

wait_child_until "${ssh_timeout_pid}" "${child_start_ticks[1]}" \
  "${transport_operation_deadline_ms}" ssh_status
child_pids=("${tee_pid}")
child_start_ticks=("${child_start_ticks[0]}")
wait_child_until "${tee_pid}" "${child_start_ticks[0]}" \
  "${transport_operation_deadline_ms}" tee_status
child_pids=()
child_start_ticks=()
(( ssh_status == 0 && tee_status == 0 ))
