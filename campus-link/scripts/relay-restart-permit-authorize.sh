#!/bin/bash -p
set -euo pipefail
umask 077
ulimit -S -c 0
ulimit -H -c 0
soft_core_limit=$(ulimit -S -c) || exit 1
hard_core_limit=$(ulimit -H -c) || exit 1
[[ ${soft_core_limit} == 0 && ${hard_core_limit} == 0 ]]

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

readonly AUTHORIZER=/usr/local/libexec/campus-link-relay-restart-permit-authorize
readonly PERMIT_PUBLIC_KEY=/etc/ssh/campus-link-relay-fault-permit-ed25519.pub.pem
readonly DEPLOYMENT_ATTESTATION=/var/lib/campus-link/deployment-attestation.env
readonly RUNTIME_DIR=/run/campus-link-relay-fault
readonly STATE_DIR=/var/lib/campus-link-relay-fault
readonly USED_DIR=${STATE_DIR}/used
readonly EXPECTED_PERMIT=${STATE_DIR}/expected-run.env
readonly PERMIT_LIFETIME_SECONDS=600
readonly MAX_USED_RUNS=4096
readonly MAX_ENVELOPE_BYTES=2048
readonly ENVELOPE_TIMEOUT_SECONDS=15

[[ ${EUID} -eq 0 ]]
[[ ${BASH_SOURCE[0]} == "${AUTHORIZER}" ]]
[[ $# -eq 0 ]]
[[ ! -t 0 && ! -t 1 && ! -t 2 ]]

require_root_file() {
  local path=$1 mode=$2 metadata
  [[ -f ${path} && ! -L ${path} ]] || return 1
  metadata=$(stat -c '%u:%g:%a:%h' -- "${path}") || return 1
  [[ ${metadata} == "0:0:${mode}:1" ]] || \
    return 1
  return 0
}

require_root_dir() {
  local path=$1 mode=$2 metadata
  [[ -d ${path} && ! -L ${path} ]] || return 1
  metadata=$(stat -c '%u:%g:%a' -- "${path}") || return 1
  [[ ${metadata} == "0:0:${mode}" ]] || return 1
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

validate_expected_record() {
  local path=$1
  mapfile -t old_lines < "${path}" || return 1
  [[ ${#old_lines[@]} -eq 13 ]]
  [[ ${old_lines[0]} == FORMAT=1 ]]
  [[ ${old_lines[1]} == STATUS=expected ]]
  [[ ${old_lines[2]} == ACTION=relay-restart ]]
  [[ ${old_lines[3]} =~ ^RUN_ID=([a-f0-9]{32})$ ]]
  old_run_id=${BASH_REMATCH[1]}
  [[ ${old_lines[4]} =~ ^CANDIDATE_SHA256=([a-f0-9]{64})$ ]]
  old_candidate_sha256=${BASH_REMATCH[1]}
  [[ ${old_lines[5]} =~ ^RUN_MANIFEST_SHA256=([a-f0-9]{64})$ ]]
  old_run_manifest_sha256=${BASH_REMATCH[1]}
  [[ ${old_lines[6]} =~ ^DEPLOYMENT_ATTESTATION_SHA256=([a-f0-9]{64})$ ]]
  old_deployment_sha256=${BASH_REMATCH[1]}
  [[ ${old_lines[7]} =~ ^PERMIT_KEY_SHA256=([a-f0-9]{64})$ ]]
  old_permit_key_sha256=${BASH_REMATCH[1]}
  [[ ${old_lines[8]} =~ ^SESSION_SHA256=([a-f0-9]{64})$ ]]
  old_session_sha256=${BASH_REMATCH[1]}
  [[ ${old_lines[9]} =~ ^ISSUED_UNIX=([1-9][0-9]{9,10})$ ]]
  old_issued_unix=${BASH_REMATCH[1]}
  [[ ${old_lines[10]} =~ ^NOT_AFTER_UNIX=([1-9][0-9]{9,10})$ ]]
  old_not_after_unix=${BASH_REMATCH[1]}
  [[ ${old_lines[11]} =~ ^PERMIT_SHA256=([a-f0-9]{64})$ ]]
  old_permit_sha256=${BASH_REMATCH[1]}
  [[ ${old_lines[12]} =~ ^PERMIT_AUTHORIZER_SHA256=([a-f0-9]{64})$ ]]
  old_authorizer_sha256=${BASH_REMATCH[1]}
}

require_root_file "${AUTHORIZER}" 755
require_root_file "${PERMIT_PUBLIC_KEY}" 600
require_root_file "${DEPLOYMENT_ATTESTATION}" 600
permit_key_type=$(openssl pkey -pubin -in "${PERMIT_PUBLIC_KEY}" \
  -text_pub -noout 2>/dev/null | sed -n '1p') || exit 1
[[ ${permit_key_type} == 'ED25519 Public-Key:' ]]
authorizer_sha256=$(sha256sum -- "${AUTHORIZER}" | awk '{print $1}') || exit 1
local_deployment_sha256=$(sha256sum -- "${DEPLOYMENT_ATTESTATION}" | awk '{print $1}') || exit 1
local_permit_key_sha256=$(sha256sum -- "${PERMIT_PUBLIC_KEY}" | awk '{print $1}') || exit 1
for digest in "${authorizer_sha256}" "${local_deployment_sha256}" \
  "${local_permit_key_sha256}"; do
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]]
done

for directory in "${RUNTIME_DIR}" "${STATE_DIR}" "${USED_DIR}"; do
  [[ ! -L ${directory} ]]
done
install -d -m 0700 -o root -g root "${RUNTIME_DIR}" "${STATE_DIR}" "${USED_DIR}"
require_root_dir "${RUNTIME_DIR}" 700
require_root_dir "${STATE_DIR}" 700
require_root_dir "${USED_DIR}" 700

raw_envelope=$(mktemp "${STATE_DIR}/.permit-envelope.XXXXXX")
canonical_envelope=$(mktemp "${STATE_DIR}/.permit-canonical.XXXXXX")
payload=$(mktemp "${STATE_DIR}/.permit-payload.XXXXXX")
signature_text=$(mktemp "${STATE_DIR}/.permit-signature-text.XXXXXX")
signature=$(mktemp "${STATE_DIR}/.permit-signature.XXXXXX")
signature_canonical=$(mktemp "${STATE_DIR}/.permit-signature-canonical.XXXXXX")
expected_source=$(mktemp "${STATE_DIR}/.expected-run.XXXXXX")
ack_source=$(mktemp "${STATE_DIR}/.permit-ack.XXXXXX")
cleanup() {
  rm -f -- "${raw_envelope:-}" "${canonical_envelope:-}" "${payload:-}" \
    "${signature_text:-}" "${signature:-}" "${signature_canonical:-}" \
    "${expected_source:-}" "${expected_source:-}.installed" "${ack_source:-}"
}
trap cleanup EXIT

# One full-block read retains partial/NUL input and terminates only at EOF,
# the hard byte cap, or the single absolute timeout.  Any cap-sized input is
# oversized because a valid envelope is substantially smaller.
timeout --signal=TERM --kill-after=2s "${ENVELOPE_TIMEOUT_SECONDS}s" \
  dd iflag=fullblock bs=$((MAX_ENVELOPE_BYTES + 1)) count=1 status=none \
  > "${raw_envelope}"
raw_size=$(stat -c '%s' -- "${raw_envelope}") || exit 1
(( raw_size > 0 && raw_size <= MAX_ENVELOPE_BYTES ))
mapfile -t envelope_lines < "${raw_envelope}" || exit 1
[[ ${#envelope_lines[@]} -eq 11 ]]
[[ ${envelope_lines[0]} == FORMAT=1 ]]
[[ ${envelope_lines[1]} == ACTION=relay-restart-permit ]]
[[ ${envelope_lines[2]} =~ ^RUN_ID=([a-f0-9]{32})$ ]]
readonly run_id=${BASH_REMATCH[1]}
[[ ${envelope_lines[3]} =~ ^CANDIDATE_SHA256=([a-f0-9]{64})$ ]]
readonly candidate_sha256=${BASH_REMATCH[1]}
[[ ${envelope_lines[4]} =~ ^RUN_MANIFEST_SHA256=([a-f0-9]{64})$ ]]
readonly run_manifest_sha256=${BASH_REMATCH[1]}
[[ ${envelope_lines[5]} =~ ^DEPLOYMENT_ATTESTATION_SHA256=([a-f0-9]{64})$ ]]
readonly deployment_attestation_sha256=${BASH_REMATCH[1]}
[[ ${envelope_lines[6]} =~ ^PERMIT_KEY_SHA256=([a-f0-9]{64})$ ]]
readonly permit_key_sha256=${BASH_REMATCH[1]}
[[ ${envelope_lines[7]} =~ ^SESSION_SHA256=([a-f0-9]{64})$ ]]
readonly session_sha256=${BASH_REMATCH[1]}
[[ ${envelope_lines[8]} =~ ^ISSUED_UNIX=([1-9][0-9]{9,10})$ ]]
readonly issued_unix=${BASH_REMATCH[1]}
[[ ${envelope_lines[9]} =~ ^NOT_AFTER_UNIX=([1-9][0-9]{9,10})$ ]]
readonly not_after_unix=${BASH_REMATCH[1]}
[[ ${envelope_lines[10]} =~ ^SIGNATURE_BASE64=([A-Za-z0-9+/]{86}==)$ ]]
readonly signature_base64=${BASH_REMATCH[1]}
(( not_after_unix - issued_unix == PERMIT_LIFETIME_SECONDS ))
[[ ${deployment_attestation_sha256} == "${local_deployment_sha256}" ]]
[[ ${permit_key_sha256} == "${local_permit_key_sha256}" ]]

printf 'FORMAT=1\nACTION=relay-restart-permit\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nDEPLOYMENT_ATTESTATION_SHA256=%s\nPERMIT_KEY_SHA256=%s\nSESSION_SHA256=%s\nISSUED_UNIX=%s\nNOT_AFTER_UNIX=%s\n' \
  "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${deployment_attestation_sha256}" "${permit_key_sha256}" \
  "${session_sha256}" "${issued_unix}" "${not_after_unix}" > "${payload}"
{ cat -- "${payload}"; printf 'SIGNATURE_BASE64=%s\n' "${signature_base64}"; } \
  > "${canonical_envelope}"
cmp -s -- "${raw_envelope}" "${canonical_envelope}"
printf '%s' "${signature_base64}" > "${signature_text}"
base64 -d -- "${signature_text}" > "${signature}"
signature_size=$(stat -c '%s' -- "${signature}") || exit 1
[[ ${signature_size} -eq 64 ]]
base64 -w 0 -- "${signature}" > "${signature_canonical}"
cmp -s -- "${signature_text}" "${signature_canonical}"
openssl pkeyutl -verify -pubin -inkey "${PERMIT_PUBLIC_KEY}" -rawin \
  -in "${payload}" -sigfile "${signature}" >/dev/null
permit_sha256=$({ cat -- "${payload}"; cat -- "${signature}"; } | sha256sum | awk '{print $1}') || exit 1
[[ ${permit_sha256} =~ ^[a-f0-9]{64}$ ]]

# Slow/untrusted stdin and cryptographic verification occur before the shared
# mutation lock, so possession of only the SSH transport key cannot hold that
# lock by opening an idle permit channel.  Recheck every mutable local binding
# after the lock is acquired and immediately before state mutation.
exec 9<>"${RUNTIME_DIR}/actuator.lock"
flock -n 9
lock_metadata=$(stat -c '%u:%g:%a:%h' -- "${RUNTIME_DIR}/actuator.lock") || exit 1
[[ ${lock_metadata} == 0:0:600:1 ]]
require_root_file "${PERMIT_PUBLIC_KEY}" 600
require_root_file "${DEPLOYMENT_ATTESTATION}" 600
current_permit_key_sha256=$(sha256sum -- "${PERMIT_PUBLIC_KEY}" | awk '{print $1}') || exit 1
current_deployment_sha256=$(sha256sum -- "${DEPLOYMENT_ATTESTATION}" | awk '{print $1}') || exit 1
[[ ${current_permit_key_sha256} == "${local_permit_key_sha256}" ]]
[[ ${current_deployment_sha256} == "${local_deployment_sha256}" ]]

now_unix=$(date +%s) || exit 1
[[ ${now_unix} =~ ^[1-9][0-9]{9,10}$ ]]
(( issued_unix <= now_unix + 30 && now_unix <= not_after_unix ))
readonly used_marker=${USED_DIR}/${run_id}
[[ ! -e ${used_marker} && ! -L ${used_marker} ]]
used_count=$(validate_used_ledger) || exit 1
(( used_count < MAX_USED_RUNS ))

idempotent=0
if [[ -e ${EXPECTED_PERMIT} || -L ${EXPECTED_PERMIT} ]]; then
  require_root_file "${EXPECTED_PERMIT}" 600
  validate_expected_record "${EXPECTED_PERMIT}"
  if [[ ${old_run_id} == "${run_id}" ]]; then
    if (( issued_unix == old_issued_unix )); then
      [[ ${old_candidate_sha256} == "${candidate_sha256}" ]]
      [[ ${old_run_manifest_sha256} == "${run_manifest_sha256}" ]]
      [[ ${old_deployment_sha256} == "${deployment_attestation_sha256}" ]]
      [[ ${old_permit_key_sha256} == "${permit_key_sha256}" ]]
      [[ ${old_session_sha256} == "${session_sha256}" ]]
      [[ ${old_not_after_unix} == "${not_after_unix}" ]]
      [[ ${old_permit_sha256} == "${permit_sha256}" ]]
      [[ ${old_authorizer_sha256} == "${authorizer_sha256}" ]]
      idempotent=1
    else
      (( issued_unix > old_issued_unix ))
    fi
  else
    (( issued_unix > old_issued_unix ))
    (( used_count + 1 < MAX_USED_RUNS ))
    old_used_marker=${USED_DIR}/${old_run_id}
    [[ ! -e ${old_used_marker} && ! -L ${old_used_marker} ]]
    mv -T -- "${EXPECTED_PERMIT}" "${old_used_marker}"
    sync -f -- "${STATE_DIR}"
  fi
fi

if (( idempotent == 0 )); then
  printf 'FORMAT=1\nSTATUS=expected\nACTION=relay-restart\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nDEPLOYMENT_ATTESTATION_SHA256=%s\nPERMIT_KEY_SHA256=%s\nSESSION_SHA256=%s\nISSUED_UNIX=%s\nNOT_AFTER_UNIX=%s\nPERMIT_SHA256=%s\nPERMIT_AUTHORIZER_SHA256=%s\n' \
    "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
    "${deployment_attestation_sha256}" "${permit_key_sha256}" \
    "${session_sha256}" "${issued_unix}" "${not_after_unix}" \
    "${permit_sha256}" "${authorizer_sha256}" > "${expected_source}"
  install -m 0600 -o root -g root "${expected_source}" "${expected_source}.installed"
  sync -f -- "${expected_source}.installed"
  mv -fT -- "${expected_source}.installed" "${EXPECTED_PERMIT}"
  sync -f -- "${STATE_DIR}"
fi

printf 'FORMAT=1\nSTATUS=pass\nACTION=relay-restart-permit\nPERMIT_AUTHORIZER_SHA256=%s\nRUN_ID=%s\nPERMIT_SHA256=%s\nNOT_AFTER_UNIX=%s\nSESSION_BOUND=1\n' \
  "${authorizer_sha256}" "${run_id}" "${permit_sha256}" \
  "${not_after_unix}" > "${ack_source}"
cat -- "${ack_source}"
