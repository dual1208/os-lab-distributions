#!/usr/bin/env bash
set -euo pipefail

# The fixed driver is a separately installed, candidate-manifest-bound
# privileged component.  It owns credential snapshots, atomic replacements,
# remote relay coordination, and the continuous test stream.  This coordinator
# accepts only its sanitized transcript and never copies key material into /run.

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-production}
readonly RUN_DIR=/run/campus-link
readonly RUN_MANIFEST=${RUN_DIR}/qualification-run.manifest
readonly PREREQUISITE=${RUN_DIR}/fault-in-stream.result
readonly RESULT=${RUN_DIR}/certificate-rotation.result
readonly FAILURE=${RUN_DIR}/certificate-rotation.failure
readonly ACTIVE=${RUN_DIR}/certificate-rotation.active
readonly CLOSED=${RUN_DIR}/certificate-rotation.closed
readonly ROTATION_ROOT=/var/lib/campus-link/rotation
readonly ROTATION_MANIFEST=${ROTATION_ROOT}/manifest.json
readonly STAGE_MARKER=${ROTATION_ROOT}/stage.env
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
readonly SCRIPT_DIR

if [[ ${MODE} == production ]]; then
  [[ -z ${CAMPUS_LINK_ROTATION_DRIVER+x} && -z ${CAMPUS_LINK_ROTATION_VALIDATOR+x} &&
    -z ${CAMPUS_LINK_ROTATION_EVIDENCE_HELPER+x} ]] || {
    echo 'Production rotation forbids executable or evidence-helper overrides.' >&2
    exit 2
  }
  readonly DRIVER=/usr/local/libexec/campus-link-certificate-rotation-driver
  readonly VALIDATOR=/usr/local/libexec/campus-link-certificate-rotation-validate.py
  readonly EVIDENCE_HELPER=/usr/local/libexec/campus-link-gate-evidence
elif [[ ${MODE} == isolated-test ]]; then
  readonly DRIVER=${CAMPUS_LINK_ROTATION_DRIVER:?isolated test driver is required}
  readonly VALIDATOR=${CAMPUS_LINK_ROTATION_VALIDATOR:-${REPO_ROOT}/campus-link/tests/certificate_rotation_gate.py}
  readonly EVIDENCE_HELPER=${CAMPUS_LINK_ROTATION_EVIDENCE_HELPER:-${SCRIPT_DIR}/gate-evidence.sh}
else
  echo 'Rotation mode must be production or isolated-test.' >&2
  exit 2
fi

[[ ${EUID} -eq 0 ]]
[[ -f ${EVIDENCE_HELPER} && ! -L ${EVIDENCE_HELPER} ]]
[[ -x ${DRIVER} && ! -L ${DRIVER} ]]
[[ -f ${VALIDATOR} && ! -L ${VALIDATOR} ]]
# shellcheck source=gate-evidence.sh
source "${EVIDENCE_HELPER}"
umask 077

campus_link_acquire_deployment_shared_lock
campus_link_acquire_gate_execution_lock
campus_link_validate_chain "${RUN_MANIFEST}" fault-in-stream
campus_link_require_root_file "${ROTATION_MANIFEST}" 444
[[ -d ${ROTATION_ROOT} && ! -L ${ROTATION_ROOT} ]]
rotation_root_metadata=$(stat -c '%u:%g:%a' -- "${ROTATION_ROOT}") || exit 1
[[ ${rotation_root_metadata} == 0:0:700 ]]
python3 -B "${VALIDATOR}" validate-manifest --mode "${MODE}" \
  --manifest "${ROTATION_MANIFEST}"
[[ ! -e ${RESULT} && ! -L ${RESULT} && ! -e ${FAILURE} && ! -L ${FAILURE} ]]
if [[ -e ${ACTIVE} || -L ${ACTIVE} || -e ${CLOSED} || -L ${CLOSED} ]]; then
  echo 'A prior rotation transaction requires explicit recovery.' >&2
  exit 3
fi

run_id=$(campus_link_marker_value "${RUN_MANIFEST}" RUN_ID) || exit 1
candidate_sha256=$(campus_link_marker_value "${RUN_MANIFEST}" CANDIDATE_SHA256) || exit 1
run_manifest_sha256=$(campus_link_run_manifest_sha256 "${RUN_MANIFEST}") || exit 1
prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || exit 1
rotation_manifest_sha256=$(sha256sum -- "${ROTATION_MANIFEST}" | awk '{print $1}') || exit 1
rotation_id=$(openssl rand -hex 16) || exit 1
started_ms=$(campus_link_monotonic_ms) || exit 1
readonly run_id candidate_sha256 run_manifest_sha256 prerequisite_sha256
readonly rotation_manifest_sha256 rotation_id started_ms
[[ ${run_id} =~ ^[a-f0-9]{32}$ ]]
[[ ${candidate_sha256} =~ ^[a-f0-9]{64}$ ]]
[[ ${run_manifest_sha256} =~ ^[a-f0-9]{64}$ ]]
[[ ${prerequisite_sha256} =~ ^[a-f0-9]{64}$ ]]
[[ ${rotation_manifest_sha256} =~ ^[a-f0-9]{64}$ ]]
[[ ${rotation_id} =~ ^[a-f0-9]{32}$ ]]

work=$(mktemp -d "${RUN_DIR}/.certificate-rotation.${rotation_id}.XXXXXX") || exit 1
chmod 0700 "${work}"
readonly work
transcript=${work}/transcript.json
rollback_marker=${work}/rollback.json
pass_source=${work}/pass.env
active_source=${work}/active.env
failure_source=${work}/failure.env
rollback_required=0
rollback_verified=0
rollback_floor=none
transaction_succeeded=0
transaction_marker_path=${ACTIVE}

write_failure_marker() {
  local failed_ms=$1
  printf 'FORMAT=1\nSTATUS=fail\nGATE=certificate-rotation\nMODE=%s\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=%s\nROTATION_ID=%s\nROTATION_MANIFEST_SHA256=%s\nTRANSACTION_MARKER_SHA256=%s\nSTART_MONOTONIC_MS=%s\nFAILURE_MONOTONIC_MS=%s\nROLLBACK_REQUIRED=%s\nROLLBACK_FLOOR=%s\nROLLBACK_VERIFIED=%s\n' \
    "${MODE}" "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
    "${prerequisite_sha256}" "${rotation_id}" "${rotation_manifest_sha256}" \
    "${transaction_marker_sha256:-none}" "${started_ms}" "${failed_ms}" \
    "${rollback_required}" "${rollback_floor}" "${rollback_verified}" > "${failure_source}"
  chmod 0600 "${failure_source}"
  campus_link_validate_schema "${failure_source}" \
    FORMAT STATUS GATE MODE RUN_ID CANDIDATE_SHA256 RUN_MANIFEST_SHA256 \
    PREREQUISITE_MARKER_SHA256 ROTATION_ID ROTATION_MANIFEST_SHA256 \
    TRANSACTION_MARKER_SHA256 START_MONOTONIC_MS FAILURE_MONOTONIC_MS \
    ROLLBACK_REQUIRED ROLLBACK_FLOOR ROLLBACK_VERIFIED
  campus_link_atomic_marker "${FAILURE}" "${failure_source}"
}

validate_stage_marker() {
  local expected_state=${1:-} state
  campus_link_validate_schema "${STAGE_MARKER}" \
    FORMAT RUN_ID CANDIDATE_SHA256 ROTATION_ID ROTATION_MANIFEST_SHA256 STATE || return 1
  campus_link_marker_equals "${STAGE_MARKER}" FORMAT 1 || return 1
  campus_link_marker_equals "${STAGE_MARKER}" RUN_ID "${run_id}" || return 1
  campus_link_marker_equals "${STAGE_MARKER}" CANDIDATE_SHA256 \
    "${candidate_sha256}" || return 1
  campus_link_marker_equals "${STAGE_MARKER}" ROTATION_ID "${rotation_id}" || return 1
  campus_link_marker_equals "${STAGE_MARKER}" ROTATION_MANIFEST_SHA256 \
    "${rotation_manifest_sha256}" || return 1
  state=$(campus_link_marker_value "${STAGE_MARKER}" STATE) || return 1
  case ${state} in
    pre|overlap|relay-next|edge-a-next|edge-b-next|retiring|post|expiry|complete) ;;
    *) return 1 ;;
  esac
  [[ -z ${expected_state} || ${state} == "${expected_state}" ]]
}

select_rollback_floor() {
  local state=unknown
  if validate_stage_marker; then
    state=$(campus_link_marker_value "${STAGE_MARKER}" STATE) || state=unknown
  fi
  case ${state} in
    pre|overlap|relay-next|edge-a-next|edge-b-next) rollback_floor=pre-retirement ;;
    retiring|post|expiry|complete|*) rollback_floor=next-only ;;
  esac
}

cleanup() {
  local status=$? failed_ms rollback_now result_revoked=0
  trap - EXIT INT TERM
  if [[ ${transaction_succeeded} -eq 1 ]]; then
    rm -rf -- "${work}"
    exit 0
  fi
  set +e
  # A result published before CLOSED removal is provisional. Any subsequent
  # failure must revoke it regardless of rollback outcome.
  rm -f -- "${RESULT}"
  [[ ! -e ${RESULT} && ! -L ${RESULT} ]] && result_revoked=1
  failed_ms=$(campus_link_monotonic_ms)
  if [[ ${rollback_required} -eq 1 ]]; then
    select_rollback_floor
    rm -f -- "${rollback_marker}"
    timeout --signal=TERM --kill-after=10s 120s "${DRIVER}" rollback \
      --mode "${MODE}" \
      --run-id "${run_id}" \
      --candidate-sha256 "${candidate_sha256}" \
      --rotation-id "${rotation_id}" \
      --rotation-manifest "${ROTATION_MANIFEST}" \
      --rotation-manifest-sha256 "${rotation_manifest_sha256}" \
      --transaction-marker "${transaction_marker_path}" \
      --transaction-marker-sha256 "${transaction_marker_sha256:-none}" \
      --stage-marker "${STAGE_MARKER}" \
      --rollback-floor "${rollback_floor}" \
      --rollback-marker "${rollback_marker}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
      rollback_now=$(campus_link_monotonic_ms)
      if python3 -B "${VALIDATOR}" validate-rollback \
        --mode "${MODE}" \
        --run-id "${run_id}" \
        --candidate-sha256 "${candidate_sha256}" \
        --rotation-id "${rotation_id}" \
        --rotation-manifest-sha256 "${rotation_manifest_sha256}" \
        --transaction-marker-sha256 "${transaction_marker_sha256:-none}" \
        --now-monotonic-ms "${rollback_now}" \
        --rollback-floor "${rollback_floor}" \
        --marker "${rollback_marker}" >/dev/null 2>&1; then
        if [[ ${rollback_floor} == pre-retirement ]]; then
          validate_stage_marker overlap && rollback_verified=1
        else
          validate_stage_marker post && rollback_verified=1
        fi
      fi
    fi
  else
    rollback_verified=1
  fi
  if [[ ${rollback_verified} -eq 1 ]]; then
    rm -f -- "${ACTIVE}" "${CLOSED}"
  fi
  write_failure_marker "${failed_ms}" || true
  rm -rf -- "${work}"
  if [[ ${rollback_verified} -ne 1 || ${result_revoked} -ne 1 ]]; then
    exit 70
  fi
  [[ ${status} -ne 0 ]] && exit "${status}"
  exit 1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'FORMAT=1\nSTATUS=active\nGATE=certificate-rotation\nMODE=%s\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=%s\nROTATION_ID=%s\nROTATION_MANIFEST_SHA256=%s\nSTART_MONOTONIC_MS=%s\n' \
  "${MODE}" "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${prerequisite_sha256}" "${rotation_id}" "${rotation_manifest_sha256}" \
  "${started_ms}" > "${active_source}"
chmod 0600 "${active_source}"
campus_link_validate_schema "${active_source}" \
  FORMAT STATUS GATE MODE RUN_ID CANDIDATE_SHA256 RUN_MANIFEST_SHA256 \
  PREREQUISITE_MARKER_SHA256 ROTATION_ID ROTATION_MANIFEST_SHA256 \
  START_MONOTONIC_MS
campus_link_atomic_marker "${ACTIVE}" "${active_source}"
transaction_marker_sha256=$(sha256sum -- "${ACTIVE}" | awk '{print $1}') || exit 1
readonly transaction_marker_sha256
[[ ${transaction_marker_sha256} =~ ^[a-f0-9]{64}$ ]]

# prepare must validate the sealed state rows and atomically bind STAGE_MARKER
# before any credential, authorization, or service mutation.
timeout --signal=TERM --kill-after=10s 120s "${DRIVER}" prepare \
  --mode "${MODE}" \
  --run-id "${run_id}" \
  --candidate-sha256 "${candidate_sha256}" \
  --rotation-id "${rotation_id}" \
  --rotation-manifest "${ROTATION_MANIFEST}" \
  --rotation-manifest-sha256 "${rotation_manifest_sha256}" \
  --transaction-marker "${ACTIVE}" \
  --transaction-marker-sha256 "${transaction_marker_sha256}" \
  --stage-marker "${STAGE_MARKER}" >/dev/null 2>&1
validate_stage_marker pre
rollback_required=1

timeout --signal=TERM --kill-after=10s 1800s "${DRIVER}" execute \
  --mode "${MODE}" \
  --run-id "${run_id}" \
  --candidate-sha256 "${candidate_sha256}" \
  --rotation-id "${rotation_id}" \
  --rotation-manifest "${ROTATION_MANIFEST}" \
  --rotation-manifest-sha256 "${rotation_manifest_sha256}" \
  --transaction-marker "${ACTIVE}" \
  --transaction-marker-sha256 "${transaction_marker_sha256}" \
  --stage-marker "${STAGE_MARKER}" \
  --transcript "${transcript}" >/dev/null 2>&1
validate_stage_marker post

now_ms=$(campus_link_monotonic_ms) || exit 1
python3 -B "${VALIDATOR}" validate \
  --mode "${MODE}" \
  --run-id "${run_id}" \
  --candidate-sha256 "${candidate_sha256}" \
  --run-manifest-sha256 "${run_manifest_sha256}" \
  --prerequisite-marker-sha256 "${prerequisite_sha256}" \
  --rotation-id "${rotation_id}" \
  --rotation-manifest-sha256 "${rotation_manifest_sha256}" \
  --transaction-marker-sha256 "${transaction_marker_sha256}" \
  --start-monotonic-ms "${started_ms}" \
  --now-monotonic-ms "${now_ms}" \
  --transcript "${transcript}" \
  --output "${pass_source}"

campus_link_validate_gate_marker "${pass_source}" "${RUN_MANIFEST}" \
  certificate-rotation "${MODE}" \
  ROTATION_ID ROTATION_MANIFEST_SHA256 TRANSACTION_MARKER_SHA256 \
  CURRENT_NEXT_OVERLAP_CHECKS NEXT_SLOT_OBSERVATIONS \
  NEXT_OBSERVATIONS_INSIDE_TRANSACTION NEXT_OBSERVATIONS_OUTSIDE_TRANSACTION \
  SERVICE_RELOADS CONTROL_RECONNECTS DIRECT_RECONNECTS \
  MAX_APPLICATION_OUTAGE_MS STREAM_RECORDS_A_TO_B STREAM_RECORDS_B_TO_A \
  STREAM_DIGEST_DIRECTIONS OLD_PIN_REJECTIONS NEXT_PIN_ACCEPTANCES \
  EXPIRY_AUTHORITIES EXPIRY_VISIBILITY_CHECKS EXPIRED_RECONNECT_REJECTIONS \
  INSIDE_MARGIN_REJECTIONS NEXT_RESTORATIONS MAX_CUTOFF_OVERRUN_MS \
  ROLLBACK_SCENARIOS ROLLBACK_RESTORES
current_run_manifest_sha256=$(sha256sum -- "${RUN_MANIFEST}" | awk '{print $1}') || exit 1
current_prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || exit 1
current_rotation_manifest_sha256=$(sha256sum -- "${ROTATION_MANIFEST}" | awk '{print $1}') || exit 1
[[ ${current_run_manifest_sha256} == "${run_manifest_sha256}" ]]
[[ ${current_prerequisite_sha256} == "${prerequisite_sha256}" ]]
[[ ${current_rotation_manifest_sha256} == "${rotation_manifest_sha256}" ]]
campus_link_validate_run_manifest "${RUN_MANIFEST}"

# Renaming ACTIVE closes the sole interval in which a next-slot observation is
# meaningful while preserving the transaction record for rollback across the
# final marker publication. A stale CLOSED marker is never chain-valid.
mv -fT -- "${ACTIVE}" "${CLOSED}"
transaction_marker_path=${CLOSED}
campus_link_atomic_marker "${RESULT}" "${pass_source}"
rm -f -- "${CLOSED}"
transaction_succeeded=1
printf 'STATUS=pass GATE=certificate-rotation MODE=%s\n' "${MODE}"
