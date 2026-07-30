#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly DURATION=${2:-3600}
readonly RESULT=/run/campus-link/accelerated-fault-soak.result
readonly PREREQUISITE=/run/campus-link/a11-b22-full.result
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
readonly SCRIPT_DIR
if [[ -f ${SCRIPT_DIR}/campus-link-gate-evidence ]]; then
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/campus-link-gate-evidence
else
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/gate-evidence.sh
fi
if [[ -x /usr/local/libexec/campus-link-test-edge-recovery ]]; then
  readonly EDGE_RECOVERY=/usr/local/libexec/campus-link-test-edge-recovery
else
  readonly EDGE_RECOVERY=${SCRIPT_DIR}/test-edge-recovery.sh
fi

[[ ${EUID} -eq 0 ]]
[[ ${DURATION} =~ ^[0-9]+$ && ${DURATION} -ge 3600 ]]
[[ -f ${EVIDENCE_HELPER} && ! -L ${EVIDENCE_HELPER} ]]
[[ -x ${EDGE_RECOVERY} && ! -L ${EDGE_RECOVERY} ]]
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
campus_link_validate_chain "${run_manifest}" full
prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || exit 1
[[ ${prerequisite_sha256} =~ ^[a-f0-9]{64}$ ]]
started_ms=$(campus_link_monotonic_ms) || exit 1
prerequisite_completed_ms=$(campus_link_marker_value "${PREREQUISITE}" COMPLETE_MONOTONIC_MS) || exit 1
(( started_ms >= prerequisite_completed_ms ))
campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
rm -f -- "${RESULT}"

deadline_ms=$((started_ms + DURATION * 1000))
cycles=0
trials=0
max_recovery_ms=0
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
stream_digest_directions=0
readonly STREAM_RECORD_BYTES=1048576
readonly STREAM_PROGRESS_TIMEOUT_MS=30000
readonly MAX_AGGREGATE_COUNTER=8999999999999999999
cycle_transcripts=$(mktemp /run/campus-link/.accelerated-transcripts.XXXXXX) || exit 1
result_source=
cleanup() {
  rm -f -- "${cycle_transcripts}"
  [[ -z ${result_source} ]] || rm -f -- "${result_source}"
}
trap cleanup EXIT

PARSED_UINT=0
parse_uint_field() {
  local expected=$1 field=$2 value
  [[ ${field} == "${expected}="* ]] || return 1
  value=${field#*=}
  [[ ${value} =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
  (( value <= MAX_AGGREGATE_COUNTER )) || return 1
  PARSED_UINT=${value}
}

checked_add() {
  local current=$1 increment=$2
  (( current <= MAX_AGGREGATE_COUNTER - increment )) || return 1
  PARSED_UINT=$((current + increment))
}

while :; do
  cycle_now_ms=$(campus_link_monotonic_ms) || exit 1
  (( cycle_now_ms < deadline_ms )) || break
  campus_link_validate_chain "${run_manifest}" full
  current_prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || exit 1
  [[ ${current_prerequisite_sha256} == "${prerequisite_sha256}" ]]
  campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
  cycle_output=$("${EDGE_RECOVERY}" "${REPO_ROOT}" full) || exit 1
  [[ ${cycle_output} != *$'\n'* ]]
  read -r pass cycle_trials_field cycle_recovery_field cycle_kill_switch \
    cycle_connections_field cycle_reconnects_field cycle_records_field \
    cycle_a_to_b_field cycle_b_to_a_field cycle_pre_field cycle_replacement_field \
    cycle_post_field cycle_survival_field cycle_max_a_to_b_field cycle_max_b_to_a_field \
    cycle_digest_directions_field cycle_transcript_field extra <<< "${cycle_output}"
  [[ ${pass} == PASS && ${cycle_kill_switch} == kill_switch=pass && -z ${extra:-} ]]
  parse_uint_field trials "${cycle_trials_field}"; cycle_trials=${PARSED_UINT}
  parse_uint_field max_recovery_ms "${cycle_recovery_field}"; cycle_recovery=${PARSED_UINT}
  parse_uint_field tcp_connections "${cycle_connections_field}"; cycle_connections=${PARSED_UINT}
  parse_uint_field tcp_reconnects "${cycle_reconnects_field}"; cycle_reconnects=${PARSED_UINT}
  parse_uint_field full_duplex_records "${cycle_records_field}"; cycle_records=${PARSED_UINT}
  parse_uint_field stream_bytes_a_to_b "${cycle_a_to_b_field}"; cycle_a_to_b=${PARSED_UINT}
  parse_uint_field stream_bytes_b_to_a "${cycle_b_to_a_field}"; cycle_b_to_a=${PARSED_UINT}
  parse_uint_field pre_restart_progress_checks "${cycle_pre_field}"; cycle_pre=${PARSED_UINT}
  parse_uint_field replacement_active_checkpoints "${cycle_replacement_field}"; cycle_replacement=${PARSED_UINT}
  parse_uint_field post_restart_progress_checks "${cycle_post_field}"; cycle_post=${PARSED_UINT}
  parse_uint_field stream_survival_checks "${cycle_survival_field}"; cycle_survival=${PARSED_UINT}
  parse_uint_field max_progress_gap_a_to_b_ms "${cycle_max_a_to_b_field}"; cycle_max_a=${PARSED_UINT}
  parse_uint_field max_progress_gap_b_to_a_ms "${cycle_max_b_to_a_field}"; cycle_max_b=${PARSED_UINT}
  parse_uint_field stream_digest_directions "${cycle_digest_directions_field}"; cycle_directions=${PARSED_UINT}
  [[ ${cycle_transcript_field} == stream_transcript_sha256=* ]]
  cycle_transcript=${cycle_transcript_field#*=}
  [[ ${cycle_transcript} =~ ^[a-f0-9]{64}$ ]]
  (( cycle_trials == 60 && cycle_connections == cycle_trials &&
     cycle_reconnects == 0 && cycle_records >= cycle_trials * 2 &&
     cycle_records <= MAX_AGGREGATE_COUNTER / STREAM_RECORD_BYTES &&
     cycle_a_to_b == cycle_records * STREAM_RECORD_BYTES &&
     cycle_b_to_a == cycle_records * STREAM_RECORD_BYTES &&
     cycle_pre == cycle_trials && cycle_replacement == cycle_trials &&
     cycle_post == cycle_trials &&
     cycle_survival >= cycle_trials * 3 &&
     cycle_recovery <= STREAM_PROGRESS_TIMEOUT_MS &&
     cycle_max_a <= STREAM_PROGRESS_TIMEOUT_MS &&
     cycle_max_b <= STREAM_PROGRESS_TIMEOUT_MS &&
     cycle_directions == cycle_trials * 2 ))
  cycles=$((cycles + 1))
  checked_add "${trials}" "${cycle_trials}"; trials=${PARSED_UINT}
  checked_add "${stream_connections}" "${cycle_connections}"; stream_connections=${PARSED_UINT}
  checked_add "${full_duplex_records}" "${cycle_records}"; full_duplex_records=${PARSED_UINT}
  checked_add "${stream_bytes_a_to_b}" "${cycle_a_to_b}"; stream_bytes_a_to_b=${PARSED_UINT}
  checked_add "${stream_bytes_b_to_a}" "${cycle_b_to_a}"; stream_bytes_b_to_a=${PARSED_UINT}
  checked_add "${pre_restart_progress_checks}" "${cycle_pre}"; pre_restart_progress_checks=${PARSED_UINT}
  checked_add "${replacement_active_checkpoints}" "${cycle_replacement}"; replacement_active_checkpoints=${PARSED_UINT}
  checked_add "${post_restart_progress_checks}" "${cycle_post}"; post_restart_progress_checks=${PARSED_UINT}
  checked_add "${stream_survival_checks}" "${cycle_survival}"; stream_survival_checks=${PARSED_UINT}
  checked_add "${stream_digest_directions}" "${cycle_directions}"; stream_digest_directions=${PARSED_UINT}
  (( cycle_recovery <= max_recovery_ms )) || max_recovery_ms=${cycle_recovery}
  (( cycle_max_a <= max_progress_gap_a_to_b_ms )) || max_progress_gap_a_to_b_ms=${cycle_max_a}
  (( cycle_max_b <= max_progress_gap_b_to_a_ms )) || max_progress_gap_b_to_a_ms=${cycle_max_b}
  printf '%s\t%s\n' "${cycles}" "${cycle_transcript}" >> "${cycle_transcripts}"
done

campus_link_validate_chain "${run_manifest}" full
current_prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || exit 1
[[ ${current_prerequisite_sha256} == "${prerequisite_sha256}" ]]
campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
completed_ms=$(campus_link_monotonic_ms) || exit 1
elapsed=$(((completed_ms - started_ms) / 1000))
(( completed_ms >= deadline_ms ))
(( cycles > 0 && trials == cycles * 60 && stream_connections == trials &&
   stream_reconnects == 0 && full_duplex_records >= trials * 2 &&
   full_duplex_records <= MAX_AGGREGATE_COUNTER / STREAM_RECORD_BYTES &&
   stream_bytes_a_to_b == full_duplex_records * STREAM_RECORD_BYTES &&
   stream_bytes_b_to_a == full_duplex_records * STREAM_RECORD_BYTES &&
   pre_restart_progress_checks == trials && replacement_active_checkpoints == trials &&
   post_restart_progress_checks == trials &&
   stream_survival_checks >= trials * 3 &&
   max_recovery_ms <= STREAM_PROGRESS_TIMEOUT_MS &&
   max_progress_gap_a_to_b_ms <= STREAM_PROGRESS_TIMEOUT_MS &&
   max_progress_gap_b_to_a_ms <= STREAM_PROGRESS_TIMEOUT_MS &&
   stream_digest_directions == trials * 2 ))
stream_transcript_sha256=$(sha256sum -- "${cycle_transcripts}" | awk '{print $1}') || exit 1
[[ ${stream_transcript_sha256} =~ ^[a-f0-9]{64}$ ]]
result_source=$(mktemp /run/campus-link/.accelerated-fault-soak.XXXXXX) || exit 1
printf 'FORMAT=1\nSTATUS=pass\nGATE=accelerated-fault\nMODE=full\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=%s\nSTART_MONOTONIC_MS=%s\nCOMPLETE_MONOTONIC_MS=%s\nDURATION_SECONDS=%s\nCYCLES=%s\nEDGE_KILL_TRIALS=%s\nMAX_RECOVERY_MS=%s\nSTREAM_RECORD_BYTES=%s\nSTREAM_PROGRESS_TIMEOUT_MS=%s\nTCP_CONNECTIONS=%s\nTCP_RECONNECTS=0\nFULL_DUPLEX_RECORDS=%s\nSTREAM_BYTES_A_TO_B=%s\nSTREAM_BYTES_B_TO_A=%s\nPRE_RESTART_PROGRESS_CHECKS=%s\nREPLACEMENT_ACTIVE_CHECKPOINTS=%s\nPOST_RESTART_PROGRESS_CHECKS=%s\nSTREAM_SURVIVAL_CHECKS=%s\nMAX_PROGRESS_GAP_A_TO_B_MS=%s\nMAX_PROGRESS_GAP_B_TO_A_MS=%s\nSTREAM_DIGEST_DIRECTIONS=%s\nSTREAM_TRANSCRIPT_SHA256=%s\n' \
  "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${prerequisite_sha256}" "${started_ms}" "${completed_ms}" "${elapsed}" \
  "${cycles}" "${trials}" "${max_recovery_ms}" "${STREAM_RECORD_BYTES}" \
  "${STREAM_PROGRESS_TIMEOUT_MS}" "${stream_connections}" \
  "${full_duplex_records}" "${stream_bytes_a_to_b}" "${stream_bytes_b_to_a}" \
  "${pre_restart_progress_checks}" "${replacement_active_checkpoints}" \
  "${post_restart_progress_checks}" "${stream_survival_checks}" \
  "${max_progress_gap_a_to_b_ms}" \
  "${max_progress_gap_b_to_a_ms}" "${stream_digest_directions}" \
  "${stream_transcript_sha256}" > "${result_source}"
campus_link_validate_gate_marker "${result_source}" "${run_manifest}" \
  accelerated-fault full DURATION_SECONDS CYCLES EDGE_KILL_TRIALS \
  MAX_RECOVERY_MS STREAM_RECORD_BYTES STREAM_PROGRESS_TIMEOUT_MS \
  TCP_CONNECTIONS TCP_RECONNECTS FULL_DUPLEX_RECORDS STREAM_BYTES_A_TO_B \
  STREAM_BYTES_B_TO_A PRE_RESTART_PROGRESS_CHECKS \
  REPLACEMENT_ACTIVE_CHECKPOINTS POST_RESTART_PROGRESS_CHECKS \
  STREAM_SURVIVAL_CHECKS \
  MAX_PROGRESS_GAP_A_TO_B_MS MAX_PROGRESS_GAP_B_TO_A_MS \
  STREAM_DIGEST_DIRECTIONS STREAM_TRANSCRIPT_SHA256
campus_link_validate_accelerated_stream_values "${result_source}" "${trials}"
campus_link_atomic_marker "${RESULT}" "${result_source}"
printf 'STATUS=pass\nDURATION_SECONDS=%s\nCYCLES=%s\nEDGE_KILL_TRIALS=%s\nTCP_CONNECTIONS=%s\nTCP_RECONNECTS=0\nFULL_DUPLEX_RECORDS=%s\nMAX_RECOVERY_MS=%s\nMAX_PROGRESS_GAP_A_TO_B_MS=%s\nMAX_PROGRESS_GAP_B_TO_A_MS=%s\n' \
  "${elapsed}" "${cycles}" "${trials}" "${stream_connections}" \
  "${full_duplex_records}" "${max_recovery_ms}" \
  "${max_progress_gap_a_to_b_ms}" "${max_progress_gap_b_to_a_ms}"
