#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=../scripts/gate-evidence.sh
source "${REPO_ROOT}/campus-link/scripts/gate-evidence.sh"
if [[ ${EUID} -ne 0 ]]; then
  # Portable developer runs still exercise schemas and chaining primitives.
  # Linux root runs retain the production owner/mode checks as well.
  campus_link_require_root_file() {
    [[ -f $1 && ! -L $1 ]]
  }
fi

tmp=$(mktemp -d)
cleanup() {
  rm -rf -- "${tmp}"
}
trap cleanup EXIT
chmod 0700 "${tmp}"

valid=${tmp}/valid.env
printf 'FORMAT=1\nRUN_ID=0123456789abcdef0123456789abcdef\n' > "${valid}"
chmod 0600 "${valid}"
campus_link_validate_schema "${valid}" FORMAT RUN_ID
[[ $(campus_link_marker_value "${valid}" FORMAT) == 1 ]]
! (
  mapfile() {
    local destination=${!#}
    eval "${destination}=('FORMAT=1')"
    return 1
  }
  campus_link_marker_value "${valid}" FORMAT >/dev/null
)
ln -s "${valid}" "${tmp}/valid-link.env"
! campus_link_validate_schema "${tmp}/valid-link.env" FORMAT RUN_ID

duplicate=${tmp}/duplicate.env
printf 'FORMAT=1\nFORMAT=1\n' > "${duplicate}"
chmod 0600 "${duplicate}"
! campus_link_validate_schema "${duplicate}" FORMAT RUN_ID

nul=${tmp}/nul.env
printf 'FORMAT=1\0\n' > "${nul}"
chmod 0600 "${nul}"
! campus_link_validate_schema "${nul}" FORMAT

manifest=${tmp}/MANIFEST.sha256
digest=$(printf x | sha256sum | awk '{print $1}')
printf '%s  VERSION\n%s  bin/campus-link-edge\n' "${digest}" "${digest}" > "${manifest}"
chmod 0600 "${manifest}"
campus_link_validate_release_manifest "${manifest}"
printf '%s  bin/campus-link-edge\n%s  VERSION\n' "${digest}" "${digest}" > "${manifest}"
! campus_link_validate_release_manifest "${manifest}"

run_manifest=${tmp}/run.manifest
printf 'FORMAT=1\nRUN_ID=0123456789abcdef0123456789abcdef\nCANDIDATE_SHA256=%064d\nDEPLOYMENT_ATTESTATION_SHA256=%064d\nSTART_MONOTONIC_MS=100\nBOOT_ID_SHA256=%064d\n' \
  0 1 2 > "${run_manifest}"
chmod 0600 "${run_manifest}"
run_manifest_sha=$(sha256sum "${run_manifest}" | awk '{print $1}')
campus_link_validate_run_manifest() {
  campus_link_validate_schema "$1" FORMAT RUN_ID CANDIDATE_SHA256 \
    DEPLOYMENT_ATTESTATION_SHA256 START_MONOTONIC_MS BOOT_ID_SHA256
}
campus_link_run_manifest_sha256() {
  sha256sum "$1" | awk '{print $1}'
}
marker=${tmp}/full.result
printf 'FORMAT=1\nSTATUS=pass\nGATE=full\nMODE=full\nRUN_ID=0123456789abcdef0123456789abcdef\nCANDIDATE_SHA256=%064d\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=none\nSTART_MONOTONIC_MS=101\nCOMPLETE_MONOTONIC_MS=102\nRECORDS=10000\n' \
  0 "${run_manifest_sha}" > "${marker}"
chmod 0600 "${marker}"
campus_link_validate_gate_marker "${marker}" "${run_manifest}" full full RECORDS
sed 's/RUN_ID=0123456789abcdef0123456789abcdef/RUN_ID=1123456789abcdef0123456789abcdef/' \
  "${marker}" > "${tmp}/wrong-run.result"
chmod 0600 "${tmp}/wrong-run.result"
! campus_link_validate_gate_marker "${tmp}/wrong-run.result" "${run_manifest}" full full RECORDS

now=$(campus_link_monotonic_ms)
future=$((now + 10000))
sed "s/COMPLETE_MONOTONIC_MS=102/COMPLETE_MONOTONIC_MS=${future}/" \
  "${marker}" > "${tmp}/future.result"
chmod 0600 "${tmp}/future.result"
! campus_link_validate_gate_marker "${tmp}/future.result" "${run_manifest}" full full RECORDS

direct=${tmp}/direct.env
printf '%s\n' \
  'DIRECT_EVIDENCE_DURATION_MS=1000' \
  'EDGE_A_DIRECT_PROGRESS_DELTA=1' \
  'EDGE_A_DIRECT_RECEIVED_DELTA=1000' \
  'EDGE_A_DIRECT_SENT_DELTA=1000' \
  'EDGE_A_DROPPED_DELTA=0' \
  'EDGE_A_DUPLICATE_PACKETS_DELTA=0' \
  'EDGE_A_FALLBACKS_DELTA=0' \
  'EDGE_A_INVALID_PACKETS_DELTA=0' \
  'EDGE_A_QUEUE_DROPS_DELTA=0' \
  'EDGE_A_RELAY_RECEIVED_DELTA=0' \
  'EDGE_A_RELAY_SENT_DELTA=0' \
  'EDGE_A_WATCHDOG_FAILURES_DELTA=0' \
  'EDGE_B_DIRECT_PROGRESS_DELTA=1' \
  'EDGE_B_DIRECT_RECEIVED_DELTA=1000' \
  'EDGE_B_DIRECT_SENT_DELTA=1000' \
  'EDGE_B_DROPPED_DELTA=0' \
  'EDGE_B_DUPLICATE_PACKETS_DELTA=0' \
  'EDGE_B_FALLBACKS_DELTA=0' \
  'EDGE_B_INVALID_PACKETS_DELTA=0' \
  'EDGE_B_QUEUE_DROPS_DELTA=0' \
  'EDGE_B_RELAY_RECEIVED_DELTA=0' \
  'EDGE_B_RELAY_SENT_DELTA=0' \
  'EDGE_B_WATCHDOG_FAILURES_DELTA=0' \
  'RAW_RELAY_BYTE_LIMIT_PER_SITE=65600' \
  'RAW_RELAY_PACKET_LIMIT_PER_SITE=33' \
  'RAW_RELAY_SITE_A_BYTES_DELTA=1024' \
  'RAW_RELAY_SITE_A_DELTA=1' \
  'RAW_RELAY_SITE_B_BYTES_DELTA=2048' \
  'RAW_RELAY_SITE_B_DELTA=2' > "${direct}"
chmod 0600 "${direct}"
[[ ${#CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]} -eq 29 ]]
campus_link_validate_schema "${direct}" "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}"
campus_link_validate_direct_evidence_values "${direct}"
sed 's/RAW_RELAY_PACKET_LIMIT_PER_SITE=33/RAW_RELAY_PACKET_LIMIT_PER_SITE=420000/' \
  "${direct}" > "${tmp}/inflated-limit.env"
chmod 0600 "${tmp}/inflated-limit.env"
! campus_link_validate_direct_evidence_values "${tmp}/inflated-limit.env"
sed 's/RAW_RELAY_BYTE_LIMIT_PER_SITE=65600/RAW_RELAY_BYTE_LIMIT_PER_SITE=65601/' \
  "${direct}" > "${tmp}/inflated-byte-limit.env"
chmod 0600 "${tmp}/inflated-byte-limit.env"
! campus_link_validate_direct_evidence_values "${tmp}/inflated-byte-limit.env"
sed 's/RAW_RELAY_SITE_A_BYTES_DELTA=1024/RAW_RELAY_SITE_A_BYTES_DELTA=65601/' \
  "${direct}" > "${tmp}/relayed-bulk.env"
chmod 0600 "${tmp}/relayed-bulk.env"
! campus_link_validate_direct_evidence_values "${tmp}/relayed-bulk.env"
sed -e 's/RAW_RELAY_SITE_A_BYTES_DELTA=1024/RAW_RELAY_SITE_A_BYTES_DELTA=67584/' \
  -e 's/RAW_RELAY_SITE_A_DELTA=1/RAW_RELAY_SITE_A_DELTA=33/' \
  "${direct}" > "${tmp}/max-sized-allowed-packets.env"
chmod 0600 "${tmp}/max-sized-allowed-packets.env"
! campus_link_validate_direct_evidence_values "${tmp}/max-sized-allowed-packets.env"
sed 's/EDGE_A_DIRECT_SENT_DELTA=1000/EDGE_A_DIRECT_SENT_DELTA=999/' \
  "${direct}" > "${tmp}/short-direct.env"
chmod 0600 "${tmp}/short-direct.env"
! campus_link_validate_direct_evidence_values "${tmp}/short-direct.env"
sed 's/EDGE_A_QUEUE_DROPS_DELTA=0/EDGE_A_QUEUE_DROPS_DELTA=1/' \
  "${direct}" > "${tmp}/queue-drop.env"
chmod 0600 "${tmp}/queue-drop.env"
! campus_link_validate_direct_evidence_values "${tmp}/queue-drop.env"
sed 's/EDGE_A_INVALID_PACKETS_DELTA=0/EDGE_A_INVALID_PACKETS_DELTA=1/' \
  "${direct}" > "${tmp}/invalid-packet.env"
chmod 0600 "${tmp}/invalid-packet.env"
! campus_link_validate_direct_evidence_values "${tmp}/invalid-packet.env"
printf 'RAW_RELAY_SITE_B_DELTA=2\n' >> "${direct}"
! campus_link_validate_schema "${direct}" "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}"

fault=${tmp}/fault.env
printf '%s\n' \
  'FAULT_DIRECT_EVIDENCE_DURATION_MS=1000' \
  'FAULT_EDGE_A_DIRECT_PROGRESS_DELTA=1' \
  'FAULT_EDGE_A_DIRECT_RECEIVED_DELTA=1000' \
  'FAULT_EDGE_A_DIRECT_SENT_DELTA=1000' \
  'FAULT_EDGE_A_DROPPED_DELTA=0' \
  'FAULT_EDGE_A_DUPLICATE_PACKETS_DELTA=0' \
  'FAULT_EDGE_A_FALLBACKS_DELTA=0' \
  'FAULT_EDGE_A_INVALID_PACKETS_DELTA=0' \
  'FAULT_EDGE_A_QUEUE_DROPS_DELTA=0' \
  'FAULT_EDGE_A_RELAY_RECEIVED_DELTA=0' \
  'FAULT_EDGE_A_RELAY_SENT_DELTA=0' \
  'FAULT_EDGE_A_WATCHDOG_FAILURES_DELTA=1' \
  'FAULT_EDGE_B_DIRECT_PROGRESS_DELTA=1' \
  'FAULT_EDGE_B_DIRECT_RECEIVED_DELTA=1000' \
  'FAULT_EDGE_B_DIRECT_SENT_DELTA=1000' \
  'FAULT_EDGE_B_DROPPED_DELTA=0' \
  'FAULT_EDGE_B_DUPLICATE_PACKETS_DELTA=0' \
  'FAULT_EDGE_B_FALLBACKS_DELTA=0' \
  'FAULT_EDGE_B_INVALID_PACKETS_DELTA=0' \
  'FAULT_EDGE_B_QUEUE_DROPS_DELTA=0' \
  'FAULT_EDGE_B_RELAY_RECEIVED_DELTA=0' \
  'FAULT_EDGE_B_RELAY_SENT_DELTA=0' \
  'FAULT_EDGE_B_WATCHDOG_FAILURES_DELTA=1' \
  'FAULT_EXACT_PATH_IDENTITY_CHECKS=6' \
  'FAULT_RAW_RELAY_BYTE_LIMIT_PER_SITE=65600' \
  'FAULT_RAW_RELAY_PACKET_LIMIT_PER_SITE=33' \
  'FAULT_RAW_RELAY_SITE_A_BYTES_DELTA=1024' \
  'FAULT_RAW_RELAY_SITE_A_DELTA=1' \
  'FAULT_RAW_RELAY_SITE_B_BYTES_DELTA=2048' \
  'FAULT_RAW_RELAY_SITE_B_DELTA=2' \
  'FAULT_REESTABLISHED_DIRECT_PATHS=2' \
  'FAULT_RELAY_CONTROL_SESSION_TRANSITIONS=2' > "${fault}"
chmod 0600 "${fault}"
[[ ${#CAMPUS_LINK_FAULT_EVIDENCE_KEYS[@]} -eq 32 ]]
campus_link_validate_schema "${fault}" "${CAMPUS_LINK_FAULT_EVIDENCE_KEYS[@]}"
campus_link_validate_fault_evidence_values "${fault}"
sed 's/FAULT_EDGE_A_RELAY_RECEIVED_DELTA=0/FAULT_EDGE_A_RELAY_RECEIVED_DELTA=1/' \
  "${fault}" > "${tmp}/fault-relay.env"
chmod 0600 "${tmp}/fault-relay.env"
! campus_link_validate_fault_evidence_values "${tmp}/fault-relay.env"
sed 's/FAULT_EDGE_B_DROPPED_DELTA=0/FAULT_EDGE_B_DROPPED_DELTA=1/' \
  "${fault}" > "${tmp}/fault-drop.env"
chmod 0600 "${tmp}/fault-drop.env"
! campus_link_validate_fault_evidence_values "${tmp}/fault-drop.env"
sed 's/FAULT_EDGE_B_DUPLICATE_PACKETS_DELTA=0/FAULT_EDGE_B_DUPLICATE_PACKETS_DELTA=1/' \
  "${fault}" > "${tmp}/fault-duplicate.env"
chmod 0600 "${tmp}/fault-duplicate.env"
! campus_link_validate_fault_evidence_values "${tmp}/fault-duplicate.env"
sed 's/FAULT_RAW_RELAY_SITE_B_BYTES_DELTA=2048/FAULT_RAW_RELAY_SITE_B_BYTES_DELTA=65601/' \
  "${fault}" > "${tmp}/fault-relayed-bulk.env"
chmod 0600 "${tmp}/fault-relayed-bulk.env"
! campus_link_validate_fault_evidence_values "${tmp}/fault-relayed-bulk.env"

accelerated=${tmp}/accelerated.env
printf '%s\n' \
  'MAX_RECOVERY_MS=1200' \
  'STREAM_RECORD_BYTES=1048576' \
  'STREAM_PROGRESS_TIMEOUT_MS=30000' \
  'TCP_CONNECTIONS=1' \
  'TCP_RECONNECTS=0' \
  'FULL_DUPLEX_RECORDS=2' \
  'STREAM_BYTES_A_TO_B=2097152' \
  'STREAM_BYTES_B_TO_A=2097152' \
  'PRE_RESTART_PROGRESS_CHECKS=1' \
  'REPLACEMENT_ACTIVE_CHECKPOINTS=1' \
  'POST_RESTART_PROGRESS_CHECKS=1' \
  'STREAM_SURVIVAL_CHECKS=3' \
  'MAX_PROGRESS_GAP_A_TO_B_MS=1000' \
  'MAX_PROGRESS_GAP_B_TO_A_MS=1100' \
  'STREAM_DIGEST_DIRECTIONS=2' \
  "STREAM_TRANSCRIPT_SHA256=$(printf b%.0s {1..64})" > "${accelerated}"
chmod 0600 "${accelerated}"
[[ ${#CAMPUS_LINK_ACCELERATED_STREAM_KEYS[@]} -eq 16 ]]
campus_link_validate_schema "${accelerated}" "${CAMPUS_LINK_ACCELERATED_STREAM_KEYS[@]}"
campus_link_validate_accelerated_stream_values "${accelerated}" 1
sed 's/TCP_RECONNECTS=0/TCP_RECONNECTS=1/' "${accelerated}" > "${tmp}/accelerated-reconnect.env"
chmod 0600 "${tmp}/accelerated-reconnect.env"
! campus_link_validate_accelerated_stream_values "${tmp}/accelerated-reconnect.env" 1
sed 's/REPLACEMENT_ACTIVE_CHECKPOINTS=1/REPLACEMENT_ACTIVE_CHECKPOINTS=0/' \
  "${accelerated}" > "${tmp}/accelerated-no-replacement.env"
chmod 0600 "${tmp}/accelerated-no-replacement.env"
! campus_link_validate_accelerated_stream_values "${tmp}/accelerated-no-replacement.env" 1
sed 's/STREAM_BYTES_B_TO_A=2097152/STREAM_BYTES_B_TO_A=2097151/' \
  "${accelerated}" > "${tmp}/accelerated-short.env"
chmod 0600 "${tmp}/accelerated-short.env"
! campus_link_validate_accelerated_stream_values "${tmp}/accelerated-short.env" 1
sed -e 's/FULL_DUPLEX_RECORDS=2/FULL_DUPLEX_RECORDS=9000000000000/' \
  -e 's/STREAM_BYTES_A_TO_B=2097152/STREAM_BYTES_A_TO_B=9000000000000/' \
  -e 's/STREAM_BYTES_B_TO_A=2097152/STREAM_BYTES_B_TO_A=9000000000000/' \
  "${accelerated}" > "${tmp}/accelerated-overflow.env"
chmod 0600 "${tmp}/accelerated-overflow.env"
! campus_link_validate_accelerated_stream_values "${tmp}/accelerated-overflow.env" 1

nat=${tmp}/nat.env
printf '%s\n' \
  'FAULT_SITES=2' \
  'FORCED_MAPPING_CHANGES=2' \
  'RESTORATION_MAPPING_CHANGES=2' \
  'MAPPING_CHANGE_OBSERVATIONS=4' \
  'SOCKET_MAPPING_PROFILE_CHECKS=4' \
  'UNTOUCHED_WAN_MAPPING_CHECKS=4' \
  'CONNTRACK_SCOPED_DELETIONS=4' \
  'NAT_RULESET_RESTORATIONS=2' \
  'FAULT_RECOVERY_TIMEOUT_MS=25000' \
  'MATCHED_DIRECT_EPOCH_CHECKS=4' \
  'MIGRATED_PATHS=2' \
  'REESTABLISHED_PATHS=2' \
  'HIGHER_DIRECT_INSTANCE_EDGE_CHECKS=4' \
  'PROCESS_CONTINUITY_CHECKS=12' \
  'TCP_CONNECTIONS=1' \
  'TCP_RECONNECTS=0' \
  'STREAM_RECORD_BYTES=1048576' \
  'FULL_DUPLEX_RECORDS=6' \
  'STREAM_BYTES_A_TO_B=6291456' \
  'STREAM_BYTES_B_TO_A=6291456' \
  'FIRST_A_TO_B_SEQUENCE=61000000000' \
  'LAST_A_TO_B_SEQUENCE=61000000005' \
  'FIRST_B_TO_A_SEQUENCE=62000000000' \
  'LAST_B_TO_A_SEQUENCE=62000000005' \
  "STREAM_TRANSCRIPT_SHA256=$(printf c%.0s {1..64})" \
  'MAX_PROGRESS_GAP_A_TO_B_MS=1000' \
  'MAX_PROGRESS_GAP_B_TO_A_MS=1100' \
  'EDGE_A_DIRECT_SENT_DELTA=1' \
  'EDGE_A_DIRECT_RECEIVED_DELTA=1' \
  'EDGE_A_DIRECT_PROGRESS_DELTA=1' \
  'EDGE_A_RELAY_SENT_DELTA=0' \
  'EDGE_A_RELAY_RECEIVED_DELTA=0' \
  'EDGE_B_DIRECT_SENT_DELTA=1' \
  'EDGE_B_DIRECT_RECEIVED_DELTA=1' \
  'EDGE_B_DIRECT_PROGRESS_DELTA=1' \
  'EDGE_B_RELAY_SENT_DELTA=0' \
  'EDGE_B_RELAY_RECEIVED_DELTA=0' \
  'RAW_RELAY_PACKET_LIMIT_PER_SITE=33' \
  'RAW_RELAY_BYTE_LIMIT_PER_SITE=65600' \
  'RAW_RELAY_SITE_A_DELTA=1' \
  'RAW_RELAY_SITE_A_BYTES_DELTA=64' \
  'RAW_RELAY_SITE_B_DELTA=2' \
  'RAW_RELAY_SITE_B_BYTES_DELTA=128' > "${nat}"
chmod 0600 "${nat}"
[[ ${#CAMPUS_LINK_NAT_REBIND_EVIDENCE_KEYS[@]} -eq 34 ]]
campus_link_validate_nat_rebinding_values "${nat}"
sed 's/FULL_DUPLEX_RECORDS=6/FULL_DUPLEX_RECORDS=8796093022208/' \
  "${nat}" > "${tmp}/nat-overflow.env"
chmod 0600 "${tmp}/nat-overflow.env"
! campus_link_validate_nat_rebinding_values "${tmp}/nat-overflow.env"
sed 's/STREAM_BYTES_A_TO_B=6291456/STREAM_BYTES_A_TO_B=6291455/' \
  "${nat}" > "${tmp}/nat-short.env"
chmod 0600 "${tmp}/nat-short.env"
! campus_link_validate_nat_rebinding_values "${tmp}/nat-short.env"
sed 's/LAST_B_TO_A_SEQUENCE=62000000005/LAST_B_TO_A_SEQUENCE=62000000006/' \
  "${nat}" > "${tmp}/nat-sequence.env"
chmod 0600 "${tmp}/nat-sequence.env"
! campus_link_validate_nat_rebinding_values "${tmp}/nat-sequence.env"
sed 's/HIGHER_DIRECT_INSTANCE_EDGE_CHECKS=4/HIGHER_DIRECT_INSTANCE_EDGE_CHECKS=3/' \
  "${nat}" > "${tmp}/nat-instance.env"
chmod 0600 "${tmp}/nat-instance.env"
! campus_link_validate_nat_rebinding_values "${tmp}/nat-instance.env"
sed 's/EDGE_A_RELAY_RECEIVED_DELTA=0/EDGE_A_RELAY_RECEIVED_DELTA=1/' \
  "${nat}" > "${tmp}/nat-relay.env"
chmod 0600 "${tmp}/nat-relay.env"
! campus_link_validate_nat_rebinding_values "${tmp}/nat-relay.env"
sed 's/RAW_RELAY_BYTE_LIMIT_PER_SITE=65600/RAW_RELAY_BYTE_LIMIT_PER_SITE=65601/' \
  "${nat}" > "${tmp}/nat-inconsistent-limit.env"
chmod 0600 "${tmp}/nat-inconsistent-limit.env"
! campus_link_validate_nat_rebinding_values "${tmp}/nat-inconsistent-limit.env"
sed 's/RAW_RELAY_SITE_B_DELTA=2/RAW_RELAY_SITE_B_DELTA=34/' \
  "${nat}" > "${tmp}/nat-raw-over.env"
chmod 0600 "${tmp}/nat-raw-over.env"
! campus_link_validate_nat_rebinding_values "${tmp}/nat-raw-over.env"

continuous=${tmp}/continuous.env
printf '%s\n' \
  'START_MONOTONIC_MS=1000' \
  'COMPLETE_MONOTONIC_MS=11000' \
  'REQUIRED_DURATION_SECONDS=10' \
  'DURATION_SECONDS=10' \
  'TCP_CONNECTIONS=1' \
  'TCP_RECONNECTS=0' \
  'FULL_DUPLEX_RECORDS=1' \
  'STREAM_BYTES_A_TO_B=16777216' \
  'STREAM_BYTES_B_TO_A=16777216' \
  'FIRST_A_TO_B_SEQUENCE=30000000000' \
  'LAST_A_TO_B_SEQUENCE=30000000000' \
  'FIRST_B_TO_A_SEQUENCE=40000000000' \
  'LAST_B_TO_A_SEQUENCE=40000000000' \
  "STREAM_TRANSCRIPT_SHA256=$(printf a%.0s {1..64})" \
  'PROGRESS_TIMEOUT_MS=30000' \
  'COMPLETION_GRACE_SECONDS=120' \
  'MAX_PROGRESS_GAP_A_TO_B_MS=100' \
  'MAX_PROGRESS_GAP_B_TO_A_MS=200' \
  'PROGRESS_OBSERVATIONS=2' \
  'DIRECT_STATUS_OBSERVATIONS=2' > "${continuous}"
chmod 0600 "${continuous}"
[[ ${#CAMPUS_LINK_CONTINUOUS_STREAM_KEYS[@]} -eq 16 ]]
campus_link_validate_continuous_stream_values "${continuous}" 10
sed 's/DIRECT_STATUS_OBSERVATIONS=2/DIRECT_STATUS_OBSERVATIONS=1/' \
  "${continuous}" > "${tmp}/missing-direct-observation.env"
chmod 0600 "${tmp}/missing-direct-observation.env"
! campus_link_validate_continuous_stream_values \
  "${tmp}/missing-direct-observation.env" 10
sed 's/TCP_RECONNECTS=0/TCP_RECONNECTS=1/' "${continuous}" > "${tmp}/reconnected.env"
chmod 0600 "${tmp}/reconnected.env"
! campus_link_validate_continuous_stream_values "${tmp}/reconnected.env" 10
sed 's/STREAM_BYTES_A_TO_B=16777216/STREAM_BYTES_A_TO_B=16777215/' \
  "${continuous}" > "${tmp}/short-stream.env"
chmod 0600 "${tmp}/short-stream.env"
! campus_link_validate_continuous_stream_values "${tmp}/short-stream.env" 10
sed 's/MAX_PROGRESS_GAP_B_TO_A_MS=200/MAX_PROGRESS_GAP_B_TO_A_MS=30001/' \
  "${continuous}" > "${tmp}/stalled-stream.env"
chmod 0600 "${tmp}/stalled-stream.env"
! campus_link_validate_continuous_stream_values "${tmp}/stalled-stream.env" 10

first=$(campus_link_monotonic_ms)
second=$(campus_link_monotonic_ms)
campus_link_is_uint "${first}"
campus_link_is_uint "${second}"
(( second >= first ))
! campus_link_is_uint 08
! campus_link_is_uint 18446744073709551615
campus_link_is_shell_uint 9223372036854775807
! campus_link_is_shell_uint 9223372036854775808
! campus_link_is_shell_uint 01
shell_uint=${tmp}/shell-uint.env
printf 'VALUE=9223372036854775807\n' > "${shell_uint}"
chmod 0600 "${shell_uint}"
[[ $(campus_link_marker_shell_uint "${shell_uint}" VALUE) == 9223372036854775807 ]]

echo 'PASS gate-evidence helper invariants'
