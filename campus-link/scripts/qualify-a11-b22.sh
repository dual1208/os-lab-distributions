#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-smoke}
readonly RESULT=/run/campus-link/a11-b22-${MODE}.result
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
  readonly STREAM_PROBE=/usr/local/libexec/campus-link-stream-transport.py
  readonly STATUS_GATE=/usr/local/libexec/campus-link-status-gate.py
else
  readonly PROBE=${REPO_ROOT}/campus-link/tests/a11_b22.py
  readonly STREAM_PROBE=${REPO_ROOT}/campus-link/tests/stream_transport.py
  readonly STATUS_GATE=${REPO_ROOT}/campus-link/tests/status_gate.py
fi

[[ ${EUID} -eq 0 ]]
[[ -f ${EVIDENCE_HELPER} && ! -L ${EVIDENCE_HELPER} ]]
[[ -f ${PROBE} && ! -L ${PROBE} ]]
# shellcheck source=gate-evidence.sh
source "${EVIDENCE_HELPER}"
umask 077

command_output_matches() {
  local pattern=$1 output
  shift
  output=$("$@") || return 1
  grep -- "${pattern}" <<< "${output}" >/dev/null
}

capture_service_identity() {
  edge_a_restarts=$(systemctl show -p NRestarts --value campus-link-edge-a.service) || return 1
  edge_b_restarts=$(systemctl show -p NRestarts --value campus-link-edge-b.service) || return 1
  edge_a_invocation=$(systemctl show -p InvocationID --value campus-link-edge-a.service) || return 1
  edge_b_invocation=$(systemctl show -p InvocationID --value campus-link-edge-b.service) || return 1
  [[ ${edge_a_restarts} =~ ^[0-9]+$ && ${edge_b_restarts} =~ ^[0-9]+$ ]] || return 1
  [[ ${edge_a_invocation} =~ ^[a-f0-9]{32}$ && ${edge_b_invocation} =~ ^[a-f0-9]{32}$ ]]
}

assert_service_identity_unchanged() {
  local value
  value=$(systemctl show -p NRestarts --value campus-link-edge-a.service) || return 1
  [[ ${value} == "${edge_a_restarts}" ]] || return 1
  value=$(systemctl show -p NRestarts --value campus-link-edge-b.service) || return 1
  [[ ${value} == "${edge_b_restarts}" ]] || return 1
  value=$(systemctl show -p InvocationID --value campus-link-edge-a.service) || return 1
  [[ ${value} == "${edge_a_invocation}" ]] || return 1
  value=$(systemctl show -p InvocationID --value campus-link-edge-b.service) || return 1
  [[ ${value} == "${edge_b_invocation}" ]]
}
case ${MODE} in
  smoke)
    bulk_bytes=$((4 * 1024 * 1024))
    records=10000
    concurrency=100
    simultaneous_stream_bytes=0
    long_stream_bytes=0
    stream_min_mbit=0
    long_stream_min_mbit=0
    ;;
  full)
    [[ -f ${STREAM_PROBE} && ! -L ${STREAM_PROBE} ]]
    [[ -f ${STATUS_GATE} && ! -L ${STATUS_GATE} ]]
    bulk_bytes=$((1024 * 1024 * 1024))
    records=10000
    concurrency=100
    simultaneous_stream_bytes=$((1024 * 1024 * 1024))
    long_stream_bytes=$((4 * 1024 * 1024 * 1024))
    stream_min_mbit=15
    long_stream_min_mbit=25
    ;;
  *)
    echo 'usage: qualify-a11-b22.sh [REPO_ROOT] [smoke|full]' >&2
    exit 2
    ;;
esac

campus_link_acquire_deployment_shared_lock
campus_link_acquire_gate_execution_lock
rm -f -- "${RESULT}"

if [[ ${MODE} == full ]]; then
  readonly run_manifest=${CAMPUS_LINK_RUN_MANIFEST}
  campus_link_validate_run_manifest "${run_manifest}"
  run_id=$(campus_link_marker_value "${run_manifest}" RUN_ID) || exit 1
  candidate_sha256=$(campus_link_marker_value "${run_manifest}" CANDIDATE_SHA256) || exit 1
  run_manifest_sha256=$(campus_link_run_manifest_sha256 "${run_manifest}") || exit 1
else
  readonly run_manifest=none
  run_id=$(openssl rand -hex 16) || exit 1
  candidate_sha256=$(campus_link_candidate_fingerprint) || exit 1
  run_manifest_sha256=none
fi
[[ ${run_id} =~ ^[a-f0-9]{32}$ ]]
[[ ${candidate_sha256} =~ ^[a-f0-9]{64}$ ]]
started_ms=$(campus_link_monotonic_ms) || exit 1
if [[ ${MODE} == full ]]; then
  manifest_started_ms=$(campus_link_marker_value "${run_manifest}" START_MONOTONIC_MS) || exit 1
  (( started_ms >= manifest_started_ms ))
  campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
fi

for required in oslab-a oslab-b campus-a campus-b; do
  command_output_matches "^${required}\\b" ip netns list
done
command_output_matches '10.81.0.11/24' ip -n oslab-a address show dev ep-a
command_output_matches '10.82.0.22/24' ip -n oslab-b address show dev ep-b

pids=()
evidence_dir=
cleanup() {
  if (( ${#pids[@]} > 0 )); then
    kill "${pids[@]}" 2>/dev/null || true
  fi
  rm -f -- "${result_source:-}"
  if [[ -n ${evidence_dir} && ${evidence_dir} == /run/campus-link/.direct-evidence.* && -d ${evidence_dir} && ! -L ${evidence_dir} ]]; then
    rm -rf -- "${evidence_dir}"
  fi
}
trap cleanup EXIT

ip netns exec oslab-a python3 -B "${PROBE}" serve --bind 10.81.0.11 &
pids+=("$!")
ip netns exec oslab-b python3 -B "${PROBE}" serve --bind 10.82.0.22 &
pids+=("$!")
if [[ ${MODE} == full ]]; then
  ip netns exec oslab-b python3 -B "${STREAM_PROBE}" serve \
    --bind 10.82.0.22 --port 18082 --progress-timeout 30 --phase-timeout 7200 \
    >/dev/null 2>&1 &
  pids+=("$!")
fi
sleep 1
kill -0 "${pids[@]}"

if [[ ${MODE} == full ]]; then
  evidence_dir=$(mktemp -d /run/campus-link/.direct-evidence.XXXXXX) || exit 1
  chmod 0700 "${evidence_dir}"
  python3 -B "${STATUS_GATE}" wait-direct \
    --edge-a /run/campus-link/site-a/status.json \
    --edge-b /run/campus-link/site-b/status.json \
    --timeout-seconds 60
  capture_service_identity
  python3 -B "${STATUS_GATE}" capture \
    --edge-a /run/campus-link/site-a/status.json \
    --edge-b /run/campus-link/site-b/status.json \
    --output "${evidence_dir}/before.json"
  assert_service_identity_unchanged
fi

ip netns exec oslab-a python3 -B "${PROBE}" client \
  --source 10.81.0.11 --destination 10.82.0.22 \
  --records "${records}" --concurrency "${concurrency}" --bulk-bytes "${bulk_bytes}"
ip netns exec oslab-b python3 -B "${PROBE}" client \
  --source 10.82.0.22 --destination 10.81.0.11 \
  --records "${records}" --concurrency "${concurrency}" --bulk-bytes "${bulk_bytes}"

if [[ ${MODE} == full ]]; then
  # One connection first proves simultaneous 1 GiB application streams in
  # both directions. A second connection proves a sequence-unique 4 GiB stream
  # in each direction without whole-payload buffering.
  ip netns exec oslab-a python3 -B "${STREAM_PROBE}" client \
    --source 10.81.0.11 --destination 10.82.0.22 --port 18082 \
    --rounds 1 --send-bytes "${simultaneous_stream_bytes}" \
    --receive-bytes "${simultaneous_stream_bytes}" \
    --send-sequence 10000000 --receive-sequence 20000000 \
    --progress-timeout 30 --phase-timeout 3600 \
    --min-send-mbit-s "${stream_min_mbit}" --min-receive-mbit-s "${stream_min_mbit}"
  ip netns exec oslab-a python3 -B "${STREAM_PROBE}" client \
    --source 10.81.0.11 --destination 10.82.0.22 --port 18082 \
    --rounds 1 --send-bytes "${long_stream_bytes}" \
    --receive-bytes "${long_stream_bytes}" \
    --send-sequence 30000000 --receive-sequence 40000000 \
    --progress-timeout 30 --phase-timeout 3600 \
    --min-send-mbit-s "${long_stream_min_mbit}" \
    --min-receive-mbit-s "${long_stream_min_mbit}"
  python3 -B "${STATUS_GATE}" wait-telemetry \
    --edge-a /run/campus-link/site-a/status.json \
    --edge-b /run/campus-link/site-b/status.json \
    --before "${evidence_dir}/before.json" \
    --timeout-seconds 30
  python3 -B "${STATUS_GATE}" capture \
    --edge-a /run/campus-link/site-a/status.json \
    --edge-b /run/campus-link/site-b/status.json \
    --output "${evidence_dir}/after.json"
  assert_service_identity_unchanged
  python3 -B "${STATUS_GATE}" verify \
    --before "${evidence_dir}/before.json" \
    --after "${evidence_dir}/after.json" \
    --minimum-direct-packets 1000 \
    --raw-relay-rate 1 > "${evidence_dir}/verified.env"
  campus_link_validate_schema "${evidence_dir}/verified.env" \
    "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}"
fi

if [[ ${MODE} == full ]]; then
  campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
else
  current_candidate_sha256=$(campus_link_candidate_fingerprint) || exit 1
  [[ ${current_candidate_sha256} == "${candidate_sha256}" ]]
fi
completed_ms=$(campus_link_monotonic_ms) || exit 1
(( completed_ms >= started_ms ))
result_source=$(mktemp /run/campus-link/.a11-b22-qualification.XXXXXX) || exit 1
printf 'FORMAT=1\nSTATUS=pass\nGATE=%s\nMODE=%s\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=none\nSTART_MONOTONIC_MS=%s\nCOMPLETE_MONOTONIC_MS=%s\nRECORDS=%s\nCONCURRENCY=%s\nBULK_BYTES_EACH_DIRECTION=%s\nSIMULTANEOUS_STREAM_BYTES_EACH_DIRECTION=%s\nLONG_STREAM_BYTES_EACH_DIRECTION=%s\nSTREAM_MIN_MBIT_S=%s\nLONG_STREAM_MIN_MBIT_S=%s\n' \
  "${MODE}" "${MODE}" "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
  "${started_ms}" "${completed_ms}" "${records}" "${concurrency}" "${bulk_bytes}" \
  "${simultaneous_stream_bytes}" "${long_stream_bytes}" "${stream_min_mbit}" \
  "${long_stream_min_mbit}" > "${result_source}"
if [[ ${MODE} == full ]]; then
  cat -- "${evidence_dir}/verified.env" >> "${result_source}"
  campus_link_validate_gate_marker "${result_source}" "${run_manifest}" full full \
    RECORDS CONCURRENCY BULK_BYTES_EACH_DIRECTION \
    SIMULTANEOUS_STREAM_BYTES_EACH_DIRECTION LONG_STREAM_BYTES_EACH_DIRECTION \
    STREAM_MIN_MBIT_S LONG_STREAM_MIN_MBIT_S \
    "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}"
else
  campus_link_validate_schema "${result_source}" \
    FORMAT STATUS GATE MODE RUN_ID CANDIDATE_SHA256 RUN_MANIFEST_SHA256 \
    PREREQUISITE_MARKER_SHA256 START_MONOTONIC_MS COMPLETE_MONOTONIC_MS \
    RECORDS CONCURRENCY BULK_BYTES_EACH_DIRECTION \
    SIMULTANEOUS_STREAM_BYTES_EACH_DIRECTION LONG_STREAM_BYTES_EACH_DIRECTION \
    STREAM_MIN_MBIT_S LONG_STREAM_MIN_MBIT_S
fi
campus_link_atomic_marker "${RESULT}" "${result_source}"
printf 'STATUS=pass\nMODE=%s\nRECORDS=%s\nCONCURRENCY=%s\nBULK_BYTES_EACH_DIRECTION=%s\nSIMULTANEOUS_STREAM_BYTES_EACH_DIRECTION=%s\nLONG_STREAM_BYTES_EACH_DIRECTION=%s\n' \
  "${MODE}" "${records}" "${concurrency}" "${bulk_bytes}" \
  "${simultaneous_stream_bytes}" "${long_stream_bytes}"
