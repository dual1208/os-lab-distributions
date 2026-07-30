#!/usr/bin/env bash
set -euo pipefail

readonly RUN_DIR=/run/campus-link
readonly RUN_MANIFEST=${RUN_DIR}/qualification-run.manifest
readonly CHAIN_LOCK=${RUN_DIR}/qualification-chain.lock
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
readonly SCRIPT_DIR
if [[ -f ${SCRIPT_DIR}/campus-link-gate-evidence ]]; then
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/campus-link-gate-evidence
else
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/gate-evidence.sh
fi

[[ ${EUID} -eq 0 ]]
[[ -f ${EVIDENCE_HELPER} && ! -L ${EVIDENCE_HELPER} ]]
# shellcheck source=gate-evidence.sh
source "${EVIDENCE_HELPER}"
umask 077

install -d -m 0755 -o root -g root "${RUN_DIR}"
[[ -d ${RUN_DIR} && ! -L ${RUN_DIR} ]]
run_dir_metadata=$(stat -c '%u:%g:%a' -- "${RUN_DIR}") || exit 1
[[ ${run_dir_metadata} == 0:0:755 ]]

exec 8<>"${CHAIN_LOCK}"
flock -n 8 || {
  echo 'A campus-link qualification chain is already active.' >&2
  exit 5
}
campus_link_acquire_deployment_shared_lock

readonly -a units=(
  campus-link-full-qualification.service
  campus-link-accelerated-fault.service
  campus-link-fault-in-stream.service
  campus-link-nat-rebinding.service
  campus-link-24h-soak.service
  campus-link-7d-burn-in.service
)
for unit in "${units[@]}"; do
  if systemctl is-active --quiet "${unit}"; then
    echo "Refusing to replace evidence while ${unit} is active." >&2
    exit 6
  fi
done
systemctl is-active --quiet campus-link-topology.service \
  campus-link-edge-a.service campus-link-edge-b.service || {
  echo 'The campus-link topology and both edge services must be active.' >&2
  exit 7
}

run_id=$(openssl rand -hex 16) || exit 1
[[ ${run_id} =~ ^[a-f0-9]{32}$ ]]
candidate_sha256=$(campus_link_candidate_fingerprint) || exit 1
deployment_sha256=$(sha256sum -- "${CAMPUS_LINK_DEPLOYMENT_ATTESTATION}" | awk '{print $1}') || exit 1
started_ms=$(campus_link_monotonic_ms) || exit 1
boot_id_sha256=$(campus_link_boot_id_sha256) || exit 1
manifest_source=$(mktemp "${RUN_DIR}/.qualification-run.XXXXXX") || exit 1
trap 'rm -f -- "${manifest_source}"' EXIT
printf 'FORMAT=1\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nDEPLOYMENT_ATTESTATION_SHA256=%s\nSTART_MONOTONIC_MS=%s\nBOOT_ID_SHA256=%s\n' \
  "${run_id}" "${candidate_sha256}" "${deployment_sha256}" "${started_ms}" \
  "${boot_id_sha256}" > "${manifest_source}"
campus_link_validate_schema "${manifest_source}" \
  FORMAT RUN_ID CANDIDATE_SHA256 DEPLOYMENT_ATTESTATION_SHA256 \
  START_MONOTONIC_MS BOOT_ID_SHA256
campus_link_atomic_marker "${RUN_MANIFEST}" "${manifest_source}"
campus_link_validate_run_manifest "${RUN_MANIFEST}"
manifest_sha256=$(campus_link_run_manifest_sha256 "${RUN_MANIFEST}") || exit 1
readonly manifest_sha256

rm -f -- \
  "${RUN_DIR}/a11-b22-full.result" \
  "${RUN_DIR}/accelerated-fault-soak.result" \
  "${RUN_DIR}/fault-in-stream.result" \
  "${RUN_DIR}/nat-rebinding.result" \
  "${RUN_DIR}/a11-b22-soak-24-hour.result" \
  "${RUN_DIR}/a11-b22-soak-24-hour.failure" \
  "${RUN_DIR}/a11-b22-soak-seven-day.result" \
  "${RUN_DIR}/a11-b22-soak-seven-day.failure"

run_gate() {
  local unit=$1 through=$2
  campus_link_assert_run_immutable "${RUN_MANIFEST}" "${manifest_sha256}" "${candidate_sha256}"
  systemctl reset-failed "${unit}" >/dev/null 2>&1 || true
  systemctl start "${unit}"
  campus_link_validate_chain "${RUN_MANIFEST}" "${through}"
  campus_link_assert_run_immutable "${RUN_MANIFEST}" "${manifest_sha256}" "${candidate_sha256}"
}

run_gate campus-link-full-qualification.service full
run_gate campus-link-accelerated-fault.service accelerated-fault
run_gate campus-link-fault-in-stream.service fault-in-stream
run_gate campus-link-nat-rebinding.service nat-rebinding
run_gate campus-link-24h-soak.service 24h-soak
run_gate campus-link-7d-burn-in.service 7d-burn-in

printf 'STATUS=pass\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nFINAL_GATE=7d-burn-in\n' \
  "${run_id}" "${candidate_sha256}"
