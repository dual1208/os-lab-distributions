#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly MODE=${2:-production}
readonly RESULT=/run/campus-link/nat-rebinding.result
readonly PREREQUISITE=/run/campus-link/fault-in-stream.result
readonly EDGE_A_STATUS=${CAMPUS_LINK_EDGE_A_STATUS:-/run/campus-link/site-a/status.json}
readonly EDGE_B_STATUS=${CAMPUS_LINK_EDGE_B_STATUS:-/run/campus-link/site-b/status.json}
readonly WAN_DEVICE_STATE=/run/campus-link/wan-device
readonly STREAM_PORT=18094
readonly STREAM_RECORD_BYTES=1048576
readonly STREAM_DEADLINE_SECONDS=300
readonly STREAM_COMPLETION_GRACE_SECONDS=60
readonly FAULT_RECOVERY_TIMEOUT_SECONDS=25
readonly FAULT_RECOVERY_TIMEOUT_MS=25000
readonly A_TO_B_SEQUENCE=61000000000
readonly B_TO_A_SEQUENCE=62000000000
readonly SITE_A_SOURCE=100.64.10.2
readonly SITE_B_SOURCE=100.64.10.6
readonly SITE_A_NAMESPACE=campus-a
readonly SITE_B_NAMESPACE=campus-b
readonly SITE_A_COMMENT=campus-link-nat-rebind-site-a
readonly SITE_B_COMMENT=campus-link-nat-rebind-site-b
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
readonly SCRIPT_DIR

if [[ -f ${SCRIPT_DIR}/campus-link-gate-evidence ]]; then
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/campus-link-gate-evidence
else
  readonly EVIDENCE_HELPER=${SCRIPT_DIR}/gate-evidence.sh
fi
if [[ -f /usr/local/libexec/campus-link-stream-transport.py ]]; then
  readonly STREAM_PROBE=/usr/local/libexec/campus-link-stream-transport.py
  readonly STATUS_GATE=/usr/local/libexec/campus-link-status-gate.py
  readonly NAT_EVIDENCE=/usr/local/libexec/campus-link-nat-rebind-gate.py
else
  readonly STREAM_PROBE=${REPO_ROOT}/campus-link/tests/stream_transport.py
  readonly STATUS_GATE=${REPO_ROOT}/campus-link/tests/status_gate.py
  readonly NAT_EVIDENCE=${REPO_ROOT}/campus-link/tests/nat_rebind_gate.py
fi

readonly -a NAT_REBIND_EVIDENCE_KEYS=(
  MATCHED_DIRECT_EPOCH_CHECKS MIGRATED_PATHS REESTABLISHED_PATHS
  HIGHER_DIRECT_INSTANCE_EDGE_CHECKS PROCESS_CONTINUITY_CHECKS
  TCP_CONNECTIONS TCP_RECONNECTS STREAM_RECORD_BYTES FULL_DUPLEX_RECORDS
  STREAM_BYTES_A_TO_B STREAM_BYTES_B_TO_A FIRST_A_TO_B_SEQUENCE
  LAST_A_TO_B_SEQUENCE FIRST_B_TO_A_SEQUENCE LAST_B_TO_A_SEQUENCE
  STREAM_TRANSCRIPT_SHA256 MAX_PROGRESS_GAP_A_TO_B_MS
  MAX_PROGRESS_GAP_B_TO_A_MS EDGE_A_DIRECT_SENT_DELTA
  EDGE_A_DIRECT_RECEIVED_DELTA EDGE_A_DIRECT_PROGRESS_DELTA
  EDGE_A_RELAY_SENT_DELTA EDGE_A_RELAY_RECEIVED_DELTA
  EDGE_B_DIRECT_SENT_DELTA EDGE_B_DIRECT_RECEIVED_DELTA
  EDGE_B_DIRECT_PROGRESS_DELTA EDGE_B_RELAY_SENT_DELTA
  EDGE_B_RELAY_RECEIVED_DELTA RAW_RELAY_PACKET_LIMIT_PER_SITE
  RAW_RELAY_BYTE_LIMIT_PER_SITE RAW_RELAY_SITE_A_DELTA
  RAW_RELAY_SITE_A_BYTES_DELTA RAW_RELAY_SITE_B_DELTA
  RAW_RELAY_SITE_B_BYTES_DELTA
)

fail() {
  printf 'NAT-rebinding gate failed: %s\n' "$1" >&2
  exit 1
}

collect_complete_lines() {
  local output_name=$1 producer=$2 producer_pid
  local consumer_status=0 producer_status=0
  local -n output=${output_name}
  shift 2
  output=()
  mapfile -t output < <("${producer}" "$@") || consumer_status=$?
  producer_pid=$!
  wait "${producer_pid}" || producer_status=$?
  (( consumer_status == 0 && producer_status == 0 ))
}

[[ ${MODE} == production ]] || fail 'production mode is required'
[[ ${EUID} -eq 0 ]] || fail 'root is required'
for command in awk chmod cmp conntrack grep ip iptables iptables-save kill mktemp \
  mv python3 readlink sha256sum sleep sort stat systemctl; do
  command -v "${command}" >/dev/null 2>&1 || fail 'a required command is unavailable'
done
for file in "${EVIDENCE_HELPER}" "${STREAM_PROBE}" "${STATUS_GATE}" "${NAT_EVIDENCE}"; do
  [[ -f ${file} && ! -L ${file} ]] || fail 'a qualification helper is unavailable'
done
# shellcheck source=gate-evidence.sh
source "${EVIDENCE_HELPER}"
umask 077
campus_link_acquire_deployment_shared_lock
campus_link_acquire_gate_execution_lock

readonly run_manifest=${CAMPUS_LINK_RUN_MANIFEST}
campus_link_validate_run_manifest "${run_manifest}"
run_id=$(campus_link_marker_value "${run_manifest}" RUN_ID) || fail 'run ID lookup failed'
candidate_sha256=$(campus_link_marker_value "${run_manifest}" CANDIDATE_SHA256) || \
  fail 'candidate lookup failed'
run_manifest_sha256=$(campus_link_run_manifest_sha256 "${run_manifest}") || \
  fail 'run manifest digest failed'
campus_link_validate_chain "${run_manifest}" fault-in-stream
prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || \
  fail 'prerequisite digest failed'
[[ ${prerequisite_sha256} =~ ^[a-f0-9]{64}$ ]] || fail 'invalid prerequisite digest'
prerequisite_completed_ms=$(campus_link_marker_value "${PREREQUISITE}" COMPLETE_MONOTONIC_MS) || \
  fail 'prerequisite completion lookup failed'
started_ms=$(campus_link_monotonic_ms) || fail 'monotonic clock read failed'
(( started_ms >= prerequisite_completed_ms )) || fail 'prerequisite time order is invalid'
campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
rm -f -- "${RESULT}"

for namespace in oslab-a oslab-b "${SITE_A_NAMESPACE}" "${SITE_B_NAMESPACE}"; do
  ip netns list | awk '{print $1}' | grep -Fxq "${namespace}" || fail 'a required namespace is absent'
done
[[ -f ${WAN_DEVICE_STATE} && ! -L ${WAN_DEVICE_STATE} ]] || fail 'WAN state is unavailable'
wan_device=$(<"${WAN_DEVICE_STATE}") || fail 'WAN state read failed'
[[ ${wan_device} =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || fail 'WAN device state is invalid'
ip link show dev "${wan_device}" >/dev/null 2>&1 || fail 'WAN device is unavailable'
systemctl is-active --quiet campus-link-edge-a.service campus-link-edge-b.service || \
  fail 'an edge service is inactive'

read_unit_uint() {
  local unit=$1 property=$2 value
  value=$(systemctl show -p "${property}" --value "${unit}") || return 1
  [[ ${value} =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
  printf '%s\n' "${value}"
}

edge_a_restarts=$(read_unit_uint campus-link-edge-a.service NRestarts) || \
  fail 'edge A restart count lookup failed'
edge_b_restarts=$(read_unit_uint campus-link-edge-b.service NRestarts) || \
  fail 'edge B restart count lookup failed'
edge_a_pid=$(read_unit_uint campus-link-edge-a.service MainPID) || \
  fail 'edge A process lookup failed'
edge_b_pid=$(read_unit_uint campus-link-edge-b.service MainPID) || \
  fail 'edge B process lookup failed'
edge_a_invocation=$(systemctl show -p InvocationID --value campus-link-edge-a.service) || \
  fail 'edge A invocation lookup failed'
edge_b_invocation=$(systemctl show -p InvocationID --value campus-link-edge-b.service) || \
  fail 'edge B invocation lookup failed'
(( edge_a_pid > 1 && edge_b_pid > 1 )) || fail 'an edge process is unavailable'
[[ ${edge_a_invocation} =~ ^[a-f0-9]{32}$ && ${edge_b_invocation} =~ ^[a-f0-9]{32}$ ]] || \
  fail 'an edge invocation is invalid'

edge_udp_port() {
  local pid=$1 fd target table row local_address inode extra port_hex port
  local -a socket_rows=()
  local -A socket_inodes=()
  local -A ports=()
  for fd in "/proc/${pid}/fd"/*; do
    target=$(readlink -- "${fd}" 2>/dev/null) || continue
    if [[ ${target} =~ ^socket:\[([0-9]+)\]$ ]]; then
      socket_inodes[${BASH_REMATCH[1]}]=1
    fi
  done
  (( ${#socket_inodes[@]} > 0 )) || return 1
  for table in "/proc/${pid}/net/udp" "/proc/${pid}/net/udp6"; do
    [[ -r ${table} ]] || continue
    collect_complete_lines socket_rows awk 'NR > 1 { print $2, $10 }' "${table}" || return 1
    for row in "${socket_rows[@]}"; do
      read -r local_address inode extra <<< "${row}" || return 1
      [[ -z ${extra} ]] || return 1
      [[ -n ${socket_inodes[${inode}]+present} ]] || continue
      port_hex=${local_address##*:}
      [[ ${port_hex} =~ ^[0-9A-Fa-f]{4}$ ]] || return 1
      port=$((16#${port_hex}))
      (( port > 0 && port <= 65535 )) || return 1
      ports[${port}]=1
    done
  done
  (( ${#ports[@]} == 1 )) || return 1
  printf '%s\n' "${!ports[*]}"
}

edge_a_udp_port=$(edge_udp_port "${edge_a_pid}") || fail 'edge A UDP ownership is ambiguous'
edge_b_udp_port=$(edge_udp_port "${edge_b_pid}") || fail 'edge B UDP ownership is ambiguous'

process_continuity_checks=0
assert_process_continuity() {
  local current_a_restarts current_b_restarts current_a_pid current_b_pid
  local current_a_invocation current_b_invocation
  systemctl is-active --quiet campus-link-edge-a.service campus-link-edge-b.service || return 1
  current_a_restarts=$(read_unit_uint campus-link-edge-a.service NRestarts) || return 1
  current_b_restarts=$(read_unit_uint campus-link-edge-b.service NRestarts) || return 1
  current_a_pid=$(read_unit_uint campus-link-edge-a.service MainPID) || return 1
  current_b_pid=$(read_unit_uint campus-link-edge-b.service MainPID) || return 1
  current_a_invocation=$(systemctl show -p InvocationID --value \
    campus-link-edge-a.service) || return 1
  current_b_invocation=$(systemctl show -p InvocationID --value \
    campus-link-edge-b.service) || return 1
  [[ ${current_a_restarts} == "${edge_a_restarts}" ]] || return 1
  [[ ${current_b_restarts} == "${edge_b_restarts}" ]] || return 1
  [[ ${current_a_pid} == "${edge_a_pid}" ]] || return 1
  [[ ${current_b_pid} == "${edge_b_pid}" ]] || return 1
  [[ ${current_a_invocation} == "${edge_a_invocation}" ]] || return 1
  [[ ${current_b_invocation} == "${edge_b_invocation}" ]] || return 1
  process_continuity_checks=$((process_continuity_checks + 2))
}

evidence_dir=$(mktemp -d /run/campus-link/.nat-rebinding.XXXXXX) || \
  fail 'evidence directory creation failed'
[[ -d ${evidence_dir} && ! -L ${evidence_dir} ]] || fail 'evidence directory is invalid'
evidence_metadata=$(stat -c '%u:%g:%a' -- "${evidence_dir}") || \
  fail 'evidence custody lookup failed'
[[ ${evidence_metadata} == 0:0:700 ]] || fail 'evidence custody is invalid'
iptables-save -t nat > "${evidence_dir}/nat.before"
chmod 0600 "${evidence_dir}/nat.before"

site_a_rule_active=0
site_b_rule_active=0
result_published=0
result_source=
pids=()

delete_temp_rule() {
  local source=$1 source_port=$2 comment=$3 low=$4 high=$5
  while iptables -w -t nat -C POSTROUTING -s "${source}/32" -o "${wan_device}" \
    -p udp --sport "${source_port}" -m comment --comment "${comment}" \
    -j MASQUERADE --to-ports "${low}-${high}" --random-fully 2>/dev/null; do
    iptables -w -t nat -D POSTROUTING -s "${source}/32" -o "${wan_device}" \
      -p udp --sport "${source_port}" -m comment --comment "${comment}" \
      -j MASQUERADE --to-ports "${low}-${high}" --random-fully >/dev/null 2>&1 || return 1
  done
}

cleanup() {
  local status=$? cleanup_failed=0
  trap - EXIT INT TERM HUP
  set +e
  if (( site_a_rule_active != 0 )); then
    delete_temp_rule "${SITE_A_SOURCE}" "${edge_a_udp_port}" "${SITE_A_COMMENT}" \
      "${site_a_low:-1}" "${site_a_high:-1}" || cleanup_failed=1
    conntrack -D -p udp --orig-src "${SITE_A_SOURCE}" --sport "${edge_a_udp_port}" \
      >/dev/null 2>&1 || true
  fi
  if (( site_b_rule_active != 0 )); then
    delete_temp_rule "${SITE_B_SOURCE}" "${edge_b_udp_port}" "${SITE_B_COMMENT}" \
      "${site_b_low:-1}" "${site_b_high:-1}" || cleanup_failed=1
    conntrack -D -p udp --orig-src "${SITE_B_SOURCE}" --sport "${edge_b_udp_port}" \
      >/dev/null 2>&1 || true
  fi
  if [[ -f ${evidence_dir}/nat.before ]]; then
    iptables-save -t nat > "${evidence_dir}/nat.cleanup" 2>/dev/null || cleanup_failed=1
    cmp -s -- "${evidence_dir}/nat.before" "${evidence_dir}/nat.cleanup" || cleanup_failed=1
  else
    cleanup_failed=1
  fi
  if (( ${#pids[@]} > 0 )); then
    kill "${pids[@]}" >/dev/null 2>&1 || true
  fi
  if (( cleanup_failed != 0 )); then
    rm -f -- "${RESULT}"
    status=1
    printf 'NAT-rebinding gate failed: cleanup did not restore the exact NAT ruleset\n' >&2
  elif (( status != 0 && result_published != 0 )); then
    rm -f -- "${RESULT}"
  fi
  rm -f -- "${result_source:-}"
  if [[ ${evidence_dir} == /run/campus-link/.nat-rebinding.* && -d ${evidence_dir} && ! -L ${evidence_dir} ]]; then
    rm -rf -- "${evidence_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

nat_listing=$(iptables-save -t nat) || fail 'NAT ruleset enumeration failed'
if [[ ${nat_listing} == *"--comment ${SITE_A_COMMENT}"* || \
      ${nat_listing} == *"--comment ${SITE_B_COMMENT}"* ]]; then
  fail 'a stale gate-owned NAT rule exists'
fi

mapping_ports() {
  local source=$1 source_port=$2
  conntrack -L -p udp --orig-src "${source}" --sport "${source_port}" -o extended 2>/dev/null | \
    awk -v expected_sport="${source_port}" '
      {
        sport_count=0; dport_count=0; original_sport=""; original_dport=""; reply_dport=""
        for (field=1; field<=NF; field++) {
          if ($field ~ /^sport=[0-9]+$/) {
            value=$field; sub(/^sport=/, "", value); sport_count++
            if (sport_count == 1) original_sport=value
          }
          if ($field ~ /^dport=[0-9]+$/) {
            value=$field; sub(/^dport=/, "", value); dport_count++
            if (dport_count == 1) original_dport=value
            if (dport_count == 2) reply_dport=value
          }
        }
        if (original_sport == expected_sport && original_dport == 443 &&
            reply_dport ~ /^[0-9]+$/ && reply_dport > 0 && reply_dport <= 65535) {
          print reply_dport
        }
      }
    ' | LC_ALL=C sort -nu
}

all_socket_mapping_ports() {
  local source=$1 source_port=$2
  conntrack -L -p udp --orig-src "${source}" --sport "${source_port}" -o extended 2>/dev/null | \
    awk -v expected_sport="${source_port}" '
      {
        sport_count=0; dport_count=0; original_sport=""; reply_dport=""
        for (field=1; field<=NF; field++) {
          if ($field ~ /^sport=[0-9]+$/) {
            value=$field; sub(/^sport=/, "", value); sport_count++
            if (sport_count == 1) original_sport=value
          }
          if ($field ~ /^dport=[0-9]+$/) {
            value=$field; sub(/^dport=/, "", value); dport_count++
            if (dport_count == 2) reply_dport=value
          }
        }
        if (original_sport == expected_sport && reply_dport ~ /^[0-9]+$/ &&
            reply_dport > 0 && reply_dport <= 65535) print reply_dport
      }
    '
}

sorted_socket_mapping_ports() {
  local source=$1 source_port=$2
  all_socket_mapping_ports "${source}" "${source_port}" | LC_ALL=C sort -nu
}

wait_single_mapping() {
  local source=$1 source_port=$2 mode=$3 reference=${4:-0} low=${5:-0} high=${6:-0}
  local deadline now candidate
  local -a values=()
  now=$(campus_link_monotonic_ms) || return 1
  deadline=$((now + 10000))
  while :; do
    collect_complete_lines values mapping_ports "${source}" "${source_port}" || return 1
    if (( ${#values[@]} == 1 )); then
      candidate=${values[0]}
      [[ ${candidate} =~ ^[0-9]+$ ]] || return 1
      case ${mode} in
        any) printf '%s\n' "${candidate}"; return 0 ;;
        forced)
          if (( candidate != reference && candidate >= low && candidate <= high )); then
            printf '%s\n' "${candidate}"
            return 0
          fi
          ;;
        restored)
          if (( candidate != reference )); then
            printf '%s\n' "${candidate}"
            return 0
          fi
          ;;
        equal)
          if (( candidate == reference )); then
            printf '%s\n' "${candidate}"
            return 0
          fi
          ;;
        *) return 1 ;;
      esac
    fi
    now=$(campus_link_monotonic_ms) || return 1
    (( now < deadline )) || return 1
    sleep 0.05
  done
}

choose_forced_range() {
  local source=$1 source_port=$2 local_port=$3 low high occupied collision
  local -a occupied_ports=()
  collect_complete_lines occupied_ports sorted_socket_mapping_ports \
    "${source}" "${source_port}" || return 1
  (( ${#occupied_ports[@]} > 0 )) || return 1
  for low in 40000 45000 50000 55000; do
    high=$((low + 4999))
    collision=0
    if (( local_port >= low && local_port <= high )); then
      collision=1
    fi
    for occupied in "${occupied_ports[@]}"; do
      if (( occupied >= low && occupied <= high )); then
        collision=1
      fi
    done
    if (( collision == 0 )); then
      printf '%s %s\n' "${low}" "${high}"
      return 0
    fi
  done
  return 1
}

assert_socket_mapping_profile() {
  local source=$1 source_port=$2 mode=$3 low=$4 high=$5 value
  local -a ports=()
  collect_complete_lines ports all_socket_mapping_ports \
    "${source}" "${source_port}" || return 1
  (( ${#ports[@]} >= 2 )) || return 1
  for value in "${ports[@]}"; do
    [[ ${value} =~ ^[0-9]+$ ]] || return 1
    case ${mode} in
      forced) (( value >= low && value <= high )) || return 1 ;;
      restored) ! (( value >= low && value <= high )) || return 1 ;;
      *) return 1 ;;
    esac
  done
}

delete_scoped_conntrack() {
  local source=$1 source_port=$2
  conntrack -D -p udp --orig-src "${source}" --sport "${source_port}" \
    >/dev/null 2>&1
}

capture_status() {
  local output=$1
  python3 -B "${STATUS_GATE}" capture \
    --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" --output "${output}"
}

wait_direct() {
  python3 -B "${STATUS_GATE}" wait-direct \
    --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" --timeout-seconds 5
}

wait_stream_boundary() {
  local prior=$1 output=$2
  python3 -B "${NAT_EVIDENCE}" wait-running \
    --progress "${evidence_dir}/progress.json" --after "${prior}" --output "${output}" \
    --timeout-seconds "${FAULT_RECOVERY_TIMEOUT_SECONDS}"
}

add_temp_rule() {
  local source=$1 source_port=$2 comment=$3 low=$4 high=$5
  iptables -w -t nat -I POSTROUTING 1 -s "${source}/32" -o "${wan_device}" \
    -p udp --sport "${source_port}" -m comment --comment "${comment}" \
    -j MASQUERADE --to-ports "${low}-${high}" --random-fully >/dev/null 2>&1
  iptables -w -t nat -C POSTROUTING -s "${source}/32" -o "${wan_device}" \
    -p udp --sport "${source_port}" -m comment --comment "${comment}" \
    -j MASQUERADE --to-ports "${low}-${high}" --random-fully >/dev/null 2>&1
}

assert_nat_restored() {
  iptables-save -t nat > "${evidence_dir}/nat.current"
  cmp -s -- "${evidence_dir}/nat.before" "${evidence_dir}/nat.current"
}

conntrack_scoped_deletions=0
mapping_change_observations=0
socket_mapping_profile_checks=0
untouched_wan_mapping_checks=0
nat_ruleset_restorations=0
current_progress=${evidence_dir}/progress-before.json

run_site_trial() {
  local label=$1 source=$2 source_port=$3 comment=$4 forced_status=$5 restored_status=$6
  local forced_progress=$7 restored_progress=$8 peer_source=$9 peer_source_port=${10}
  local old_mapping forced_mapping restored_mapping peer_mapping forced_range low high extra
  local pre_forced=${evidence_dir}/progress-${label}-pre-forced.json
  local pre_restored=${evidence_dir}/progress-${label}-pre-restored.json
  (( site_a_rule_active == 0 && site_b_rule_active == 0 )) || \
    fail 'NAT fault trials overlapped'
  peer_mapping=$(wait_single_mapping "${peer_source}" "${peer_source_port}" any) || \
    fail 'the untouched WAN mapping was not uniquely observable'
  old_mapping=$(wait_single_mapping "${source}" "${source_port}" any) || \
    fail 'a pre-fault external UDP mapping was not uniquely observable'
  forced_range=$(choose_forced_range "${source}" "${source_port}" "${source_port}") || \
    fail 'a disjoint forced port range was unavailable'
  [[ ${forced_range} =~ ^[0-9]+\ [0-9]+$ ]] || fail 'a forced port range was malformed'
  read -r low high extra <<< "${forced_range}" || fail 'a forced port range was unreadable'
  [[ -z ${extra} ]] || fail 'a forced port range contained extra fields'
  if [[ ${label} == site-a ]]; then
    site_a_low=${low}; site_a_high=${high}; site_a_rule_active=1
  else
    site_b_low=${low}; site_b_high=${high}; site_b_rule_active=1
  fi
  add_temp_rule "${source}" "${source_port}" "${comment}" "${low}" "${high}" || \
    fail 'temporary NAT rule installation failed'
  # Pin a record boundary after rule insertion but before deleting the old
  # mapping. The post-fault checkpoint must advance beyond this fresh pin, not
  # merely beyond an older trial boundary.
  wait_stream_boundary "${current_progress}" "${pre_forced}" || \
    fail 'the pre-fault TCP stream checkpoint did not advance'
  delete_scoped_conntrack "${source}" "${source_port}" || \
    fail 'scoped conntrack deletion found no mapping'
  conntrack_scoped_deletions=$((conntrack_scoped_deletions + 1))
  forced_mapping=$(wait_single_mapping "${source}" "${source_port}" forced \
    "${old_mapping}" "${low}" "${high}") || fail 'forced external UDP mapping did not change'
  mapping_change_observations=$((mapping_change_observations + 1))
  wait_stream_boundary "${pre_forced}" "${forced_progress}" || \
    fail 'the original TCP stream did not cross a forced mapping change'
  assert_socket_mapping_profile "${source}" "${source_port}" forced "${low}" "${high}" || \
    fail 'the forced direct-socket mapping profile was not observed'
  socket_mapping_profile_checks=$((socket_mapping_profile_checks + 1))
  wait_direct || fail 'authenticated direct recovery did not complete'
  capture_status "${forced_status}"
  assert_process_continuity || fail 'an edge process changed during NAT rebinding'
  kill -0 "${client_pid}" "${server_pid}" 2>/dev/null || fail 'the pinned stream process changed'
  wait_single_mapping "${peer_source}" "${peer_source_port}" equal "${peer_mapping}" \
    >/dev/null || fail 'the untouched WAN mapping changed during the peer fault'
  untouched_wan_mapping_checks=$((untouched_wan_mapping_checks + 1))
  current_progress=${forced_progress}

  # Pin another complete record while the forced mapping is active. Mapping
  # restoration must carry a later record on the same socket.
  wait_stream_boundary "${current_progress}" "${pre_restored}" || \
    fail 'the forced-mapping TCP stream checkpoint did not advance'
  delete_temp_rule "${source}" "${source_port}" "${comment}" "${low}" "${high}" || \
    fail 'temporary NAT rule removal failed'
  if [[ ${label} == site-a ]]; then site_a_rule_active=0; else site_b_rule_active=0; fi
  delete_scoped_conntrack "${source}" "${source_port}" || \
    fail 'scoped restoration conntrack deletion found no mapping'
  conntrack_scoped_deletions=$((conntrack_scoped_deletions + 1))
  restored_mapping=$(wait_single_mapping "${source}" "${source_port}" restored \
    "${forced_mapping}") || fail 'restored external UDP mapping did not change'
  [[ ${restored_mapping} != "${forced_mapping}" ]] || fail 'restored mapping reused the forced tuple'
  mapping_change_observations=$((mapping_change_observations + 1))
  wait_stream_boundary "${pre_restored}" "${restored_progress}" || \
    fail 'the original TCP stream did not cross mapping restoration'
  assert_socket_mapping_profile "${source}" "${source_port}" restored "${low}" "${high}" || \
    fail 'the restored direct-socket mapping profile was not observed'
  socket_mapping_profile_checks=$((socket_mapping_profile_checks + 1))
  wait_direct || fail 'authenticated direct restoration did not complete'
  capture_status "${restored_status}"
  assert_process_continuity || fail 'an edge process changed during NAT restoration'
  kill -0 "${client_pid}" "${server_pid}" 2>/dev/null || fail 'the pinned stream process changed'
  wait_single_mapping "${peer_source}" "${peer_source_port}" equal "${peer_mapping}" \
    >/dev/null || fail 'the untouched WAN mapping changed during peer restoration'
  untouched_wan_mapping_checks=$((untouched_wan_mapping_checks + 1))
  current_progress=${restored_progress}
  assert_nat_restored || fail 'the exact pre-gate NAT ruleset was not restored'
  nat_ruleset_restorations=$((nat_ruleset_restorations + 1))
}

ip netns exec oslab-b python3 -B "${STREAM_PROBE}" serve-once \
  --bind 10.82.0.22 --port "${STREAM_PORT}" --max-stream-bytes "${STREAM_RECORD_BYTES}" \
  --progress-timeout 30 --phase-timeout 370 --accept-timeout 30 \
  >"${evidence_dir}/server.log" 2>&1 &
server_pid=$!
pids+=("${server_pid}")
sleep 1
kill -0 "${server_pid}" 2>/dev/null || fail 'stream server did not start'
python3 -B "${STATUS_GATE}" wait-direct \
  --edge-a "${EDGE_A_STATUS}" --edge-b "${EDGE_B_STATUS}" --timeout-seconds 60

ip netns exec oslab-a python3 -B "${STREAM_PROBE}" continuous-client \
  --source 10.81.0.11 --destination 10.82.0.22 --port "${STREAM_PORT}" \
  --duration-seconds "${STREAM_DEADLINE_SECONDS}" \
  --completion-grace-seconds "${STREAM_COMPLETION_GRACE_SECONDS}" \
  --record-bytes "${STREAM_RECORD_BYTES}" --send-sequence "${A_TO_B_SEQUENCE}" \
  --receive-sequence "${B_TO_A_SEQUENCE}" --progress-timeout 30 --progress-interval 0.05 \
  --progress-file "${evidence_dir}/progress.json" --stop-file "${evidence_dir}/stop" \
  >"${evidence_dir}/client.log" 2>&1 &
client_pid=$!
pids+=("${client_pid}")

python3 -B "${NAT_EVIDENCE}" wait-running \
  --progress "${evidence_dir}/progress.json" --output "${current_progress}" \
  --timeout-seconds 30
capture_status "${evidence_dir}/status-before.json"
assert_process_continuity || fail 'an edge process changed before the first fault'

run_site_trial site-a "${SITE_A_SOURCE}" "${edge_a_udp_port}" "${SITE_A_COMMENT}" \
  "${evidence_dir}/status-site-a-forced.json" "${evidence_dir}/status-site-a-restored.json" \
  "${evidence_dir}/progress-site-a-forced.json" "${evidence_dir}/progress-site-a-restored.json" \
  "${SITE_B_SOURCE}" "${edge_b_udp_port}"
run_site_trial site-b "${SITE_B_SOURCE}" "${edge_b_udp_port}" "${SITE_B_COMMENT}" \
  "${evidence_dir}/status-site-b-forced.json" "${evidence_dir}/status-site-b-restored.json" \
  "${evidence_dir}/progress-site-b-forced.json" "${evidence_dir}/progress-site-b-restored.json" \
  "${SITE_A_SOURCE}" "${edge_a_udp_port}"

(( conntrack_scoped_deletions == 4 )) || fail 'conntrack deletion count is invalid'
(( mapping_change_observations == 4 )) || fail 'mapping observation count is invalid'
(( socket_mapping_profile_checks == 4 )) || fail 'socket mapping profile check count is invalid'
(( untouched_wan_mapping_checks == 4 )) || fail 'untouched WAN mapping check count is invalid'
(( nat_ruleset_restorations == 2 )) || fail 'NAT restoration count is invalid'
(( process_continuity_checks == 10 )) || fail 'process continuity count is invalid'

stop_tmp=$(mktemp "${evidence_dir}/.stop.XXXXXX") || fail 'stop marker creation failed'
printf 'CAMPUS_LINK_STOP=1\n' > "${stop_tmp}"
chmod 0600 "${stop_tmp}"
mv -fT -- "${stop_tmp}" "${evidence_dir}/stop"
python3 -B "${NAT_EVIDENCE}" wait-pass \
  --progress "${evidence_dir}/progress.json" --after "${current_progress}" \
  --output "${evidence_dir}/progress-final.json" --timeout-seconds 60
wait "${client_pid}" || fail 'continuous stream client failed'
client_pid=
wait "${server_pid}" || fail 'single-accept stream server failed'
server_pid=
pids=()
grep -Eq '^PASS connections=1 reconnects=0 records=[1-9][0-9]* ' \
  "${evidence_dir}/client.log" || fail 'continuous client summary is invalid'
grep -Eq '^PASS connections=1 reconnects=0 records=[1-9][0-9]*$' \
  "${evidence_dir}/server.log" || fail 'single-accept server summary is invalid'
assert_nat_restored || fail 'final NAT ruleset restoration failed'
assert_process_continuity || fail 'an edge process changed before publication'
(( process_continuity_checks == 12 )) || fail 'final process continuity count is invalid'

python3 -B "${NAT_EVIDENCE}" verify \
  --status-before "${evidence_dir}/status-before.json" \
  --status-site-a-forced "${evidence_dir}/status-site-a-forced.json" \
  --status-site-a-restored "${evidence_dir}/status-site-a-restored.json" \
  --status-site-b-forced "${evidence_dir}/status-site-b-forced.json" \
  --status-site-b-restored "${evidence_dir}/status-site-b-restored.json" \
  --progress-before "${evidence_dir}/progress-before.json" \
  --progress-site-a-forced "${evidence_dir}/progress-site-a-forced.json" \
  --progress-site-a-restored "${evidence_dir}/progress-site-a-restored.json" \
  --progress-site-b-forced "${evidence_dir}/progress-site-b-forced.json" \
  --progress-site-b-restored "${evidence_dir}/progress-site-b-restored.json" \
  --progress-final "${evidence_dir}/progress-final.json" \
  --process-continuity-checks "${process_continuity_checks}" \
  > "${evidence_dir}/verified.env"
campus_link_validate_schema "${evidence_dir}/verified.env" "${NAT_REBIND_EVIDENCE_KEYS[@]}"

campus_link_assert_run_immutable "${run_manifest}" "${run_manifest_sha256}" "${candidate_sha256}"
current_prerequisite_sha256=$(sha256sum -- "${PREREQUISITE}" | awk '{print $1}') || \
  fail 'prerequisite digest recheck failed'
[[ ${current_prerequisite_sha256} == "${prerequisite_sha256}" ]] || \
  fail 'prerequisite marker changed during the gate'
assert_nat_restored || fail 'NAT ruleset changed before publication'
completed_ms=$(campus_link_monotonic_ms) || fail 'completion clock read failed'
(( completed_ms >= started_ms )) || fail 'completion time is invalid'
result_source=$(mktemp /run/campus-link/.nat-rebinding-result.XXXXXX) || \
  fail 'result marker creation failed'
{
  printf 'FORMAT=1\nSTATUS=pass\nGATE=nat-rebinding\nMODE=production\nRUN_ID=%s\nCANDIDATE_SHA256=%s\nRUN_MANIFEST_SHA256=%s\nPREREQUISITE_MARKER_SHA256=%s\nSTART_MONOTONIC_MS=%s\nCOMPLETE_MONOTONIC_MS=%s\nFAULT_SITES=2\nFORCED_MAPPING_CHANGES=2\nRESTORATION_MAPPING_CHANGES=2\nMAPPING_CHANGE_OBSERVATIONS=4\nSOCKET_MAPPING_PROFILE_CHECKS=4\nUNTOUCHED_WAN_MAPPING_CHECKS=4\nCONNTRACK_SCOPED_DELETIONS=4\nNAT_RULESET_RESTORATIONS=2\nFAULT_RECOVERY_TIMEOUT_MS=%s\n' \
    "${run_id}" "${candidate_sha256}" "${run_manifest_sha256}" \
    "${prerequisite_sha256}" "${started_ms}" "${completed_ms}" \
    "${FAULT_RECOVERY_TIMEOUT_MS}"
  cat -- "${evidence_dir}/verified.env"
} > "${result_source}"
campus_link_validate_gate_marker "${result_source}" "${run_manifest}" \
  nat-rebinding production FAULT_SITES FORCED_MAPPING_CHANGES \
  RESTORATION_MAPPING_CHANGES MAPPING_CHANGE_OBSERVATIONS \
  SOCKET_MAPPING_PROFILE_CHECKS \
  UNTOUCHED_WAN_MAPPING_CHECKS \
  CONNTRACK_SCOPED_DELETIONS NAT_RULESET_RESTORATIONS \
  FAULT_RECOVERY_TIMEOUT_MS "${NAT_REBIND_EVIDENCE_KEYS[@]}"
campus_link_atomic_marker "${RESULT}" "${result_source}"
rm -f -- "${result_source}"
result_published=1
printf 'STATUS=pass\nMODE=production\nFAULT_SITES=2\nMAPPING_CHANGE_OBSERVATIONS=4\nTCP_CONNECTIONS=1\nTCP_RECONNECTS=0\n'
