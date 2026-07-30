#!/usr/bin/env bash

# Shared fail-closed helpers for the supervised qualification gates. Callers
# must already use `set -euo pipefail` and run as root. Nothing in this file is
# a deploy operation; the shared install lock only prevents a candidate from
# changing while evidence is being collected.

readonly CAMPUS_LINK_RUN_DIR=/run/campus-link
readonly CAMPUS_LINK_RUN_MANIFEST=${CAMPUS_LINK_RUN_DIR}/qualification-run.manifest
readonly CAMPUS_LINK_DEPLOY_LOCK=/run/campus-link-install-edge.lock
readonly CAMPUS_LINK_GATE_LOCK=${CAMPUS_LINK_RUN_DIR}/qualification-gate.lock
readonly CAMPUS_LINK_DEPLOYMENT_ATTESTATION=/var/lib/campus-link/deployment-attestation.env
readonly CAMPUS_LINK_RELEASE_MANIFEST=/var/lib/campus-link/installed-release-manifest.sha256
readonly -a CAMPUS_LINK_DIRECT_EVIDENCE_KEYS=(
  DIRECT_EVIDENCE_DURATION_MS
  EDGE_A_DIRECT_PROGRESS_DELTA
  EDGE_A_DIRECT_RECEIVED_DELTA
  EDGE_A_DIRECT_SENT_DELTA
  EDGE_A_DROPPED_DELTA
  EDGE_A_DUPLICATE_PACKETS_DELTA
  EDGE_A_FALLBACKS_DELTA
  EDGE_A_INVALID_PACKETS_DELTA
  EDGE_A_QUEUE_DROPS_DELTA
  EDGE_A_RELAY_RECEIVED_DELTA
  EDGE_A_RELAY_SENT_DELTA
  EDGE_A_WATCHDOG_FAILURES_DELTA
  EDGE_B_DIRECT_PROGRESS_DELTA
  EDGE_B_DIRECT_RECEIVED_DELTA
  EDGE_B_DIRECT_SENT_DELTA
  EDGE_B_DROPPED_DELTA
  EDGE_B_DUPLICATE_PACKETS_DELTA
  EDGE_B_FALLBACKS_DELTA
  EDGE_B_INVALID_PACKETS_DELTA
  EDGE_B_QUEUE_DROPS_DELTA
  EDGE_B_RELAY_RECEIVED_DELTA
  EDGE_B_RELAY_SENT_DELTA
  EDGE_B_WATCHDOG_FAILURES_DELTA
  RAW_RELAY_BYTE_LIMIT_PER_SITE
  RAW_RELAY_PACKET_LIMIT_PER_SITE
  RAW_RELAY_SITE_A_BYTES_DELTA
  RAW_RELAY_SITE_A_DELTA
  RAW_RELAY_SITE_B_BYTES_DELTA
  RAW_RELAY_SITE_B_DELTA
)
readonly -a CAMPUS_LINK_FAULT_EVIDENCE_KEYS=(
  FAULT_DIRECT_EVIDENCE_DURATION_MS
  FAULT_EDGE_A_DIRECT_PROGRESS_DELTA
  FAULT_EDGE_A_DIRECT_RECEIVED_DELTA
  FAULT_EDGE_A_DIRECT_SENT_DELTA
  FAULT_EDGE_A_DROPPED_DELTA
  FAULT_EDGE_A_DUPLICATE_PACKETS_DELTA
  FAULT_EDGE_A_FALLBACKS_DELTA
  FAULT_EDGE_A_INVALID_PACKETS_DELTA
  FAULT_EDGE_A_QUEUE_DROPS_DELTA
  FAULT_EDGE_A_RELAY_RECEIVED_DELTA
  FAULT_EDGE_A_RELAY_SENT_DELTA
  FAULT_EDGE_A_WATCHDOG_FAILURES_DELTA
  FAULT_EDGE_B_DIRECT_PROGRESS_DELTA
  FAULT_EDGE_B_DIRECT_RECEIVED_DELTA
  FAULT_EDGE_B_DIRECT_SENT_DELTA
  FAULT_EDGE_B_DROPPED_DELTA
  FAULT_EDGE_B_DUPLICATE_PACKETS_DELTA
  FAULT_EDGE_B_FALLBACKS_DELTA
  FAULT_EDGE_B_INVALID_PACKETS_DELTA
  FAULT_EDGE_B_QUEUE_DROPS_DELTA
  FAULT_EDGE_B_RELAY_RECEIVED_DELTA
  FAULT_EDGE_B_RELAY_SENT_DELTA
  FAULT_EDGE_B_WATCHDOG_FAILURES_DELTA
  FAULT_EXACT_PATH_IDENTITY_CHECKS
  FAULT_RAW_RELAY_BYTE_LIMIT_PER_SITE
  FAULT_RAW_RELAY_PACKET_LIMIT_PER_SITE
  FAULT_RAW_RELAY_SITE_A_BYTES_DELTA
  FAULT_RAW_RELAY_SITE_A_DELTA
  FAULT_RAW_RELAY_SITE_B_BYTES_DELTA
  FAULT_RAW_RELAY_SITE_B_DELTA
  FAULT_REESTABLISHED_DIRECT_PATHS
  FAULT_RELAY_CONTROL_SESSION_TRANSITIONS
)
readonly -a CAMPUS_LINK_ACCELERATED_STREAM_KEYS=(
  MAX_RECOVERY_MS
  STREAM_RECORD_BYTES
  STREAM_PROGRESS_TIMEOUT_MS
  TCP_CONNECTIONS
  TCP_RECONNECTS
  FULL_DUPLEX_RECORDS
  STREAM_BYTES_A_TO_B
  STREAM_BYTES_B_TO_A
  PRE_RESTART_PROGRESS_CHECKS
  REPLACEMENT_ACTIVE_CHECKPOINTS
  POST_RESTART_PROGRESS_CHECKS
  STREAM_SURVIVAL_CHECKS
  MAX_PROGRESS_GAP_A_TO_B_MS
  MAX_PROGRESS_GAP_B_TO_A_MS
  STREAM_DIGEST_DIRECTIONS
  STREAM_TRANSCRIPT_SHA256
)
readonly -a CAMPUS_LINK_NAT_REBIND_EVIDENCE_KEYS=(
  MATCHED_DIRECT_EPOCH_CHECKS
  MIGRATED_PATHS
  REESTABLISHED_PATHS
  HIGHER_DIRECT_INSTANCE_EDGE_CHECKS
  PROCESS_CONTINUITY_CHECKS
  TCP_CONNECTIONS
  TCP_RECONNECTS
  STREAM_RECORD_BYTES
  FULL_DUPLEX_RECORDS
  STREAM_BYTES_A_TO_B
  STREAM_BYTES_B_TO_A
  FIRST_A_TO_B_SEQUENCE
  LAST_A_TO_B_SEQUENCE
  FIRST_B_TO_A_SEQUENCE
  LAST_B_TO_A_SEQUENCE
  STREAM_TRANSCRIPT_SHA256
  MAX_PROGRESS_GAP_A_TO_B_MS
  MAX_PROGRESS_GAP_B_TO_A_MS
  EDGE_A_DIRECT_SENT_DELTA
  EDGE_A_DIRECT_RECEIVED_DELTA
  EDGE_A_DIRECT_PROGRESS_DELTA
  EDGE_A_RELAY_SENT_DELTA
  EDGE_A_RELAY_RECEIVED_DELTA
  EDGE_B_DIRECT_SENT_DELTA
  EDGE_B_DIRECT_RECEIVED_DELTA
  EDGE_B_DIRECT_PROGRESS_DELTA
  EDGE_B_RELAY_SENT_DELTA
  EDGE_B_RELAY_RECEIVED_DELTA
  RAW_RELAY_PACKET_LIMIT_PER_SITE
  RAW_RELAY_BYTE_LIMIT_PER_SITE
  RAW_RELAY_SITE_A_DELTA
  RAW_RELAY_SITE_A_BYTES_DELTA
  RAW_RELAY_SITE_B_DELTA
  RAW_RELAY_SITE_B_BYTES_DELTA
)
readonly -a CAMPUS_LINK_CONTINUOUS_STREAM_KEYS=(
  TCP_CONNECTIONS
  TCP_RECONNECTS
  FULL_DUPLEX_RECORDS
  STREAM_BYTES_A_TO_B
  STREAM_BYTES_B_TO_A
  FIRST_A_TO_B_SEQUENCE
  LAST_A_TO_B_SEQUENCE
  FIRST_B_TO_A_SEQUENCE
  LAST_B_TO_A_SEQUENCE
  STREAM_TRANSCRIPT_SHA256
  PROGRESS_TIMEOUT_MS
  COMPLETION_GRACE_SECONDS
  MAX_PROGRESS_GAP_A_TO_B_MS
  MAX_PROGRESS_GAP_B_TO_A_MS
  PROGRESS_OBSERVATIONS
  DIRECT_STATUS_OBSERVATIONS
)

campus_link_monotonic_ms() {
  local uptime whole fraction
  read -r uptime _ < /proc/uptime || return 1
  [[ ${uptime} =~ ^([0-9]+)\.([0-9]+)$ ]] || return 1
  whole=${BASH_REMATCH[1]}
  fraction=${BASH_REMATCH[2]}000
  fraction=${fraction:0:3}
  printf '%s\n' "$((10#${whole} * 1000 + 10#${fraction}))"
}

campus_link_boot_id_sha256() {
  local digest
  [[ -f /proc/sys/kernel/random/boot_id && ! -L /proc/sys/kernel/random/boot_id ]] || return 1
  digest=$(sha256sum -- /proc/sys/kernel/random/boot_id | awk '{print $1}') || return 1
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

campus_link_require_root_file() {
  local path=$1 expected_mode=${2:-} metadata mode
  [[ -f ${path} && ! -L ${path} ]] || return 1
  metadata=$(stat -c '%u:%g' -- "${path}") || return 1
  [[ ${metadata} == 0:0 ]] || return 1
  if [[ -n ${expected_mode} ]]; then
    mode=$(stat -c '%a' -- "${path}") || return 1
    [[ ${mode} == "${expected_mode}" ]] || return 1
  fi
}

campus_link_marker_value() {
  local marker=$1 key=$2 line marker_size octets grep_status last_byte
  local -a lines=() matches=()
  [[ ${key} =~ ^[A-Z][A-Z0-9_]*$ ]] || return 1
  [[ -f ${marker} && ! -L ${marker} ]] || return 1
  marker_size=$(stat -c '%s' -- "${marker}") || return 1
  [[ ${marker_size} =~ ^[0-9]+$ ]] || return 1
  (( marker_size > 0 && marker_size <= 65536 )) || return 1
  octets=$(od -An -v -t u1 -- "${marker}") || return 1
  if grep -Eq '(^|[[:space:]])0($|[[:space:]])' <<< "${octets}"; then
    return 1
  else
    grep_status=$?
    (( grep_status == 1 )) || return 1
  fi
  last_byte=$(tail -c 1 -- "${marker}" | od -An -t u1 | tr -d '[:space:]') || return 1
  [[ ${last_byte} == 10 ]] || return 1
  mapfile -t lines < "${marker}" || return 1
  for line in "${lines[@]}"; do
    if [[ ${line} == "${key}="* ]]; then
      matches+=("${line}")
    fi
  done
  [[ ${#matches[@]} -eq 1 ]] || return 1
  printf '%s' "${matches[0]#*=}"
}

campus_link_marker_equals() {
  local marker=$1 key=$2 expected=$3 actual
  actual=$(campus_link_marker_value "${marker}" "${key}") || return 1
  [[ ${actual} == "${expected}" ]]
}

campus_link_validate_schema() {
  local file=$1
  shift
  local index line key position last_byte file_size octets grep_status
  local -a lines=()
  campus_link_require_root_file "${file}" 600 || return 1
  file_size=$(stat -c '%s' -- "${file}") || return 1
  [[ ${file_size} =~ ^[0-9]+$ ]] || return 1
  (( file_size > 0 && file_size <= 65536 )) || return 1
  octets=$(od -An -v -t u1 -- "${file}") || return 1
  if grep -Eq '(^|[[:space:]])0($|[[:space:]])' <<< "${octets}"; then
    return 1
  else
    grep_status=$?
    (( grep_status == 1 )) || return 1
  fi
  last_byte=$(tail -c 1 -- "${file}" | od -An -t u1 | tr -d '[:space:]') || return 1
  [[ ${last_byte} == 10 ]] || return 1
  mapfile -t lines < "${file}" || return 1
  [[ ${#lines[@]} -eq $# ]] || return 1
  for index in "${!lines[@]}"; do
    line=${lines[index]}
    position=$((index + 1))
    key=${!position}
    [[ ${line} =~ ^${key}=[A-Za-z0-9._:+-]+$ ]] || return 1
  done
}

campus_link_validate_deployment_attestation() {
  local version source_tree manifest_digest actual_manifest_digest installed_version
  campus_link_validate_schema "${CAMPUS_LINK_DEPLOYMENT_ATTESTATION}" \
    VERSION SOURCE_TREE_SHA256 MANIFEST_SHA256 || return 1
  version=$(campus_link_marker_value "${CAMPUS_LINK_DEPLOYMENT_ATTESTATION}" VERSION) || return 1
  source_tree=$(campus_link_marker_value "${CAMPUS_LINK_DEPLOYMENT_ATTESTATION}" SOURCE_TREE_SHA256) || return 1
  manifest_digest=$(campus_link_marker_value "${CAMPUS_LINK_DEPLOYMENT_ATTESTATION}" MANIFEST_SHA256) || return 1
  [[ ${version} =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$ ]] || return 1
  [[ ${source_tree} =~ ^[a-f0-9]{64}$ && ${manifest_digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  campus_link_require_root_file "${CAMPUS_LINK_RELEASE_MANIFEST}" 600 || return 1
  campus_link_validate_release_manifest "${CAMPUS_LINK_RELEASE_MANIFEST}" || return 1
  actual_manifest_digest=$(sha256sum -- "${CAMPUS_LINK_RELEASE_MANIFEST}" | awk '{print $1}') || return 1
  [[ ${actual_manifest_digest} == "${manifest_digest}" ]] || return 1
  [[ -f /var/lib/campus-link/installed-edge-version && \
    ! -L /var/lib/campus-link/installed-edge-version ]] || return 1
  installed_version=$(< /var/lib/campus-link/installed-edge-version) || return 1
  [[ ${installed_version} == "${version}" ]] || return 1
}

campus_link_validate_release_manifest() {
  local manifest=$1 line digest name previous= file_size octets grep_status last_byte
  local LC_ALL=C
  local count=0
  local -a lines=()
  declare -A seen=()
  file_size=$(stat -c '%s' -- "${manifest}") || return 1
  [[ ${file_size} =~ ^[0-9]+$ ]] || return 1
  (( file_size > 0 && file_size <= 65536 )) || return 1
  octets=$(od -An -v -t u1 -- "${manifest}") || return 1
  if grep -Eq '(^|[[:space:]])0($|[[:space:]])' <<< "${octets}"; then
    return 1
  else
    grep_status=$?
    (( grep_status == 1 )) || return 1
  fi
  last_byte=$(tail -c 1 -- "${manifest}" | od -An -t u1 | tr -d '[:space:]') || return 1
  [[ ${last_byte} == 10 ]] || return 1
  mapfile -t lines < "${manifest}" || return 1
  for line in "${lines[@]}"; do
    [[ ${line} =~ ^([a-f0-9]{64})\ \ ([A-Za-z0-9._/-]+)$ ]] || return 1
    digest=${BASH_REMATCH[1]}
    name=${BASH_REMATCH[2]}
    [[ ${name} != /* && ${name} != */../* && ${name} != ../* && \
      ${name} != */.. && ${name} != *//* ]] || return 1
    [[ -z ${seen[${name}]+present} ]] || return 1
    seen[${name}]=1
    if [[ -n ${previous} ]]; then
      [[ ${previous} < ${name} ]] || return 1
    fi
    previous=${name}
    count=$((count + 1))
    (( count <= 4096 )) || return 1
    : "${digest}"
  done
  (( count > 0 ))
}

campus_link_is_uint() {
  [[ $1 =~ ^(0|[1-9][0-9]{0,15})$ ]]
}

campus_link_is_shell_uint() {
  local value=$1 maximum=9223372036854775807
  local LC_ALL=C
  [[ ${value} =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
  [[ ${#value} -lt 19 || ${value} < "${maximum}" || ${value} == "${maximum}" ]]
}

campus_link_marker_uint() {
  local value
  value=$(campus_link_marker_value "$1" "$2") || return 1
  campus_link_is_uint "${value}" || return 1
  printf '%s' "${value}"
}

campus_link_marker_shell_uint() {
  local value
  value=$(campus_link_marker_value "$1" "$2") || return 1
  campus_link_is_shell_uint "${value}" || return 1
  printf '%s' "${value}"
}

campus_link_validate_direct_evidence_values() {
  local marker=$1 max_duration=${2:-28800000} minimum_packets=${3:-1000}
  local minimum_duration=${4:-1}
  local direct_duration raw_limit expected_raw_limit raw_a raw_b
  local byte_limit expected_byte_limit raw_a_bytes raw_b_bytes
  local a_progress a_received a_sent a_dropped a_duplicates a_fallbacks a_invalid a_queue
  local a_relay a_relay_received a_watchdog
  local b_progress b_received b_sent b_dropped b_duplicates b_fallbacks b_invalid b_queue
  local b_relay b_relay_received b_watchdog
  campus_link_is_uint "${max_duration}" || return 1
  campus_link_is_uint "${minimum_packets}" || return 1
  campus_link_is_uint "${minimum_duration}" || return 1
  (( max_duration > 0 && minimum_packets > 0 && minimum_duration > 0 && \
    minimum_duration <= max_duration )) || return 1
  direct_duration=$(campus_link_marker_uint "${marker}" DIRECT_EVIDENCE_DURATION_MS) || return 1
  a_progress=$(campus_link_marker_uint "${marker}" EDGE_A_DIRECT_PROGRESS_DELTA) || return 1
  a_received=$(campus_link_marker_uint "${marker}" EDGE_A_DIRECT_RECEIVED_DELTA) || return 1
  a_sent=$(campus_link_marker_uint "${marker}" EDGE_A_DIRECT_SENT_DELTA) || return 1
  a_dropped=$(campus_link_marker_uint "${marker}" EDGE_A_DROPPED_DELTA) || return 1
  a_duplicates=$(campus_link_marker_uint "${marker}" EDGE_A_DUPLICATE_PACKETS_DELTA) || return 1
  a_fallbacks=$(campus_link_marker_uint "${marker}" EDGE_A_FALLBACKS_DELTA) || return 1
  a_invalid=$(campus_link_marker_uint "${marker}" EDGE_A_INVALID_PACKETS_DELTA) || return 1
  a_queue=$(campus_link_marker_uint "${marker}" EDGE_A_QUEUE_DROPS_DELTA) || return 1
  a_relay_received=$(campus_link_marker_uint "${marker}" EDGE_A_RELAY_RECEIVED_DELTA) || return 1
  a_relay=$(campus_link_marker_uint "${marker}" EDGE_A_RELAY_SENT_DELTA) || return 1
  a_watchdog=$(campus_link_marker_uint "${marker}" EDGE_A_WATCHDOG_FAILURES_DELTA) || return 1
  b_progress=$(campus_link_marker_uint "${marker}" EDGE_B_DIRECT_PROGRESS_DELTA) || return 1
  b_received=$(campus_link_marker_uint "${marker}" EDGE_B_DIRECT_RECEIVED_DELTA) || return 1
  b_sent=$(campus_link_marker_uint "${marker}" EDGE_B_DIRECT_SENT_DELTA) || return 1
  b_dropped=$(campus_link_marker_uint "${marker}" EDGE_B_DROPPED_DELTA) || return 1
  b_duplicates=$(campus_link_marker_uint "${marker}" EDGE_B_DUPLICATE_PACKETS_DELTA) || return 1
  b_fallbacks=$(campus_link_marker_uint "${marker}" EDGE_B_FALLBACKS_DELTA) || return 1
  b_invalid=$(campus_link_marker_uint "${marker}" EDGE_B_INVALID_PACKETS_DELTA) || return 1
  b_queue=$(campus_link_marker_uint "${marker}" EDGE_B_QUEUE_DROPS_DELTA) || return 1
  b_relay_received=$(campus_link_marker_uint "${marker}" EDGE_B_RELAY_RECEIVED_DELTA) || return 1
  b_relay=$(campus_link_marker_uint "${marker}" EDGE_B_RELAY_SENT_DELTA) || return 1
  b_watchdog=$(campus_link_marker_uint "${marker}" EDGE_B_WATCHDOG_FAILURES_DELTA) || return 1
  raw_limit=$(campus_link_marker_uint "${marker}" RAW_RELAY_PACKET_LIMIT_PER_SITE) || return 1
  raw_a=$(campus_link_marker_uint "${marker}" RAW_RELAY_SITE_A_DELTA) || return 1
  raw_b=$(campus_link_marker_uint "${marker}" RAW_RELAY_SITE_B_DELTA) || return 1
  byte_limit=$(campus_link_marker_uint "${marker}" RAW_RELAY_BYTE_LIMIT_PER_SITE) || return 1
  raw_a_bytes=$(campus_link_marker_uint "${marker}" RAW_RELAY_SITE_A_BYTES_DELTA) || return 1
  raw_b_bytes=$(campus_link_marker_uint "${marker}" RAW_RELAY_SITE_B_BYTES_DELTA) || return 1
  (( direct_duration >= minimum_duration && direct_duration <= max_duration )) || return 1
  (( a_progress > 0 && b_progress > 0 )) || return 1
  (( a_received >= minimum_packets && a_sent >= minimum_packets && \
    b_received >= minimum_packets && b_sent >= minimum_packets )) || return 1
  (( a_dropped == 0 && a_duplicates == 0 && a_fallbacks == 0 && a_invalid == 0 && \
    a_queue == 0 && a_relay == 0 && a_relay_received == 0 && a_watchdog == 0 )) || return 1
  (( b_dropped == 0 && b_duplicates == 0 && b_fallbacks == 0 && b_invalid == 0 && \
    b_queue == 0 && b_relay == 0 && b_relay_received == 0 && b_watchdog == 0 )) || return 1
  expected_raw_limit=$((32 + (direct_duration + 999) / 1000))
  (( raw_limit == expected_raw_limit )) || return 1
  expected_byte_limit=$((65536 + (direct_duration * 64 + 999) / 1000))
  (( byte_limit == expected_byte_limit )) || return 1
  (( raw_a <= raw_limit && raw_b <= raw_limit && \
    raw_a_bytes <= byte_limit && raw_b_bytes <= byte_limit ))
}

campus_link_validate_fault_evidence_values() {
  local marker=$1 prefix value
  local duration raw_limit expected_raw_limit raw_a raw_b exact_checks reestablished transitions
  local byte_limit expected_byte_limit raw_a_bytes raw_b_bytes
  duration=$(campus_link_marker_uint "${marker}" FAULT_DIRECT_EVIDENCE_DURATION_MS) || return 1
  (( duration > 0 && duration <= 28800000 )) || return 1
  for prefix in FAULT_EDGE_A FAULT_EDGE_B; do
    value=$(campus_link_marker_uint "${marker}" "${prefix}_DIRECT_PROGRESS_DELTA") || return 1
    (( value > 0 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_DIRECT_RECEIVED_DELTA") || return 1
    (( value >= 1000 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_DIRECT_SENT_DELTA") || return 1
    (( value >= 1000 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_DROPPED_DELTA") || return 1
    (( value == 0 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_DUPLICATE_PACKETS_DELTA") || return 1
    (( value == 0 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_FALLBACKS_DELTA") || return 1
    (( value == 0 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_INVALID_PACKETS_DELTA") || return 1
    (( value == 0 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_QUEUE_DROPS_DELTA") || return 1
    (( value == 0 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_RELAY_RECEIVED_DELTA") || return 1
    (( value == 0 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_RELAY_SENT_DELTA") || return 1
    (( value == 0 )) || return 1
    value=$(campus_link_marker_uint "${marker}" "${prefix}_WATCHDOG_FAILURES_DELTA") || return 1
    (( value > 0 )) || return 1
  done
  exact_checks=$(campus_link_marker_uint "${marker}" FAULT_EXACT_PATH_IDENTITY_CHECKS) || return 1
  reestablished=$(campus_link_marker_uint "${marker}" FAULT_REESTABLISHED_DIRECT_PATHS) || return 1
  transitions=$(campus_link_marker_uint "${marker}" FAULT_RELAY_CONTROL_SESSION_TRANSITIONS) || return 1
  (( exact_checks == 6 && reestablished == 2 && transitions == 2 )) || return 1
  raw_limit=$(campus_link_marker_uint "${marker}" FAULT_RAW_RELAY_PACKET_LIMIT_PER_SITE) || return 1
  raw_a=$(campus_link_marker_uint "${marker}" FAULT_RAW_RELAY_SITE_A_DELTA) || return 1
  raw_b=$(campus_link_marker_uint "${marker}" FAULT_RAW_RELAY_SITE_B_DELTA) || return 1
  byte_limit=$(campus_link_marker_uint "${marker}" FAULT_RAW_RELAY_BYTE_LIMIT_PER_SITE) || return 1
  raw_a_bytes=$(campus_link_marker_uint "${marker}" FAULT_RAW_RELAY_SITE_A_BYTES_DELTA) || return 1
  raw_b_bytes=$(campus_link_marker_uint "${marker}" FAULT_RAW_RELAY_SITE_B_BYTES_DELTA) || return 1
  expected_raw_limit=$((32 + (duration + 999) / 1000))
  expected_byte_limit=$((65536 + (duration * 64 + 999) / 1000))
  (( raw_limit == expected_raw_limit && byte_limit == expected_byte_limit && \
    raw_a <= raw_limit && raw_b <= raw_limit && \
    raw_a_bytes <= byte_limit && raw_b_bytes <= byte_limit ))
}

campus_link_validate_nat_rebinding_values() {
  local marker=$1 key value
  local fault_sites forced_changes restoration_changes mapping_observations
  local profile_checks untouched_checks scoped_deletions ruleset_restorations timeout
  local matched migrated reestablished higher continuity connections reconnects
  local record_bytes records bytes_a bytes_b first_a last_a first_b last_b transcript gap_a gap_b
  local expected_bytes packet_limit byte_limit raw_a raw_a_bytes raw_b raw_b_bytes
  local packet_steps byte_growth packet_lower packet_upper byte_lower byte_upper

  fault_sites=$(campus_link_marker_uint "${marker}" FAULT_SITES) || return 1
  forced_changes=$(campus_link_marker_uint "${marker}" FORCED_MAPPING_CHANGES) || return 1
  restoration_changes=$(campus_link_marker_uint "${marker}" RESTORATION_MAPPING_CHANGES) || return 1
  mapping_observations=$(campus_link_marker_uint "${marker}" MAPPING_CHANGE_OBSERVATIONS) || return 1
  profile_checks=$(campus_link_marker_uint "${marker}" SOCKET_MAPPING_PROFILE_CHECKS) || return 1
  untouched_checks=$(campus_link_marker_uint "${marker}" UNTOUCHED_WAN_MAPPING_CHECKS) || return 1
  scoped_deletions=$(campus_link_marker_uint "${marker}" CONNTRACK_SCOPED_DELETIONS) || return 1
  ruleset_restorations=$(campus_link_marker_uint "${marker}" NAT_RULESET_RESTORATIONS) || return 1
  timeout=$(campus_link_marker_uint "${marker}" FAULT_RECOVERY_TIMEOUT_MS) || return 1
  matched=$(campus_link_marker_uint "${marker}" MATCHED_DIRECT_EPOCH_CHECKS) || return 1
  migrated=$(campus_link_marker_uint "${marker}" MIGRATED_PATHS) || return 1
  reestablished=$(campus_link_marker_uint "${marker}" REESTABLISHED_PATHS) || return 1
  higher=$(campus_link_marker_uint "${marker}" HIGHER_DIRECT_INSTANCE_EDGE_CHECKS) || return 1
  continuity=$(campus_link_marker_uint "${marker}" PROCESS_CONTINUITY_CHECKS) || return 1
  connections=$(campus_link_marker_uint "${marker}" TCP_CONNECTIONS) || return 1
  reconnects=$(campus_link_marker_uint "${marker}" TCP_RECONNECTS) || return 1
  record_bytes=$(campus_link_marker_uint "${marker}" STREAM_RECORD_BYTES) || return 1
  records=$(campus_link_marker_uint "${marker}" FULL_DUPLEX_RECORDS) || return 1
  bytes_a=$(campus_link_marker_shell_uint "${marker}" STREAM_BYTES_A_TO_B) || return 1
  bytes_b=$(campus_link_marker_shell_uint "${marker}" STREAM_BYTES_B_TO_A) || return 1
  first_a=$(campus_link_marker_uint "${marker}" FIRST_A_TO_B_SEQUENCE) || return 1
  last_a=$(campus_link_marker_uint "${marker}" LAST_A_TO_B_SEQUENCE) || return 1
  first_b=$(campus_link_marker_uint "${marker}" FIRST_B_TO_A_SEQUENCE) || return 1
  last_b=$(campus_link_marker_uint "${marker}" LAST_B_TO_A_SEQUENCE) || return 1
  transcript=$(campus_link_marker_value "${marker}" STREAM_TRANSCRIPT_SHA256) || return 1
  gap_a=$(campus_link_marker_uint "${marker}" MAX_PROGRESS_GAP_A_TO_B_MS) || return 1
  gap_b=$(campus_link_marker_uint "${marker}" MAX_PROGRESS_GAP_B_TO_A_MS) || return 1

  (( fault_sites == 2 && forced_changes == 2 && restoration_changes == 2 )) || return 1
  (( mapping_observations == 4 && profile_checks == 4 && untouched_checks == 4 )) || return 1
  (( scoped_deletions == 4 && ruleset_restorations == 2 && timeout == 25000 )) || return 1
  (( matched == 4 && continuity == 12 && connections == 1 && reconnects == 0 )) || return 1
  (( migrated <= 4 && reestablished <= 4 )) || return 1
  (( migrated + reestablished == 4 )) || return 1
  (( reestablished <= 9223372036854775807 / 2 )) || return 1
  (( higher == reestablished * 2 )) || return 1

  [[ ${transcript} =~ ^[a-f0-9]{64}$ ]] || return 1
  (( record_bytes == 1048576 && records > 0 )) || return 1
  # Bound the product before evaluating it in Bash's signed 64-bit arithmetic.
  (( records <= 9223372036854775807 / record_bytes )) || return 1
  expected_bytes=$((records * record_bytes))
  (( bytes_a == expected_bytes && bytes_b == expected_bytes )) || return 1
  # Difference form avoids overflowing an endpoint addition.
  (( last_a >= first_a && last_b >= first_b )) || return 1
  (( last_a - first_a == records - 1 && last_b - first_b == records - 1 )) || return 1
  (( gap_a <= timeout && gap_b <= timeout )) || return 1

  for key in \
    EDGE_A_DIRECT_SENT_DELTA EDGE_A_DIRECT_RECEIVED_DELTA EDGE_A_DIRECT_PROGRESS_DELTA \
    EDGE_B_DIRECT_SENT_DELTA EDGE_B_DIRECT_RECEIVED_DELTA EDGE_B_DIRECT_PROGRESS_DELTA; do
    value=$(campus_link_marker_uint "${marker}" "${key}") || return 1
    (( value > 0 )) || return 1
  done
  for key in EDGE_A_RELAY_SENT_DELTA EDGE_A_RELAY_RECEIVED_DELTA \
    EDGE_B_RELAY_SENT_DELTA EDGE_B_RELAY_RECEIVED_DELTA; do
    value=$(campus_link_marker_uint "${marker}" "${key}") || return 1
    (( value == 0 )) || return 1
  done

  packet_limit=$(campus_link_marker_uint "${marker}" RAW_RELAY_PACKET_LIMIT_PER_SITE) || return 1
  byte_limit=$(campus_link_marker_uint "${marker}" RAW_RELAY_BYTE_LIMIT_PER_SITE) || return 1
  raw_a=$(campus_link_marker_uint "${marker}" RAW_RELAY_SITE_A_DELTA) || return 1
  raw_a_bytes=$(campus_link_marker_uint "${marker}" RAW_RELAY_SITE_A_BYTES_DELTA) || return 1
  raw_b=$(campus_link_marker_uint "${marker}" RAW_RELAY_SITE_B_DELTA) || return 1
  raw_b_bytes=$(campus_link_marker_uint "${marker}" RAW_RELAY_SITE_B_BYTES_DELTA) || return 1
  # The verifier derives both limits from one positive interval of at most five
  # minutes: 32 + ceil(ms/1000) packets and 65536 + ceil(ms*64/1000) bytes.
  (( packet_limit >= 33 && packet_limit <= 332 )) || return 1
  (( byte_limit >= 65537 && byte_limit <= 84736 )) || return 1
  packet_steps=$((packet_limit - 32))
  byte_growth=$((byte_limit - 65536))
  packet_lower=$(((packet_steps - 1) * 1000 + 1))
  packet_upper=$((packet_steps * 1000))
  byte_lower=$((((byte_growth - 1) * 1000) / 64 + 1))
  byte_upper=$(((byte_growth * 1000) / 64))
  (( packet_lower <= byte_upper && byte_lower <= packet_upper )) || return 1
  (( raw_a <= packet_limit && raw_b <= packet_limit )) || return 1
  (( raw_a_bytes <= byte_limit && raw_b_bytes <= byte_limit ))
}

campus_link_validate_continuous_stream_values() {
  local marker=$1 expected_required=$2
  local required duration connections reconnects records bytes_a bytes_b
  local first_a last_a first_b last_b transcript progress_timeout grace gap_a gap_b observations
  local direct_status_observations
  local started completed elapsed_ms expected_bytes minimum_bytes
  required=$(campus_link_marker_uint "${marker}" REQUIRED_DURATION_SECONDS) || return 1
  duration=$(campus_link_marker_uint "${marker}" DURATION_SECONDS) || return 1
  connections=$(campus_link_marker_uint "${marker}" TCP_CONNECTIONS) || return 1
  reconnects=$(campus_link_marker_uint "${marker}" TCP_RECONNECTS) || return 1
  records=$(campus_link_marker_uint "${marker}" FULL_DUPLEX_RECORDS) || return 1
  bytes_a=$(campus_link_marker_shell_uint "${marker}" STREAM_BYTES_A_TO_B) || return 1
  bytes_b=$(campus_link_marker_shell_uint "${marker}" STREAM_BYTES_B_TO_A) || return 1
  first_a=$(campus_link_marker_uint "${marker}" FIRST_A_TO_B_SEQUENCE) || return 1
  last_a=$(campus_link_marker_uint "${marker}" LAST_A_TO_B_SEQUENCE) || return 1
  first_b=$(campus_link_marker_uint "${marker}" FIRST_B_TO_A_SEQUENCE) || return 1
  last_b=$(campus_link_marker_uint "${marker}" LAST_B_TO_A_SEQUENCE) || return 1
  transcript=$(campus_link_marker_value "${marker}" STREAM_TRANSCRIPT_SHA256) || return 1
  progress_timeout=$(campus_link_marker_uint "${marker}" PROGRESS_TIMEOUT_MS) || return 1
  grace=$(campus_link_marker_uint "${marker}" COMPLETION_GRACE_SECONDS) || return 1
  gap_a=$(campus_link_marker_uint "${marker}" MAX_PROGRESS_GAP_A_TO_B_MS) || return 1
  gap_b=$(campus_link_marker_uint "${marker}" MAX_PROGRESS_GAP_B_TO_A_MS) || return 1
  observations=$(campus_link_marker_uint "${marker}" PROGRESS_OBSERVATIONS) || return 1
  direct_status_observations=$(campus_link_marker_uint \
    "${marker}" DIRECT_STATUS_OBSERVATIONS) || return 1
  started=$(campus_link_marker_uint "${marker}" START_MONOTONIC_MS) || return 1
  completed=$(campus_link_marker_uint "${marker}" COMPLETE_MONOTONIC_MS) || return 1

  [[ ${transcript} =~ ^[a-f0-9]{64}$ ]] || return 1
  (( required == expected_required && connections == 1 && reconnects == 0 && records > 0 )) || return 1
  # Keep every multiplication inside Bash's signed 64-bit arithmetic range.
  (( records <= 549755813887 )) || return 1
  expected_bytes=$((records * 16777216))
  (( bytes_a == expected_bytes && bytes_b == expected_bytes )) || return 1
  (( first_a == 30000000000 && first_b == 40000000000 )) || return 1
  (( last_a == first_a + records - 1 && last_b == first_b + records - 1 )) || return 1
  (( progress_timeout == 30000 && grace == 120 )) || return 1
  (( gap_a <= progress_timeout && gap_b <= progress_timeout )) || return 1
  (( completed >= started )) || return 1
  elapsed_ms=$((completed - started))
  (( duration == elapsed_ms / 1000 )) || return 1
  (( duration >= required && duration <= required + grace )) || return 1
  minimum_bytes=$((elapsed_ms * 250))
  (( bytes_a >= minimum_bytes && bytes_b >= minimum_bytes )) || return 1
  (( observations >= required / 5 && \
    direct_status_observations >= observations ))
}

campus_link_validate_accelerated_stream_values() {
  local marker=$1 trials=$2
  local recovery record_bytes progress_timeout connections reconnects records
  local bytes_a bytes_b pre replacement post survival gap_a gap_b directions transcript
  recovery=$(campus_link_marker_uint "${marker}" MAX_RECOVERY_MS) || return 1
  record_bytes=$(campus_link_marker_uint "${marker}" STREAM_RECORD_BYTES) || return 1
  progress_timeout=$(campus_link_marker_uint "${marker}" STREAM_PROGRESS_TIMEOUT_MS) || return 1
  connections=$(campus_link_marker_uint "${marker}" TCP_CONNECTIONS) || return 1
  reconnects=$(campus_link_marker_uint "${marker}" TCP_RECONNECTS) || return 1
  records=$(campus_link_marker_uint "${marker}" FULL_DUPLEX_RECORDS) || return 1
  bytes_a=$(campus_link_marker_shell_uint "${marker}" STREAM_BYTES_A_TO_B) || return 1
  bytes_b=$(campus_link_marker_shell_uint "${marker}" STREAM_BYTES_B_TO_A) || return 1
  pre=$(campus_link_marker_uint "${marker}" PRE_RESTART_PROGRESS_CHECKS) || return 1
  replacement=$(campus_link_marker_uint "${marker}" REPLACEMENT_ACTIVE_CHECKPOINTS) || return 1
  post=$(campus_link_marker_uint "${marker}" POST_RESTART_PROGRESS_CHECKS) || return 1
  survival=$(campus_link_marker_uint "${marker}" STREAM_SURVIVAL_CHECKS) || return 1
  gap_a=$(campus_link_marker_uint "${marker}" MAX_PROGRESS_GAP_A_TO_B_MS) || return 1
  gap_b=$(campus_link_marker_uint "${marker}" MAX_PROGRESS_GAP_B_TO_A_MS) || return 1
  directions=$(campus_link_marker_uint "${marker}" STREAM_DIGEST_DIRECTIONS) || return 1
  transcript=$(campus_link_marker_value "${marker}" STREAM_TRANSCRIPT_SHA256) || return 1
  campus_link_is_uint "${trials}" || return 1
  [[ ${transcript} =~ ^[a-f0-9]{64}$ ]] || return 1
  (( trials > 0 && record_bytes == 1048576 && progress_timeout == 30000 )) || return 1
  (( connections == trials && reconnects == 0 )) || return 1
  (( trials <= 8999999999999999999 / 3 )) || return 1
  (( records >= trials * 2 )) || return 1
  (( records <= 8999999999999999999 / record_bytes )) || return 1
  (( bytes_a == records * record_bytes && bytes_b == records * record_bytes )) || return 1
  (( pre == trials && replacement == trials && post == trials )) || return 1
  (( survival >= trials * 3 )) || return 1
  (( recovery <= progress_timeout && gap_a <= progress_timeout && gap_b <= progress_timeout )) || return 1
  (( directions == trials * 2 )) || return 1
}

campus_link_prepare_systemd_properties() {
  local unit=$1 snapshot line property value
  snapshot=$(LC_ALL=C SYSTEMD_PAGER=cat systemctl show --all --no-pager "${unit}" 2>/dev/null) || return 1
  declare -gA CAMPUS_LINK_SYSTEMD_PROPERTY_CACHE=()
  declare -g CAMPUS_LINK_SYSTEMD_PROPERTY_CACHE_UNIT=${unit}
  while IFS= read -r line; do
    [[ ${line} == *=* && ${line} != *$'\r'* ]] || return 1
    property=${line%%=*}
    value=${line#*=}
    [[ ${property} =~ ^[A-Za-z][A-Za-z0-9]*$ ]] || return 1
    [[ -z ${CAMPUS_LINK_SYSTEMD_PROPERTY_CACHE[${property}]+present} ]] || return 1
    CAMPUS_LINK_SYSTEMD_PROPERTY_CACHE[${property}]=${value}
  done <<< "${snapshot}"
  (( ${#CAMPUS_LINK_SYSTEMD_PROPERTY_CACHE[@]} > 0 ))
}

campus_link_systemd_property() {
  local unit=$1 property=$2
  if [[ ${CAMPUS_LINK_SYSTEMD_PROPERTY_CACHE_UNIT:-} == "${unit}" ]]; then
    [[ -n ${CAMPUS_LINK_SYSTEMD_PROPERTY_CACHE[${property}]+present} ]] || return 1
    printf '%s' "${CAMPUS_LINK_SYSTEMD_PROPERTY_CACHE[${property}]}"
    return
  fi
  LC_ALL=C SYSTEMD_PAGER=cat systemctl show --property="${property}" --value "${unit}" 2>/dev/null
}

campus_link_systemd_live_property() {
  local unit=$1 property=$2
  LC_ALL=C SYSTEMD_PAGER=cat systemctl show --property="${property}" --value "${unit}" 2>/dev/null
}

campus_link_boundary_record() {
  local unit=$1 property=$2 value=$3
  [[ ${unit} != *$'\n'* && ${property} != *$'\n'* && ${value} != *$'\n'* ]] || return 1
  printf '%u:%s%u:%s%u:%s\n' \
    "${#unit}" "${unit}" "${#property}" "${property}" "${#value}" "${value}"
}

campus_link_assert_boundary_scalar() {
  local unit=$1 property=$2 expected=$3 actual
  actual=$(campus_link_systemd_property "${unit}" "${property}") || return 1
  [[ ${actual} != *$'\n'* && ${actual} != *$'\r'* && ${actual} == "${expected}" ]] || return 1
  campus_link_boundary_record "${unit}" "${property}" "${actual}"
}

campus_link_sort_unique_array() {
  local destination=$1 serialization
  local -n output=${destination}
  shift
  output=()
  (( $# > 0 )) || return 0
  serialization=$(printf '%s\n' "$@" | LC_ALL=C sort -u) || return 1
  [[ -n ${serialization} && ${serialization} != *$'\r'* ]] || return 1
  mapfile -t output <<< "${serialization}" || return 1
}

campus_link_assert_boundary_word_set() {
  local unit=$1 property=$2
  shift 2
  local actual normalized actual_normalized expected_normalized
  local -a actual_words=() actual_sorted=() expected_words=("$@") expected_sorted=()
  actual=$(campus_link_systemd_property "${unit}" "${property}") || return 1
  [[ ${actual} != *$'\r'* ]] || return 1
  normalized=${actual//$'\n'/ }
  if [[ -n ${normalized} ]]; then
    read -r -a actual_words <<< "${normalized}"
  fi
  if (( ${#actual_words[@]} > 0 )); then
    campus_link_sort_unique_array actual_sorted "${actual_words[@]}" || return 1
  fi
  if (( ${#expected_words[@]} > 0 )); then
    campus_link_sort_unique_array expected_sorted "${expected_words[@]}" || return 1
  fi
  (( ${#actual_words[@]} == ${#actual_sorted[@]} && \
    ${#expected_words[@]} == ${#expected_sorted[@]} )) || return 1
  actual_normalized=$(IFS=,; printf '%s' "${actual_sorted[*]}")
  expected_normalized=$(IFS=,; printf '%s' "${expected_sorted[*]}")
  [[ ${actual_normalized} == "${expected_normalized}" ]] || return 1
  campus_link_boundary_record "${unit}" "${property}" "${actual_normalized}"
}

campus_link_global_service_dropin_sha256() {
  local path=$1 owner mode digest
  [[ -f ${path} && ! -L ${path} ]] || return 1
  owner=$(stat -c '%u' -- "${path}" 2>/dev/null) || return 1
  [[ ${owner} == 0 ]] || return 1
  mode=$(stat -c '%a' -- "${path}" 2>/dev/null) || return 1
  [[ ${mode} =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#${mode} & 8#022) == 0 )) || return 1
  digest=$(sha256sum -- "${path}" 2>/dev/null | awk '{print $1}') || return 1
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s' "${digest}"
}

campus_link_assert_edge_dropins() {
  local unit=$1 actual normalized path digest
  local -a paths=() sorted=()
  actual=$(campus_link_systemd_property "${unit}" DropInPaths) || return 1
  [[ ${actual} != *$'\r'* ]] || return 1
  normalized=${actual//$'\n'/ }
  if [[ -n ${normalized} ]]; then
    read -r -a paths <<< "${normalized}"
    campus_link_sort_unique_array sorted "${paths[@]}" || return 1
    (( ${#paths[@]} == ${#sorted[@]} )) || return 1
  fi
  for path in "${sorted[@]}"; do
    # Type-wide service.d policy shipped by the OS is permitted only when the
    # effective contract below remains exact. Unit-specific, generated,
    # transient and system.control drop-ins are never candidate state.
    case ${path} in
      /etc/systemd/system/service.d/*.conf|\
      /run/systemd/system/service.d/*.conf|\
      /usr/local/lib/systemd/system/service.d/*.conf|\
      /usr/lib/systemd/system/service.d/*.conf|\
      /lib/systemd/system/service.d/*.conf) ;;
      *) return 1 ;;
    esac
    digest=$(campus_link_global_service_dropin_sha256 "${path}") || return 1
    campus_link_boundary_record "${unit}" DropInPath "${path}:${digest}" || return 1
  done
  (( ${#sorted[@]} > 0 )) || campus_link_boundary_record "${unit}" DropInPaths none
}

campus_link_assert_edge_exec_start() {
  local unit=$1 binary=$2 config=$3 legacy extended legacy_prefix extended_prefix
  legacy=$(campus_link_systemd_property "${unit}" ExecStart) || return 1
  extended=$(campus_link_systemd_property "${unit}" ExecStartEx) || return 1
  [[ ${legacy} != *$'\n'* && ${legacy} != *$'\r'* && ${legacy} == *'}' ]] || return 1
  [[ ${extended} != *$'\n'* && ${extended} != *$'\r'* && ${extended} == *'}' ]] || return 1
  legacy_prefix="{ path=${binary} ; argv[]=${binary} -config ${config} ; ignore_errors=no ; "
  extended_prefix="{ path=${binary} ; argv[]=${binary} -config ${config} ; flags= ; "
  [[ ${legacy} == "${legacy_prefix}"* && ${legacy#"${legacy_prefix}"} != *'{ path='* ]] || return 1
  [[ ${extended} == "${extended_prefix}"* && ${extended#"${extended_prefix}"} != *'{ path='* ]] || return 1
  campus_link_boundary_record "${unit}" ExecStartStatic "${binary} -config ${config}" || return 1
  campus_link_boundary_record "${unit}" ExecStartFlags none
}

campus_link_proc_path() {
  local pid=$1 leaf=$2
  printf '/proc/%s/%s' "${pid}" "${leaf}"
}

campus_link_edge_binary_path() {
  printf '/usr/local/bin/campus-link-edge'
}

campus_link_edge_config_path() {
  printf '/etc/campus-link/%s/edge.json' "$1"
}

campus_link_edge_fragment_path() {
  printf '/etc/systemd/system/campus-link-edge-%s.service' "$1"
}

campus_link_edge_namespace_path() {
  printf '/run/netns/campus-%s' "$1"
}

campus_link_edge_identity() {
  local user=$1 uid gid
  uid=$(id -u "${user}" 2>/dev/null) || return 1
  gid=$(id -g "${user}" 2>/dev/null) || return 1
  [[ ${uid} =~ ^[0-9]+$ && ${gid} =~ ^[0-9]+$ ]] || return 1
  printf '%s %s' "${uid}" "${gid}"
}

campus_link_proc_status_value() {
  local status=$1 key=$2 line value= count=0
  while IFS= read -r line; do
    if [[ ${line} == "${key}:"* ]]; then
      value=${line#*:}
      value=${value#${value%%[!$' \t']*}}
      count=$((count + 1))
    fi
  done 2>/dev/null < "${status}" || return 1
  (( count == 1 )) || return 1
  printf '%s' "${value}"
}

campus_link_process_executable_matches() {
  local exe=$1 binary=$2
  [[ -L ${exe} ]] && cmp -s -- "${exe}" "${binary}"
}

campus_link_assert_edge_process_boundary() {
  local unit=$1 user=$2 namespace=$3 binary=$4 config=$5
  local active pid pid_again process_dir process_inode process_inode_after status cmdline exe
  local actual_namespace_path
  local identity uid gid uid_line gid_line groups no_new_privs capability value expected_namespace_inode actual_namespace_inode
  local -a ids=() group_ids=() argv=()
  active=$(campus_link_systemd_live_property "${unit}" ActiveState) || return 1
  [[ ${active} != *$'\n'* && ${active} != *$'\r'* ]] || return 1
  [[ ${active} == active ]] || return 1
  pid=$(campus_link_systemd_live_property "${unit}" MainPID) || return 1
  [[ ${pid} =~ ^[1-9][0-9]*$ ]] || return 1
  identity=$(campus_link_edge_identity "${user}") || return 1
  read -r uid gid <<< "${identity}"
  [[ ${uid} =~ ^[0-9]+$ && ${gid} =~ ^[0-9]+$ ]] || return 1
  process_dir=$(campus_link_proc_path "${pid}" .) || return 1
  status=$(campus_link_proc_path "${pid}" status) || return 1
  cmdline=$(campus_link_proc_path "${pid}" cmdline) || return 1
  exe=$(campus_link_proc_path "${pid}" exe) || return 1
  process_inode=$(stat -Lc '%d:%i' -- "${process_dir}" 2>/dev/null) || return 1

  uid_line=$(campus_link_proc_status_value "${status}" Uid) || return 1
  read -r -a ids <<< "${uid_line}"
  (( ${#ids[@]} == 4 )) || return 1
  [[ ${ids[0]} == "${uid}" && ${ids[1]} == "${uid}" && \
    ${ids[2]} == "${uid}" && ${ids[3]} == "${uid}" ]] || return 1
  gid_line=$(campus_link_proc_status_value "${status}" Gid) || return 1
  read -r -a ids <<< "${gid_line}"
  (( ${#ids[@]} == 4 )) || return 1
  [[ ${ids[0]} == "${gid}" && ${ids[1]} == "${gid}" && \
    ${ids[2]} == "${gid}" && ${ids[3]} == "${gid}" ]] || return 1
  groups=$(campus_link_proc_status_value "${status}" Groups) || return 1
  if [[ -n ${groups} ]]; then
    read -r -a group_ids <<< "${groups}"
  fi
  (( ${#group_ids[@]} <= 1 )) || return 1
  (( ${#group_ids[@]} == 0 )) || [[ ${group_ids[0]} == "${gid}" ]] || return 1
  no_new_privs=$(campus_link_proc_status_value "${status}" NoNewPrivs) || return 1
  [[ ${no_new_privs} == 1 ]] || return 1
  for capability in CapInh CapPrm CapEff CapBnd CapAmb; do
    value=$(campus_link_proc_status_value "${status}" "${capability}") || return 1
    [[ ${value} =~ ^0+$ ]] || return 1
  done

  [[ -e ${namespace} && ! -L ${namespace} ]] || return 1
  expected_namespace_inode=$(stat -Lc '%d:%i' -- "${namespace}" 2>/dev/null) || return 1
  actual_namespace_path=$(campus_link_proc_path "${pid}" ns/net) || return 1
  actual_namespace_inode=$(stat -Lc '%d:%i' -- "${actual_namespace_path}" 2>/dev/null) || return 1
  [[ ${actual_namespace_inode} == "${expected_namespace_inode}" ]] || return 1
  mapfile -d '' -t argv 2>/dev/null < "${cmdline}" || return 1
  (( ${#argv[@]} == 3 )) || return 1
  [[ ${argv[0]} == "${binary}" && ${argv[1]} == -config && ${argv[2]} == "${config}" ]] || return 1
  campus_link_process_executable_matches "${exe}" "${binary}" || return 1

  process_inode_after=$(stat -Lc '%d:%i' -- "${process_dir}" 2>/dev/null) || return 1
  pid_again=$(campus_link_systemd_live_property "${unit}" MainPID) || return 1
  [[ ${pid_again} == "${pid}" && ${process_inode_after} == "${process_inode}" ]] || return 1
}

campus_link_assert_edge_runtime_unit() {
  local site=$1 suffix unit user namespace binary config fragment property expected
  suffix=${site#site-}
  unit=campus-link-edge-${suffix}.service
  user=campus-link-${suffix}
  namespace=$(campus_link_edge_namespace_path "${suffix}") || return 1
  binary=$(campus_link_edge_binary_path) || return 1
  config=$(campus_link_edge_config_path "${site}") || return 1
  fragment=$(campus_link_edge_fragment_path "${suffix}") || return 1
  campus_link_prepare_systemd_properties "${unit}" || return 1
  campus_link_assert_edge_dropins "${unit}" || return 1
  while IFS='|' read -r property expected; do
    campus_link_assert_boundary_scalar "${unit}" "${property}" "${expected}" || return 1
  done <<EOF
LoadState|loaded
FragmentPath|${fragment}
Type|simple
User|${user}
Group|${user}
SupplementaryGroups|
DynamicUser|no
RemainAfterExit|no
GuessMainPID|yes
NotifyAccess|none
PIDFile|
FileDescriptorStoreMax|0
KillMode|control-group
SendSIGKILL|yes
SameProcessGroup|no
NetworkNamespacePath|${namespace}
NoNewPrivileges|yes
CapabilityBoundingSet|
AmbientCapabilities|
SecureBits|0
DevicePolicy|closed
PrivateTmp|yes
PrivateDevices|no
PrivateNetwork|no
PrivateUsers|no
PrivateMounts|no
ProtectClock|yes
ProtectControlGroups|yes
ProtectHome|yes
ProtectHostname|no
ProtectKernelLogs|yes
ProtectKernelModules|yes
ProtectKernelTunables|yes
ProtectProc|default
ProtectSystem|strict
ProcSubset|all
RestrictNamespaces|yes
RestrictRealtime|yes
RestrictSUIDSGID|yes
LockPersonality|yes
SystemCallArchitectures|native
UMask|0077
Restart|on-failure
RestartUSec|10s
StartLimitIntervalUSec|0
MemoryHigh|83886080
MemoryMax|100663296
TasksMax|128
LimitNOFILE|512
LimitNOFILESoft|512
LimitCORE|0
LimitCORESoft|0
MemoryDenyWriteExecute|no
KeyringMode|private
RootDirectory|
RootImage|
RootImageOptions|
RootDirectoryStartOnly|no
WorkingDirectory|
PAMName|
Environment|
EnvironmentFiles|
PassEnvironment|
UnsetEnvironment|
LoadCredential|
LoadCredentialEncrypted|
SetCredential|
SetCredentialEncrypted|
ImportCredential|
ImportCredentialEx|
OpenFile|
Sockets|
RuntimeDirectory|
StateDirectory|
CacheDirectory|
LogsDirectory|
ConfigurationDirectory|
ReadOnlyPaths|
BindPaths|
BindReadOnlyPaths|
TemporaryFileSystem|
MountImages|
ExtensionImages|
ExtensionDirectories|
MountFlags|
IPCNamespacePath|
JoinsNamespaceOf|
AppArmorProfile|
SELinuxContext|
SmackProcessLabel|
ExecCondition|
ExecStartPre|
ExecStartPost|
ExecReload|
ExecStop|
ExecStopPost|
StandardInput|null
StandardInputData|
NonBlocking|no
Delegate|no
EOF
  campus_link_assert_boundary_word_set "${unit}" DeviceAllow /dev/net/tun rw || return 1
  campus_link_assert_boundary_word_set "${unit}" RestrictAddressFamilies AF_INET AF_INET6 AF_UNIX || return 1
  campus_link_assert_boundary_word_set "${unit}" ReadWritePaths "/run/campus-link/${site}" || return 1
  if [[ ${site} == site-a ]]; then
    campus_link_assert_boundary_word_set "${unit}" InaccessiblePaths \
      -/etc/campus-link/site-b -/etc/campus-link/pki -/etc/campus-link/relay-fault \
      -/run/campus-link/site-b \
      -/var/lib/campus-link -/srv/openwrt-lab || return 1
  else
    campus_link_assert_boundary_word_set "${unit}" InaccessiblePaths \
      -/etc/campus-link/site-a -/etc/campus-link/pki -/etc/campus-link/relay-fault \
      -/run/campus-link/site-a \
      -/var/lib/campus-link -/srv/openwrt-lab || return 1
  fi
  campus_link_assert_edge_exec_start "${unit}" "${binary}" "${config}" || return 1
  campus_link_assert_edge_process_boundary \
    "${unit}" "${user}" "${namespace}" "${binary}" "${config}"
}

campus_link_assert_edge_runtime_boundary() {
  local serialization digest
  CAMPUS_LINK_EDGE_RUNTIME_BOUNDARY_SHA256=
  serialization=$(
    campus_link_assert_edge_runtime_unit site-a &&
      campus_link_assert_edge_runtime_unit site-b
  ) || return 1
  [[ -n ${serialization} ]] || return 1
  digest=$(printf '%s' "${serialization}" | sha256sum | awk '{print $1}') || return 1
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  CAMPUS_LINK_EDGE_RUNTIME_BOUNDARY_SHA256=${digest}
}

campus_link_candidate_fingerprint() {
  local path digest metadata runtime_boundary_digest site_metadata file_digest
  local -a paths=(
    /var/lib/campus-link/deployment-attestation.env
    /var/lib/campus-link/installed-release-manifest.sha256
    /var/lib/campus-link/installed-edge-version
    /var/lib/campus-link/a11-b22-firewall.complete
    /var/lib/campus-link/router-only.enabled
    /usr/local/bin/campus-link-edge
    /usr/local/bin/campus-linkctl
    /etc/campus-link/site-a/edge.json
    /etc/campus-link/site-a/control-ca.crt
    /etc/campus-link/site-a/data-ca.crt
    /etc/campus-link/site-a/site-a-control.crt
    /etc/campus-link/site-a/site-a-control.key
    /etc/campus-link/site-a/site-a-data.crt
    /etc/campus-link/site-a/site-a-data.key
    /etc/campus-link/site-b/edge.json
    /etc/campus-link/site-b/control-ca.crt
    /etc/campus-link/site-b/data-ca.crt
    /etc/campus-link/site-b/site-b-control.crt
    /etc/campus-link/site-b/site-b-control.key
    /etc/campus-link/site-b/site-b-data.crt
    /etc/campus-link/site-b/site-b-data.key
    /etc/campus-link/pki/authorization.env
    /etc/campus-link/pki/control-ca.key
    /etc/campus-link/pki/control-ca.crt
    /etc/campus-link/pki/data-ca.crt
    /etc/campus-link/pki/data-ca.key
    /etc/campus-link/pki/relay-control.crt
    /etc/campus-link/pki/relay-control.key
    /etc/campus-link/pki/site-a-control.crt
    /etc/campus-link/pki/site-a-control.key
    /etc/campus-link/pki/site-b-control.crt
    /etc/campus-link/pki/site-b-control.key
    /etc/campus-link/pki/site-a-data.crt
    /etc/campus-link/pki/site-a-data.key
    /etc/campus-link/pki/site-b-data.crt
    /etc/campus-link/pki/site-b-data.key
    /usr/local/libexec/campus-link-topology
    /usr/local/libexec/campus-link-configure-tun
    /usr/local/libexec/campus-link-smoke-external
    /usr/local/libexec/campus-link-restore-offline
    /usr/local/libexec/campus-link-qualify-a11-b22
    /usr/local/libexec/campus-link-test-edge-recovery
    /usr/local/libexec/campus-link-test-netem
    /usr/local/libexec/campus-link-test-relay-recovery-watch
    /usr/local/libexec/campus-link-soak-a11-b22
    /usr/local/libexec/campus-link-accelerated-fault-soak
    /usr/local/libexec/campus-link-fault-in-stream
    /usr/local/libexec/campus-link-nat-rebinding-gate
    /usr/local/libexec/campus-link-relay-restart-driver
    /usr/local/libexec/campus-link-relay-restart-transport
    /usr/local/libexec/campus-link-gate-evidence
    /usr/local/libexec/campus-link-qualification-chain
    /usr/local/libexec/campus-link-a11-b22.py
    /usr/local/libexec/campus-link-stream-transport.py
    /usr/local/libexec/campus-link-status-gate.py
    /usr/local/libexec/campus-link-nat-rebind-gate.py
    /usr/local/libexec/campus-link-rollback-edge
    /usr/local/libexec/openwrt-lab-topology
    /usr/local/libexec/openwrt-lab-start
    /usr/local/libexec/openwrt-lab-stop
    /usr/local/libexec/openwrt-lab-smoke
    /usr/local/libexec/openwrt-lab-console-config
    /etc/systemd/system/campus-link-topology.service
    /etc/systemd/system/campus-link-edge-a.service
    /etc/systemd/system/campus-link-edge-b.service
    /etc/systemd/system/campus-link-external.target
    /etc/systemd/system/campus-link-full-qualification.service
    /etc/systemd/system/campus-link-accelerated-fault.service
    /etc/systemd/system/campus-link-fault-in-stream.service
    /etc/systemd/system/campus-link-nat-rebinding.service
    /etc/systemd/system/campus-link-24h-soak.service
    /etc/systemd/system/campus-link-7d-burn-in.service
    /etc/systemd/system/campus-link-qualification-chain.service
    /etc/campus-link/relay-fault/id_ed25519
    /etc/campus-link/relay-fault/id_ed25519.pub
    /etc/campus-link/relay-fault/permit_ed25519.pem
    /etc/campus-link/relay-fault/permit_ed25519.pub.pem
    /etc/campus-link/relay-fault/known_hosts
    /etc/campus-link/relay-fault/target
  )
  campus_link_assert_no_plaintext_relay || return 1
  campus_link_assert_key_isolation || return 1
  campus_link_assert_relay_fault_access || return 1
  campus_link_assert_edge_runtime_boundary || return 1
  runtime_boundary_digest=${CAMPUS_LINK_EDGE_RUNTIME_BOUNDARY_SHA256}
  [[ ${runtime_boundary_digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  campus_link_validate_deployment_attestation || return 1
  for path in "${paths[@]}"; do
    case ${path} in
      /etc/campus-link/site-a/*|/etc/campus-link/site-b/*)
        [[ -f ${path} && ! -L ${path} ]] || return 1
        site_metadata=$(stat -c '%u:%a' -- "${path}") || return 1
        [[ ${site_metadata} == 0:640 ]] || return 1
        ;;
      *) campus_link_require_root_file "${path}" || return 1 ;;
    esac
  done
  digest=$(
    {
      printf 'edge-runtime-boundary\0%s\0' "${runtime_boundary_digest}"
      for path in "${paths[@]}"; do
        metadata=$(stat -c '%u:%g:%a:%s' -- "${path}") || exit 1
        printf '%s\0%s\0' "${path}" "${metadata}"
        file_digest=$(sha256sum -- "${path}" | awk '{print $1}') || exit 1
        [[ ${file_digest} =~ ^[a-f0-9]{64}$ ]] || exit 1
        printf '%s\n' "${file_digest}"
      done
    } | sha256sum | awk '{print $1}'
  ) || return 1
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

campus_link_assert_relay_fault_access() {
  local directory=/etc/campus-link/relay-fault private public known_hosts target
  local permit_private permit_public derived declared metadata link_count path
  local public_lines known_hosts_lines target_lines permit_private_type permit_public_type
  local derived_permit_public declared_permit_public
  private=${directory}/id_ed25519
  public=${directory}/id_ed25519.pub
  permit_private=${directory}/permit_ed25519.pem
  permit_public=${directory}/permit_ed25519.pub.pem
  known_hosts=${directory}/known_hosts
  target=${directory}/target
  command -v ssh-keygen >/dev/null || return 1
  command -v openssl >/dev/null || return 1
  [[ -d ${directory} && ! -L ${directory} ]] || return 1
  metadata=$(stat -c '%u:%g:%a' -- "${directory}") || return 1
  [[ ${metadata} == 0:0:700 ]] || return 1
  campus_link_require_root_file "${private}" 600 || return 1
  campus_link_require_root_file "${public}" 644 || return 1
  campus_link_require_root_file "${permit_private}" 600 || return 1
  campus_link_require_root_file "${permit_public}" 600 || return 1
  campus_link_require_root_file "${known_hosts}" 600 || return 1
  campus_link_require_root_file "${target}" 600 || return 1
  for path in "${private}" "${public}" "${permit_private}" "${permit_public}" \
    "${known_hosts}" "${target}"; do
    link_count=$(stat -c '%h' -- "${path}") || return 1
    [[ ${link_count} == 1 ]] || return 1
  done
  public_lines=$(wc -l < "${public}") || return 1
  known_hosts_lines=$(wc -l < "${known_hosts}") || return 1
  target_lines=$(wc -l < "${target}") || return 1
  [[ ${public_lines} -eq 1 && ${known_hosts_lines} -eq 1 && \
    ${target_lines} -eq 1 ]] || return 1
  grep -Eq '^ssh-ed25519 [A-Za-z0-9+/]+={0,2} campus-link-relay-fault$' "${public}" || return 1
  grep -Eq '^campus-link-relay-fault ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' "${known_hosts}" || return 1
  grep -Eq '^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$' "${target}" || return 1
  derived=$(ssh-keygen -y -f "${private}" 2>/dev/null) || return 1
  declared=$(cut -d ' ' -f 1-2 "${public}") || return 1
  [[ ${derived} == "${declared}" && ${derived%% *} == ssh-ed25519 ]] || return 1
  grep -Fxq -- '-----BEGIN PRIVATE KEY-----' "${permit_private}" || return 1
  grep -Fxq -- '-----BEGIN PUBLIC KEY-----' "${permit_public}" || return 1
  permit_private_type=$(openssl pkey -in "${permit_private}" \
    -text_pub -noout 2>/dev/null | sed -n '1p') || return 1
  permit_public_type=$(openssl pkey -pubin -in "${permit_public}" \
    -text_pub -noout 2>/dev/null | sed -n '1p') || return 1
  [[ ${permit_private_type} == 'ED25519 Public-Key:' && \
    ${permit_public_type} == 'ED25519 Public-Key:' ]] || return 1
  derived_permit_public=$(openssl pkey -in "${permit_private}" \
    -pubout 2>/dev/null) || return 1
  declared_permit_public=$(<"${permit_public}") || return 1
  [[ ${derived_permit_public} == "${declared_permit_public}" ]] || return 1
  runuser -u campus-link-a -- test ! -r "${private}" || return 1
  runuser -u campus-link-b -- test ! -r "${private}" || return 1
  runuser -u campus-link-a -- test ! -r "${permit_private}" || return 1
  runuser -u campus-link-b -- test ! -r "${permit_private}" || return 1
}

campus_link_assert_no_plaintext_relay() {
  local namespace_listing link_listing line namespace ignored
  campus_link_require_root_file /var/lib/campus-link/router-only.enabled || return 1
  namespace_listing=$(ip netns list) || return 1
  while IFS= read -r line; do
    read -r namespace ignored <<< "${line}" || return 1
    [[ ${namespace} != oslab-relay ]] || return 1
  done <<< "${namespace_listing}"
  link_listing=$(ip -o link show) || return 1
  [[ ${link_listing} != *': br-relay-a:'* && \
    ${link_listing} != *': br-relay-b:'* ]]
}

campus_link_assert_no_nonregular_entries() {
  local dir=$1 unexpected
  unexpected=$(find "${dir}" -mindepth 1 -maxdepth 1 ! -type f -print -quit) || return 1
  [[ -z ${unexpected} ]]
}

campus_link_assert_key_isolation() {
  local site user group dir actual expected path metadata peer pki_metadata dir_metadata
  command -v runuser >/dev/null || return 1
  pki_metadata=$(stat -c '%u:%g:%a' -- /etc/campus-link/pki) || return 1
  [[ ${pki_metadata} == 0:0:700 ]] || return 1
  for site in site-a site-b; do
    user=campus-link-${site#site-}
    group=$(id -g "${user}") || return 1
    dir=/etc/campus-link/${site}
    [[ -d ${dir} && ! -L ${dir} ]] || return 1
    dir_metadata=$(stat -c '%u:%g:%a' -- "${dir}") || return 1
    [[ ${dir_metadata} == "0:${group}:750" ]] || return 1
    actual=$(find "${dir}" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort) || return 1
    expected=$(printf '%s\n' control-ca.crt data-ca.crt edge.json \
      "${site}-control.crt" "${site}-control.key" "${site}-data.crt" "${site}-data.key" | LC_ALL=C sort) || return 1
    [[ ${actual} == "${expected}" ]] || return 1
    campus_link_assert_no_nonregular_entries "${dir}" || return 1
    while IFS= read -r path; do
      path=${dir}/${path}
      metadata=$(stat -c '%u:%g:%a:%h' -- "${path}") || return 1
      [[ ${metadata} == "0:${group}:640:1" ]] || return 1
    done <<< "${actual}"
    runuser -u "${user}" -- test -r "${dir}/${site}-control.key" || return 1
    runuser -u "${user}" -- test -r "${dir}/${site}-data.key" || return 1
    peer=site-a
    [[ ${site} == site-a ]] && peer=site-b
    runuser -u "${user}" -- test ! -r "/etc/campus-link/${peer}/${peer}-control.key" || return 1
    runuser -u "${user}" -- test ! -r "/etc/campus-link/${peer}/${peer}-data.key" || return 1
    runuser -u "${user}" -- test ! -r /etc/campus-link/pki/control-ca.key || return 1
    runuser -u "${user}" -- test ! -r /etc/campus-link/pki/data-ca.key || return 1
    runuser -u "${user}" -- test ! -r /etc/campus-link/pki/relay-control.key || return 1
  done
}

campus_link_acquire_deployment_shared_lock() {
  [[ -d /run && ! -L /run ]] || return 1
  exec {CAMPUS_LINK_DEPLOY_LOCK_FD}<>"${CAMPUS_LINK_DEPLOY_LOCK}"
  flock -s -w 300 "${CAMPUS_LINK_DEPLOY_LOCK_FD}"
}

campus_link_acquire_gate_execution_lock() {
  [[ -d ${CAMPUS_LINK_RUN_DIR} && ! -L ${CAMPUS_LINK_RUN_DIR} ]] || return 1
  exec {CAMPUS_LINK_GATE_LOCK_FD}<>"${CAMPUS_LINK_GATE_LOCK}"
  flock -w 300 "${CAMPUS_LINK_GATE_LOCK_FD}"
}

campus_link_validate_run_manifest() {
  local manifest=${1:-${CAMPUS_LINK_RUN_MANIFEST}}
  local run_id candidate deployment start boot actual_deployment now expected_boot
  campus_link_validate_schema "${manifest}" \
    FORMAT RUN_ID CANDIDATE_SHA256 DEPLOYMENT_ATTESTATION_SHA256 \
    START_MONOTONIC_MS BOOT_ID_SHA256 || return 1
  campus_link_marker_equals "${manifest}" FORMAT 1 || return 1
  run_id=$(campus_link_marker_value "${manifest}" RUN_ID) || return 1
  candidate=$(campus_link_marker_value "${manifest}" CANDIDATE_SHA256) || return 1
  deployment=$(campus_link_marker_value "${manifest}" DEPLOYMENT_ATTESTATION_SHA256) || return 1
  start=$(campus_link_marker_value "${manifest}" START_MONOTONIC_MS) || return 1
  boot=$(campus_link_marker_value "${manifest}" BOOT_ID_SHA256) || return 1
  [[ ${run_id} =~ ^[a-f0-9]{32}$ ]] || return 1
  [[ ${candidate} =~ ^[a-f0-9]{64}$ && ${deployment} =~ ^[a-f0-9]{64}$ ]] || return 1
  campus_link_is_uint "${start}" || return 1
  now=$(campus_link_monotonic_ms) || return 1
  (( start <= now )) || return 1
  expected_boot=$(campus_link_boot_id_sha256) || return 1
  [[ ${boot} == "${expected_boot}" ]] || return 1
  campus_link_validate_deployment_attestation || return 1
  actual_deployment=$(sha256sum -- "${CAMPUS_LINK_DEPLOYMENT_ATTESTATION}" | awk '{print $1}') || return 1
  [[ ${actual_deployment} == "${deployment}" ]] || return 1
}

campus_link_run_manifest_sha256() {
  local manifest=${1:-${CAMPUS_LINK_RUN_MANIFEST}} digest
  campus_link_validate_run_manifest "${manifest}" || return 1
  digest=$(sha256sum -- "${manifest}" | awk '{print $1}') || return 1
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

campus_link_validate_gate_marker() {
  local marker=$1 manifest=$2 expected_gate=$3 expected_mode=$4
  shift 4
  local run_id candidate manifest_sha prerequisite started completed manifest_started now
  local manifest_run_id manifest_candidate expected_manifest_sha
  campus_link_validate_schema "${marker}" \
    FORMAT STATUS GATE MODE RUN_ID CANDIDATE_SHA256 RUN_MANIFEST_SHA256 \
    PREREQUISITE_MARKER_SHA256 START_MONOTONIC_MS COMPLETE_MONOTONIC_MS "$@" || return 1
  campus_link_marker_equals "${marker}" FORMAT 1 || return 1
  campus_link_marker_equals "${marker}" STATUS pass || return 1
  campus_link_marker_equals "${marker}" GATE "${expected_gate}" || return 1
  campus_link_marker_equals "${marker}" MODE "${expected_mode}" || return 1
  campus_link_validate_run_manifest "${manifest}" || return 1
  run_id=$(campus_link_marker_value "${marker}" RUN_ID) || return 1
  candidate=$(campus_link_marker_value "${marker}" CANDIDATE_SHA256) || return 1
  manifest_sha=$(campus_link_marker_value "${marker}" RUN_MANIFEST_SHA256) || return 1
  prerequisite=$(campus_link_marker_value "${marker}" PREREQUISITE_MARKER_SHA256) || return 1
  started=$(campus_link_marker_value "${marker}" START_MONOTONIC_MS) || return 1
  completed=$(campus_link_marker_value "${marker}" COMPLETE_MONOTONIC_MS) || return 1
  manifest_started=$(campus_link_marker_value "${manifest}" START_MONOTONIC_MS) || return 1
  manifest_run_id=$(campus_link_marker_value "${manifest}" RUN_ID) || return 1
  manifest_candidate=$(campus_link_marker_value "${manifest}" CANDIDATE_SHA256) || return 1
  expected_manifest_sha=$(campus_link_run_manifest_sha256 "${manifest}") || return 1
  [[ ${run_id} == "${manifest_run_id}" ]] || return 1
  [[ ${candidate} == "${manifest_candidate}" ]] || return 1
  [[ ${manifest_sha} == "${expected_manifest_sha}" ]] || return 1
  [[ ${prerequisite} == none || ${prerequisite} =~ ^[a-f0-9]{64}$ ]] || return 1
  campus_link_is_uint "${started}" || return 1
  campus_link_is_uint "${completed}" || return 1
  now=$(campus_link_monotonic_ms) || return 1
  (( started >= manifest_started && completed >= started && completed <= now )) || return 1
}

campus_link_validate_chain() {
  local manifest=$1 through=$2
  local full=${CAMPUS_LINK_RUN_DIR}/a11-b22-full.result
  local accelerated=${CAMPUS_LINK_RUN_DIR}/accelerated-fault-soak.result
  local fault=${CAMPUS_LINK_RUN_DIR}/fault-in-stream.result
  local nat=${CAMPUS_LINK_RUN_DIR}/nat-rebinding.result
  local day=${CAMPUS_LINK_RUN_DIR}/a11-b22-soak-24-hour.result
  local week=${CAMPUS_LINK_RUN_DIR}/a11-b22-soak-seven-day.result
  local full_hash accelerated_hash fault_hash nat_hash day_hash full_completed accelerated_started
  local accelerated_completed fault_started fault_completed nat_started nat_completed
  local day_started day_completed week_started
  local records concurrency bulk simultaneous long_stream stream_floor long_floor
  local duration cycles trials max_outage
  local impaired_floor measured_a measured_b
  local fault_bytes fault_rounds delay jitter loss reorder relay_outage
  local relay_progress_a relay_progress_b relay_samples relay_guard fault_hold
  local relay_before_a relay_during_a relay_near_a relay_before_b relay_during_b relay_near_b
  local fault_hold_a fault_hold_b max_outage_a max_outage_b
  local memory_ceiling peak_a peak_b continuity checksums sequences control_outages withdrawals
  local relay_restarts relay_restart_acks relay_restart_permits relay_restart_sessions
  local relay_restart_consumptions relay_restart_signed_phases
  local relay_restart_commits relay_restart_nrestarts_delta relay_restart_commit_stability
  local relay_restart_hold relay_restart_duration
  local relay_restart_progress_a relay_restart_progress_b relay_restart_outages
  local relay_restart_invocations
  local actual_candidate manifest_candidate

  campus_link_validate_run_manifest "${manifest}" || return 1
  actual_candidate=$(campus_link_candidate_fingerprint) || return 1
  manifest_candidate=$(campus_link_marker_value "${manifest}" CANDIDATE_SHA256) || return 1
  [[ ${actual_candidate} == "${manifest_candidate}" ]] || return 1

  campus_link_validate_gate_marker "${full}" "${manifest}" full full \
    RECORDS CONCURRENCY BULK_BYTES_EACH_DIRECTION \
    SIMULTANEOUS_STREAM_BYTES_EACH_DIRECTION LONG_STREAM_BYTES_EACH_DIRECTION \
    STREAM_MIN_MBIT_S LONG_STREAM_MIN_MBIT_S \
    "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}" || return 1
  campus_link_marker_equals "${full}" PREREQUISITE_MARKER_SHA256 none || return 1
  records=$(campus_link_marker_uint "${full}" RECORDS) || return 1
  concurrency=$(campus_link_marker_uint "${full}" CONCURRENCY) || return 1
  bulk=$(campus_link_marker_uint "${full}" BULK_BYTES_EACH_DIRECTION) || return 1
  simultaneous=$(campus_link_marker_uint "${full}" SIMULTANEOUS_STREAM_BYTES_EACH_DIRECTION) || return 1
  long_stream=$(campus_link_marker_uint "${full}" LONG_STREAM_BYTES_EACH_DIRECTION) || return 1
  stream_floor=$(campus_link_marker_uint "${full}" STREAM_MIN_MBIT_S) || return 1
  long_floor=$(campus_link_marker_uint "${full}" LONG_STREAM_MIN_MBIT_S) || return 1
  (( records == 10000 && concurrency == 100 )) || return 1
  (( bulk >= 1073741824 && simultaneous >= 1073741824 )) || return 1
  (( long_stream >= 4294967296 && long_stream <= 8589934592 )) || return 1
  (( stream_floor >= 15 && long_floor >= 25 )) || return 1
  campus_link_validate_direct_evidence_values "${full}" || return 1
  [[ ${through} == full ]] && return 0
  full_hash=$(sha256sum -- "${full}" | awk '{print $1}') || return 1

  campus_link_validate_gate_marker "${accelerated}" "${manifest}" accelerated-fault full \
    DURATION_SECONDS CYCLES EDGE_KILL_TRIALS \
    "${CAMPUS_LINK_ACCELERATED_STREAM_KEYS[@]}" || return 1
  campus_link_marker_equals "${accelerated}" PREREQUISITE_MARKER_SHA256 \
    "${full_hash}" || return 1
  duration=$(campus_link_marker_uint "${accelerated}" DURATION_SECONDS) || return 1
  cycles=$(campus_link_marker_uint "${accelerated}" CYCLES) || return 1
  trials=$(campus_link_marker_uint "${accelerated}" EDGE_KILL_TRIALS) || return 1
  (( duration >= 3600 && cycles > 0 && trials == cycles * 60 )) || return 1
  campus_link_validate_accelerated_stream_values "${accelerated}" "${trials}" || return 1
  full_completed=$(campus_link_marker_value "${full}" COMPLETE_MONOTONIC_MS) || return 1
  accelerated_started=$(campus_link_marker_value "${accelerated}" START_MONOTONIC_MS) || return 1
  (( accelerated_started >= full_completed )) || return 1
  [[ ${through} == accelerated-fault ]] && return 0
  accelerated_hash=$(sha256sum -- "${accelerated}" | awk '{print $1}') || return 1

  campus_link_validate_gate_marker "${fault}" "${manifest}" fault-in-stream production \
    STREAM_BYTES_EACH_DIRECTION STREAM_ROUNDS IMPAIRED_MIN_MILLI_MBIT_S \
    MEASURED_A_TO_B_MILLI_MBIT_S MEASURED_B_TO_A_MILLI_MBIT_S \
    NETEM_DELAY_MS NETEM_JITTER_MS \
    NETEM_LOSS_BASIS_POINTS NETEM_REORDER_BASIS_POINTS RELAY_CONTROL_OUTAGE_MS \
    RELAY_PROGRESS_A_TO_B_BEFORE_BYTES RELAY_PROGRESS_A_TO_B_DURING_BYTES \
    RELAY_PROGRESS_A_TO_B_NEAR_UNBLOCK_BYTES RELAY_PROGRESS_A_TO_B_DELTA_BYTES \
    RELAY_PROGRESS_B_TO_A_BEFORE_BYTES RELAY_PROGRESS_B_TO_A_DURING_BYTES \
    RELAY_PROGRESS_B_TO_A_NEAR_UNBLOCK_BYTES RELAY_PROGRESS_B_TO_A_DELTA_BYTES \
    RELAY_PROGRESS_SAMPLES_EACH_DIRECTION RELAY_NEAR_UNBLOCK_GUARD_MS \
    DIRECT_FAULT_HOLD_MS DIRECT_FAULT_HOLD_A_TO_B_MS DIRECT_FAULT_HOLD_B_TO_A_MS \
    MAX_APPLICATION_OUTAGE_MS MAX_APPLICATION_OUTAGE_A_TO_B_MS \
    MAX_APPLICATION_OUTAGE_B_TO_A_MS \
    MEMORY_CEILING_BYTES \
    EDGE_A_PEAK_MEMORY_BYTES EDGE_B_PEAK_MEMORY_BYTES PROCESS_CONTINUITY_CHECKS \
    CHECKSUM_DIRECTIONS SEQUENCE_RECORDS RELAY_CONTROL_OUTAGE_OBSERVATIONS \
    RELAY_PROCESS_RESTARTS RELAY_RESTART_ACKS RELAY_RESTART_SIGNED_PERMITS \
    RELAY_RESTART_SESSION_BINDINGS RELAY_RESTART_PERMIT_CONSUMPTIONS \
    RELAY_RESTART_SIGNED_PHASES RELAY_RESTART_COMMITS \
    RELAY_RESTART_NRESTARTS_DELTA RELAY_RESTART_COMMIT_STABILITY_MS \
    RELAY_RESTART_HOLD_MS \
    RELAY_RESTART_DURATION_MS RELAY_RESTART_PROGRESS_A_TO_B_DELTA_BYTES \
    RELAY_RESTART_PROGRESS_B_TO_A_DELTA_BYTES \
    RELAY_RESTART_CONTROL_OUTAGE_OBSERVATIONS \
    RELAY_RESTART_INVOCATION_TRANSITIONS \
    DIRECT_WITHDRAWAL_OBSERVATIONS "${CAMPUS_LINK_FAULT_EVIDENCE_KEYS[@]}" || return 1
  campus_link_marker_equals "${fault}" PREREQUISITE_MARKER_SHA256 \
    "${accelerated_hash}" || return 1
  fault_bytes=$(campus_link_marker_uint "${fault}" STREAM_BYTES_EACH_DIRECTION) || return 1
  fault_rounds=$(campus_link_marker_uint "${fault}" STREAM_ROUNDS) || return 1
  impaired_floor=$(campus_link_marker_uint "${fault}" IMPAIRED_MIN_MILLI_MBIT_S) || return 1
  measured_a=$(campus_link_marker_uint "${fault}" MEASURED_A_TO_B_MILLI_MBIT_S) || return 1
  measured_b=$(campus_link_marker_uint "${fault}" MEASURED_B_TO_A_MILLI_MBIT_S) || return 1
  delay=$(campus_link_marker_uint "${fault}" NETEM_DELAY_MS) || return 1
  jitter=$(campus_link_marker_uint "${fault}" NETEM_JITTER_MS) || return 1
  loss=$(campus_link_marker_uint "${fault}" NETEM_LOSS_BASIS_POINTS) || return 1
  reorder=$(campus_link_marker_uint "${fault}" NETEM_REORDER_BASIS_POINTS) || return 1
  relay_outage=$(campus_link_marker_uint "${fault}" RELAY_CONTROL_OUTAGE_MS) || return 1
  relay_before_a=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_A_TO_B_BEFORE_BYTES) || return 1
  relay_during_a=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_A_TO_B_DURING_BYTES) || return 1
  relay_near_a=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_A_TO_B_NEAR_UNBLOCK_BYTES) || return 1
  relay_progress_a=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_A_TO_B_DELTA_BYTES) || return 1
  relay_before_b=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_B_TO_A_BEFORE_BYTES) || return 1
  relay_during_b=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_B_TO_A_DURING_BYTES) || return 1
  relay_near_b=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_B_TO_A_NEAR_UNBLOCK_BYTES) || return 1
  relay_progress_b=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_B_TO_A_DELTA_BYTES) || return 1
  relay_samples=$(campus_link_marker_uint "${fault}" RELAY_PROGRESS_SAMPLES_EACH_DIRECTION) || return 1
  relay_guard=$(campus_link_marker_uint "${fault}" RELAY_NEAR_UNBLOCK_GUARD_MS) || return 1
  fault_hold=$(campus_link_marker_uint "${fault}" DIRECT_FAULT_HOLD_MS) || return 1
  fault_hold_a=$(campus_link_marker_uint "${fault}" DIRECT_FAULT_HOLD_A_TO_B_MS) || return 1
  fault_hold_b=$(campus_link_marker_uint "${fault}" DIRECT_FAULT_HOLD_B_TO_A_MS) || return 1
  max_outage=$(campus_link_marker_uint "${fault}" MAX_APPLICATION_OUTAGE_MS) || return 1
  max_outage_a=$(campus_link_marker_uint "${fault}" MAX_APPLICATION_OUTAGE_A_TO_B_MS) || return 1
  max_outage_b=$(campus_link_marker_uint "${fault}" MAX_APPLICATION_OUTAGE_B_TO_A_MS) || return 1
  memory_ceiling=$(campus_link_marker_uint "${fault}" MEMORY_CEILING_BYTES) || return 1
  peak_a=$(campus_link_marker_uint "${fault}" EDGE_A_PEAK_MEMORY_BYTES) || return 1
  peak_b=$(campus_link_marker_uint "${fault}" EDGE_B_PEAK_MEMORY_BYTES) || return 1
  continuity=$(campus_link_marker_uint "${fault}" PROCESS_CONTINUITY_CHECKS) || return 1
  checksums=$(campus_link_marker_uint "${fault}" CHECKSUM_DIRECTIONS) || return 1
  sequences=$(campus_link_marker_uint "${fault}" SEQUENCE_RECORDS) || return 1
  control_outages=$(campus_link_marker_uint "${fault}" RELAY_CONTROL_OUTAGE_OBSERVATIONS) || return 1
  relay_restarts=$(campus_link_marker_uint "${fault}" RELAY_PROCESS_RESTARTS) || return 1
  relay_restart_acks=$(campus_link_marker_uint "${fault}" RELAY_RESTART_ACKS) || return 1
  relay_restart_permits=$(campus_link_marker_uint "${fault}" RELAY_RESTART_SIGNED_PERMITS) || return 1
  relay_restart_sessions=$(campus_link_marker_uint "${fault}" RELAY_RESTART_SESSION_BINDINGS) || return 1
  relay_restart_consumptions=$(campus_link_marker_uint "${fault}" RELAY_RESTART_PERMIT_CONSUMPTIONS) || return 1
  relay_restart_signed_phases=$(campus_link_marker_uint "${fault}" RELAY_RESTART_SIGNED_PHASES) || return 1
  relay_restart_commits=$(campus_link_marker_uint "${fault}" RELAY_RESTART_COMMITS) || return 1
  relay_restart_nrestarts_delta=$(campus_link_marker_uint "${fault}" RELAY_RESTART_NRESTARTS_DELTA) || return 1
  relay_restart_commit_stability=$(campus_link_marker_uint "${fault}" RELAY_RESTART_COMMIT_STABILITY_MS) || return 1
  relay_restart_hold=$(campus_link_marker_uint "${fault}" RELAY_RESTART_HOLD_MS) || return 1
  relay_restart_duration=$(campus_link_marker_uint "${fault}" RELAY_RESTART_DURATION_MS) || return 1
  relay_restart_progress_a=$(campus_link_marker_uint "${fault}" RELAY_RESTART_PROGRESS_A_TO_B_DELTA_BYTES) || return 1
  relay_restart_progress_b=$(campus_link_marker_uint "${fault}" RELAY_RESTART_PROGRESS_B_TO_A_DELTA_BYTES) || return 1
  relay_restart_outages=$(campus_link_marker_uint "${fault}" RELAY_RESTART_CONTROL_OUTAGE_OBSERVATIONS) || return 1
  relay_restart_invocations=$(campus_link_marker_uint "${fault}" RELAY_RESTART_INVOCATION_TRANSITIONS) || return 1
  withdrawals=$(campus_link_marker_uint "${fault}" DIRECT_WITHDRAWAL_OBSERVATIONS) || return 1
  (( fault_bytes >= 2147483648 && fault_bytes <= 8589934592 && fault_rounds == 1 )) || return 1
  (( impaired_floor == 2000 && measured_a >= impaired_floor && measured_b >= impaired_floor )) || return 1
  (( delay == 100 && jitter == 20 && loss == 100 && reorder == 10 )) || return 1
  (( relay_outage >= 15000 && relay_progress_a >= 1048576 && relay_progress_b >= 1048576 )) || return 1
  (( relay_before_a < relay_during_a && relay_during_a < relay_near_a )) || return 1
  (( relay_before_b < relay_during_b && relay_during_b < relay_near_b )) || return 1
  (( relay_near_a <= fault_bytes && relay_near_b <= fault_bytes )) || return 1
  (( relay_progress_a == relay_near_a - relay_before_a )) || return 1
  (( relay_progress_b == relay_near_b - relay_before_b )) || return 1
  (( relay_samples == 3 && relay_guard <= 1000 )) || return 1
  (( fault_hold >= 15000 && fault_hold < 25000 )) || return 1
  (( fault_hold_a >= fault_hold && fault_hold_b >= fault_hold )) || return 1
  (( max_outage_a >= fault_hold_a && max_outage_a <= 25000 )) || return 1
  (( max_outage_b >= fault_hold_b && max_outage_b <= 25000 )) || return 1
  (( max_outage == max_outage_a || max_outage == max_outage_b )) || return 1
  (( max_outage >= max_outage_a && max_outage >= max_outage_b && max_outage < 30000 )) || return 1
  (( memory_ceiling > 0 && memory_ceiling <= 100663296 )) || return 1
  (( peak_a <= memory_ceiling && peak_b <= memory_ceiling )) || return 1
  (( continuity >= 12 && checksums == 2 && sequences == 2 )) || return 1
  (( control_outages == 2 && withdrawals == 2 )) || return 1
  (( relay_restarts == 1 && relay_restart_acks == 1 && \
    relay_restart_permits == 1 && relay_restart_sessions == 1 && \
    relay_restart_consumptions == 1 && relay_restart_signed_phases == 2 && \
    relay_restart_commits == 1 && relay_restart_nrestarts_delta == 0 && \
    relay_restart_commit_stability == 5000 )) || return 1
  (( relay_restart_hold == 15000 )) || return 1
  (( relay_restart_duration >= relay_restart_hold && relay_restart_duration <= 120000 )) || return 1
  (( relay_restart_progress_a >= 1048576 && relay_restart_progress_b >= 1048576 )) || return 1
  (( relay_restart_outages == 2 && relay_restart_invocations == 1 )) || return 1
  campus_link_validate_fault_evidence_values "${fault}" || return 1
  accelerated_completed=$(campus_link_marker_value "${accelerated}" COMPLETE_MONOTONIC_MS) || return 1
  fault_started=$(campus_link_marker_value "${fault}" START_MONOTONIC_MS) || return 1
  (( fault_started >= accelerated_completed )) || return 1
  [[ ${through} == fault-in-stream ]] && return 0
  fault_hash=$(sha256sum -- "${fault}" | awk '{print $1}') || return 1

  campus_link_validate_gate_marker "${nat}" "${manifest}" nat-rebinding production \
    FAULT_SITES FORCED_MAPPING_CHANGES RESTORATION_MAPPING_CHANGES \
    MAPPING_CHANGE_OBSERVATIONS SOCKET_MAPPING_PROFILE_CHECKS \
    UNTOUCHED_WAN_MAPPING_CHECKS CONNTRACK_SCOPED_DELETIONS \
    NAT_RULESET_RESTORATIONS FAULT_RECOVERY_TIMEOUT_MS \
    "${CAMPUS_LINK_NAT_REBIND_EVIDENCE_KEYS[@]}" || return 1
  campus_link_marker_equals "${nat}" PREREQUISITE_MARKER_SHA256 \
    "${fault_hash}" || return 1
  campus_link_validate_nat_rebinding_values "${nat}" || return 1
  fault_completed=$(campus_link_marker_value "${fault}" COMPLETE_MONOTONIC_MS) || return 1
  nat_started=$(campus_link_marker_value "${nat}" START_MONOTONIC_MS) || return 1
  (( nat_started >= fault_completed )) || return 1
  [[ ${through} == nat-rebinding ]] && return 0
  nat_hash=$(sha256sum -- "${nat}" | awk '{print $1}') || return 1

  campus_link_validate_gate_marker "${day}" "${manifest}" 24h-soak 24-hour \
    REQUIRED_DURATION_SECONDS DURATION_SECONDS \
    "${CAMPUS_LINK_CONTINUOUS_STREAM_KEYS[@]}" \
    "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}" || return 1
  campus_link_marker_equals "${day}" PREREQUISITE_MARKER_SHA256 \
    "${nat_hash}" || return 1
  campus_link_validate_continuous_stream_values "${day}" 86400 || return 1
  campus_link_validate_direct_evidence_values "${day}" \
    $(((86400 + 120 + 60) * 1000)) 1000 $((86400 * 1000)) || return 1
  nat_completed=$(campus_link_marker_value "${nat}" COMPLETE_MONOTONIC_MS) || return 1
  day_started=$(campus_link_marker_value "${day}" START_MONOTONIC_MS) || return 1
  (( day_started >= nat_completed )) || return 1
  [[ ${through} == 24h-soak ]] && return 0
  day_hash=$(sha256sum -- "${day}" | awk '{print $1}') || return 1

  campus_link_validate_gate_marker "${week}" "${manifest}" 7d-burn-in seven-day \
    REQUIRED_DURATION_SECONDS DURATION_SECONDS \
    "${CAMPUS_LINK_CONTINUOUS_STREAM_KEYS[@]}" \
    "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}" || return 1
  campus_link_marker_equals "${week}" PREREQUISITE_MARKER_SHA256 \
    "${day_hash}" || return 1
  campus_link_validate_continuous_stream_values "${week}" 604800 || return 1
  campus_link_validate_direct_evidence_values "${week}" \
    $(((604800 + 120 + 60) * 1000)) 1000 $((604800 * 1000)) || return 1
  day_completed=$(campus_link_marker_value "${day}" COMPLETE_MONOTONIC_MS) || return 1
  week_started=$(campus_link_marker_value "${week}" START_MONOTONIC_MS) || return 1
  (( week_started >= day_completed )) || return 1
  [[ ${through} == 7d-burn-in ]]
}

campus_link_assert_run_immutable() {
  local manifest=$1 expected_manifest_sha=$2 expected_candidate=$3
  local actual_manifest_sha actual_candidate
  actual_manifest_sha=$(campus_link_run_manifest_sha256 "${manifest}") || return 1
  actual_candidate=$(campus_link_candidate_fingerprint) || return 1
  [[ ${actual_manifest_sha} == "${expected_manifest_sha}" ]] || return 1
  [[ ${actual_candidate} == "${expected_candidate}" ]] || return 1
}

campus_link_atomic_marker() {
  local marker=$1 source=$2 parent marker_name tmp
  parent=$(dirname "${marker}") || return 1
  [[ -d ${parent} && ! -L ${parent} ]] || return 1
  [[ -f ${source} && ! -L ${source} ]] || return 1
  marker_name=$(basename "${marker}") || return 1
  tmp=$(mktemp "${parent}/.${marker_name}.XXXXXX") || return 1
  install -m 0600 -o root -g root "${source}" "${tmp}" || {
    rm -f -- "${tmp}"
    return 1
  }
  mv -fT -- "${tmp}" "${marker}" || {
    rm -f -- "${tmp}"
    return 1
  }
}
