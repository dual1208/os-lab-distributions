#!/usr/bin/env bash
# Executable byte-level regressions for the authenticated relay-restart channel.

set -euo pipefail
umask 077
export LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ACTUATOR=${ROOT}/scripts/relay-restart-actuator.sh
AUTHORIZER=${ROOT}/scripts/relay-restart-permit-authorize.sh
DRIVER=${ROOT}/scripts/relay-restart-driver.sh

readonly ROOT ACTUATOR AUTHORIZER DRIVER

tmp=$(mktemp -d "${TMPDIR:-/tmp}/campus-link-framing.XXXXXX")
cleanup() {
  rm -rf -- "${tmp}"
}
trap cleanup EXIT

tests=0
pass() {
  tests=$((tests + 1))
  printf 'ok %d - %s\n' "${tests}" "$1"
}
fail() {
  printf 'not ok %d - %s\n' "$((tests + 1))" "$1" >&2
  exit 1
}

expect_success() {
  local label=$1
  shift
  if "$@"; then
    pass "${label}"
  else
    fail "${label}"
  fi
}

expect_failure() {
  local label=$1
  shift
  if "$@"; then
    fail "${label}"
  else
    pass "${label}"
  fi
}

extract_function() {
  local name=$1 source=$2
  awk -v signature="${name}() {" '
    $0 == signature { inside = 1 }
    inside { print }
    inside && $0 == "}" { exit }
  ' "${source}"
}

for function_name in monotonic_ms run_bounded sleep_bounded read_exact_frame \
  assert_no_buffered_input assert_exact_eof; do
  definition=$(extract_function "${function_name}" "${ACTUATOR}")
  [[ -n ${definition} ]] || fail "extract ${function_name} from actuator"
  eval "${definition}"
done
for function_name in require_driver_temp_file assert_raw_phase_exact; do
  definition=$(extract_function "${function_name}" "${DRIVER}")
  [[ -n ${definition} ]] || fail "extract ${function_name} from driver"
  eval "${definition}"
done
readonly COMMAND_KILL_GRACE_MILLISECONDS=100
export COMMAND_KILL_GRACE_MILLISECONDS
export -f monotonic_ms run_bounded assert_exact_eof
readonly RAW_ACK_MAX_BYTES=4096
readonly RAW_PHASE_STABILITY_MILLISECONDS=150
readonly RAW_COMPARE_TIMEOUT_MILLISECONDS=500
readonly RAW_COMPARE_KILL_GRACE_MILLISECONDS=100

# The production helper requires root:root files.  This executable regression
# runs unprivileged and replaces only that ownership predicate; type, link,
# mode, byte, timing, and transition behavior remain exercised.
require_driver_temp_file() {
  local path=$1
  [[ -f ${path} && ! -L ${path} ]] || return 1
  [[ $(stat -c '%a:%h' -- "${path}") == 600:1 ]] || return 1
  return 0
}
campus_link_monotonic_ms() { monotonic_ms; }
relay_child_matches() { return 0; }

OPEN_BODY="open $(printf 'a%.0s' {1..32}) $(printf 'b%.0s' {1..64})"
OPEN_FRAME=${tmp}/open.frame
CANONICAL_FRAME=${tmp}/canonical.frame
PROBE=${tmp}/probe
readonly OPEN_BODY OPEN_FRAME CANONICAL_FRAME PROBE

printf '%s\n' "${OPEN_BODY}" > "${CANONICAL_FRAME}"
[[ $(stat -c '%s' -- "${CANONICAL_FRAME}") -eq 103 ]] || \
  fail 'test fixture has the protocol open-frame size'

validate_open_file() {
  local source=$1 canonical=$2 open_action run_id session_secret
  grep -aEq '^open [a-f0-9]{32} [a-f0-9]{64}$' "${source}" &&
    [[ $(wc -l < "${source}") -eq 1 ]] &&
    read -r open_action run_id session_secret < "${source}" &&
    [[ ${open_action} == open && ${run_id} =~ ^[a-f0-9]{32}$ &&
      ${session_secret} =~ ^[a-f0-9]{64}$ ]] &&
    printf 'open %s %s\n' "${run_id}" "${session_secret}" > "${canonical}" &&
    cmp -s -- "${source}" "${canonical}"
}

fragmented_open_writer() {
  printf '%s' "${OPEN_BODY:0:9}"
  sleep 0.015
  printf '%s' "${OPEN_BODY:9:37}"
  sleep 0.015
  printf '%s\n' "${OPEN_BODY:46}"
  # Keep the same application stream open past the anti-prequeue probe.
  sleep 30
}

fragmented_open_case() {
  local deadline_ms status writer_pid fifo=${tmp}/fragmented.fifo
  mkfifo -- "${fifo}"
  fragmented_open_writer > "${fifo}" &
  writer_pid=$!
  deadline_ms=$(($(monotonic_ms) + 5000))
  set +e
  (
    set -e
    read_exact_frame "${OPEN_FRAME}" 103 "${deadline_ms}"
    validate_open_file "${OPEN_FRAME}" "${tmp}/fragmented.canonical"
    assert_no_buffered_input "${PROBE}" "${deadline_ms}"
  ) < "${fifo}"
  status=$?
  kill "${writer_pid}" 2>/dev/null
  wait "${writer_pid}" 2>/dev/null
  rm -f -- "${fifo}"
  set -e
  (( status == 0 )) && cmp -s -- "${OPEN_FRAME}" "${CANONICAL_FRAME}"
}

embedded_nul_writer() {
  printf 'open '
  printf 'a%.0s' {1..15}
  printf '\0'
  printf 'a%.0s' {1..16}
  printf ' '
  printf 'b%.0s' {1..64}
  printf '\n'
}

embedded_nul_case() {
  local deadline_ms status
  deadline_ms=$(($(monotonic_ms) + 5000))
  set +e
  embedded_nul_writer | (
    set -e
    read_exact_frame "${OPEN_FRAME}" 103 "${deadline_ms}"
    if validate_open_file "${OPEN_FRAME}" "${tmp}/nul.canonical"; then
      exit 1
    fi
    [[ $(stat -c '%s' -- "${OPEN_FRAME}") -eq 103 ]]
  )
  status=${PIPESTATUS[1]}
  set -e
  (( status == 0 ))
}

early_eof_case() {
  local deadline_ms status
  deadline_ms=$(($(monotonic_ms) + 5000))
  set +e
  printf '%s' "${OPEN_BODY:0:52}" |
    (set -e; read_exact_frame "${OPEN_FRAME}" 103 "${deadline_ms}")
  status=${PIPESTATUS[1]}
  set -e
  (( status != 0 )) && [[ $(stat -c '%s' -- "${OPEN_FRAME}") -eq 52 ]]
}

trailing_byte_case() {
  local deadline_ms status
  deadline_ms=$(($(monotonic_ms) + 5000))
  set +e
  { printf '%s\nX' "${OPEN_BODY}"; sleep 0.150; } | (
    set -e
    read_exact_frame "${OPEN_FRAME}" 103 "${deadline_ms}"
    assert_no_buffered_input "${PROBE}" "${deadline_ms}"
  )
  status=${PIPESTATUS[1]}
  set -e
  (( status != 0 )) && [[ $(stat -c '%s' -- "${PROBE}") -eq 1 ]]
}

concatenated_frame_case() {
  local deadline_ms status
  deadline_ms=$(($(monotonic_ms) + 5000))
  set +e
  { printf '%s\n%s\n' "${OPEN_BODY}" "${OPEN_BODY}"; sleep 0.150; } | (
    set -e
    read_exact_frame "${OPEN_FRAME}" 103 "${deadline_ms}"
    assert_no_buffered_input "${PROBE}" "${deadline_ms}"
  )
  status=${PIPESTATUS[1]}
  set -e
  (( status != 0 )) && [[ $(stat -c '%s' -- "${PROBE}") -eq 1 ]]
}

partial_timeout_case() {
  local deadline_ms status
  deadline_ms=$(($(monotonic_ms) + 300))
  set +e
  { printf '%s' "${OPEN_BODY:0:41}"; sleep 0.600; } |
    (set -e; read_exact_frame "${OPEN_FRAME}" 103 "${deadline_ms}")
  status=${PIPESTATUS[1]}
  set -e
  (( status != 0 ))
}

permit_bounded_read() {
  local destination=$1 status size
  if timeout --signal=TERM --kill-after=1s 1s \
    dd iflag=fullblock bs=2049 count=1 status=none > "${destination}"; then
    status=0
  else
    status=$?
  fi
  (( status == 0 )) || return "${status}"
  size=$(stat -c '%s' -- "${destination}")
  (( size > 0 && size <= 2048 ))
}

fragmented_permit_case() {
  local destination=${tmp}/permit.fragmented status
  set +e
  { printf 'FORMAT=1\nACTION='; sleep 0.015; printf 'relay-restart-permit\n'; } |
    permit_bounded_read "${destination}"
  status=${PIPESTATUS[1]}
  set -e
  (( status == 0 )) &&
    cmp -s -- "${destination}" <(printf 'FORMAT=1\nACTION=relay-restart-permit\n')
}

oversized_permit_case() {
  local destination=${tmp}/permit.oversized status
  set +e
  head -c 2049 /dev/zero | permit_bounded_read "${destination}"
  status=${PIPESTATUS[1]}
  set -e
  (( status != 0 )) && [[ $(stat -c '%s' -- "${destination}") -eq 2049 ]]
}

closed_stream_is_exact_eof() {
  local status
  set +e
  : | "${BASH}" -c \
    'set -e; assert_exact_eof "$1" "$(($(monotonic_ms) + 7000))"' _ "${PROBE}"
  status=${PIPESTATUS[1]}
  set -e
  (( status == 0 )) && [[ ! -s ${PROBE} ]]
}

nul_is_not_eof() {
  local status
  set +e
  printf '\0' | "${BASH}" -c \
    'set -e; assert_exact_eof "$1" "$(($(monotonic_ms) + 7000))"' _ "${PROBE}"
  status=${PIPESTATUS[1]}
  set -e
  (( status != 0 )) && [[ $(stat -c '%s' -- "${PROBE}") -eq 1 ]]
}

unclosed_stream_is_not_eof() {
  local status writer_pid fifo=${tmp}/unclosed.fifo
  mkfifo -- "${fifo}"
  { sleep 30; } > "${fifo}" &
  writer_pid=$!
  set +e
  "${BASH}" -c \
    'set -e; assert_exact_eof "$1" "$(($(monotonic_ms) + 7000))"' _ "${PROBE}" \
    < "${fifo}"
  status=$?
  kill "${writer_pid}" 2>/dev/null
  wait "${writer_pid}" 2>/dev/null
  rm -f -- "${fifo}"
  set -e
  (( status != 0 )) && [[ ! -s ${PROBE} ]]
}

driver_raw_fragmented_case() {
  local expected=${tmp}/driver.expected deadline_ms writer_pid status
  raw_ack=${tmp}/driver.raw
  printf 'FORMAT=1\nSTOPPED=1\n' > "${expected}"
  : > "${raw_ack}"
  chmod 0600 "${expected}" "${raw_ack}"
  (
    printf 'FORMAT=1\n' >> "${raw_ack}"
    sleep 0.030
    printf 'STOPPED=1\n' >> "${raw_ack}"
  ) &
  writer_pid=$!
  deadline_ms=$(($(monotonic_ms) + 5000))
  if assert_raw_phase_exact "${expected}" "${deadline_ms}"; then
    status=0
  else
    status=$?
  fi
  wait "${writer_pid}" || return 1
  (( status == 0 ))
}

driver_raw_nul_case() {
  local expected=${tmp}/driver-nul.expected deadline_ms
  raw_ack=${tmp}/driver-nul.raw
  printf 'FORMAT=1\nSTOPPED=1\n' > "${expected}"
  { printf 'FORMAT=1\0\n'; printf 'STOPPED=1\n'; } > "${raw_ack}"
  chmod 0600 "${expected}" "${raw_ack}"
  deadline_ms=$(($(monotonic_ms) + 5000))
  ! assert_raw_phase_exact "${expected}" "${deadline_ms}"
}

driver_raw_prequeue_case() {
  local expected=${tmp}/driver-prequeue.expected deadline_ms
  raw_ack=${tmp}/driver-prequeue.raw
  printf 'FORMAT=1\nSTOPPED=1\n' > "${expected}"
  printf 'FORMAT=1\nSTOPPED=1\nSTARTED=1\n' > "${raw_ack}"
  chmod 0600 "${expected}" "${raw_ack}"
  deadline_ms=$(($(monotonic_ms) + 5000))
  ! assert_raw_phase_exact "${expected}" "${deadline_ms}"
}

driver_raw_delayed_trailing_case() {
  local expected=${tmp}/driver-delayed.expected deadline_ms writer_pid status
  raw_ack=${tmp}/driver-delayed.raw
  printf 'FORMAT=1\nSTOPPED=1\n' > "${expected}"
  cp -- "${expected}" "${raw_ack}"
  chmod 0600 "${expected}" "${raw_ack}"
  (sleep 0.050; printf 'X' >> "${raw_ack}") &
  writer_pid=$!
  deadline_ms=$(($(monotonic_ms) + 5000))
  set +e
  assert_raw_phase_exact "${expected}" "${deadline_ms}"
  status=$?
  set -e
  wait "${writer_pid}"
  (( status != 0 ))
}

single_read_contract_case() {
  local frame_reader permit_reader
  frame_reader=$(extract_function read_exact_frame "${ACTUATOR}")
  permit_reader=$(sed -n \
    '/# One full-block read retains/,/^raw_size=/p' "${AUTHORIZER}")
  [[ $(grep -Fc 'dd iflag=fullblock' <<< "${frame_reader}") -eq 1 ]] &&
    [[ $(grep -Fc 'dd iflag=fullblock' <<< "${permit_reader}") -eq 1 ]] &&
    ! grep -Eq '^[[:space:]]*(while|until)[[:space:]]' <<< "${frame_reader}" &&
    ! grep -Eq '^[[:space:]]*(while|until)[[:space:]]' <<< "${permit_reader}" &&
    ! grep -Eq 'read[[:space:]].*-t' <<< "${frame_reader}" &&
    grep -Fq 'actual_bytes=$(stat -c '\''%s'\'' -- "${destination}") || return 1' \
      <<< "${frame_reader}" &&
    grep -Fq '[[ ${actual_bytes} -eq ${expected_bytes} ]] || return 1' \
      <<< "${frame_reader}" &&
    grep -Fq 'MAX_ENVELOPE_BYTES=2048' "${AUTHORIZER}" &&
    grep -Fq 'bs=$((MAX_ENVELOPE_BYTES + 1)) count=1' "${AUTHORIZER}" &&
    grep -Fq '(( raw_size > 0 && raw_size <= MAX_ENVELOPE_BYTES ))' "${AUTHORIZER}"
}

canonical_comparison_contract_case() {
  grep -Fq 'cmp -s -- "${open_frame}" "${canonical_frame}"' "${ACTUATOR}" &&
    grep -Fq 'cmp -s -- "${phase_frame}" "${canonical_frame}"' "${ACTUATOR}" &&
    grep -Fq 'cmp -s -- "${raw_envelope}" "${canonical_envelope}"' "${AUTHORIZER}" &&
    grep -Fq 'cmp -s -- "${raw_ack}" "${ack}"' "${DRIVER}"
}

commit_eof_order_contract_case() {
  local commit_read commit_verify exact_eof final_ack
  commit_read=$(grep -nF \
    'read_exact_frame "${phase_frame}" "${COMMIT_FRAME_BYTES}"' "${ACTUATOR}" |
    cut -d: -f1)
  commit_verify=$(awk -v after="${commit_read}" \
    'NR > after && /openssl pkeyutl -verify/ { print NR; exit }' "${ACTUATOR}")
  exact_eof=$(grep -nF 'assert_exact_eof "${input_probe}"' "${ACTUATOR}" |
    cut -d: -f1)
  final_ack=$(grep -nF "printf 'STATUS=pass" "${ACTUATOR}" | cut -d: -f1)
  [[ ${commit_read} =~ ^[0-9]+$ && ${commit_verify} =~ ^[0-9]+$ &&
    ${exact_eof} =~ ^[0-9]+$ && ${final_ack} =~ ^[0-9]+$ ]] &&
    (( commit_read < commit_verify && commit_verify < exact_eof &&
      exact_eof < final_ack ))
}

printf '1..18\n'
expect_success 'fragmented fixed frame is retained, canonical, and accepted' \
  fragmented_open_case
expect_success 'embedded NUL survives the byte read and canonical validation rejects it' \
  embedded_nul_case
expect_success 'early EOF cannot satisfy a fixed-length frame' early_eof_case
expect_success 'one trailing byte is rejected before the next phase' trailing_byte_case
expect_success 'concatenated frames are rejected as prequeued input' concatenated_frame_case
expect_success 'a partial frame hitting its absolute timeout fails closed' \
  partial_timeout_case
expect_success 'a fragmented bounded permit envelope is retained through EOF' \
  fragmented_permit_case
expect_success 'a cap-plus-one permit envelope is rejected as oversized' \
  oversized_permit_case
expect_success 'closed input is accepted as exact EOF after commit' \
  closed_stream_is_exact_eof
expect_success 'a trailing NUL byte is not mistaken for EOF' nul_is_not_eof
expect_success 'an open idle stream is not mistaken for EOF' unclosed_stream_is_not_eof
expect_success 'driver accepts a fragmented raw phase only after exact capture' \
  driver_raw_fragmented_case
expect_success 'driver rejects an embedded NUL before the phase transition' \
  driver_raw_nul_case
expect_success 'driver rejects a prequeued later phase before transition' \
  driver_raw_prequeue_case
expect_success 'driver rejects a byte arriving during anti-prequeue stability' \
  driver_raw_delayed_trailing_case
expect_success 'frame readers use one full-block read and no polling retry loop' \
  single_read_contract_case
expect_success 'canonical byte comparisons and post-commit EOF precede acceptance' \
  canonical_comparison_contract_case

# Keep the ordering check separate so a source refactor cannot accidentally move
# exact-EOF validation ahead of commit authentication or after the success ACK.
expect_success 'commit is verified before exact EOF and the success ACK' \
  commit_eof_order_contract_case
