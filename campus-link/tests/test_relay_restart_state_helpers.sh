#!/usr/bin/env bash
# Hermetic executable regressions for restart state and deadline helpers.

set -euo pipefail
umask 077
export LC_ALL=C
if [[ ${OSTYPE} == msys* || ${OSTYPE} == cygwin* ]]; then
  export MSYS=winsymlinks:nativestrict
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ACTUATOR=${ROOT}/scripts/relay-restart-actuator.sh
readonly ROOT ACTUATOR

tmp=$(mktemp -d "${TMPDIR:-/tmp}/campus-link-restart-state.XXXXXX")
cleanup() {
  rm -rf -- "${tmp}"
}
trap cleanup EXIT

START_INHIBIT=${tmp}/inhibit-start
HARNESS=${tmp}/actuator-state-harness.sh
QUERY_LOG=${tmp}/systemctl-query.log
TIMEOUT_LOG=${tmp}/timeout.log
REAL_STAT=$(type -P stat)
readonly HARNESS QUERY_LOG TIMEOUT_LOG REAL_STAT

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

# Generate a harness from the production definitions.  The only replacement is
# deterministic time and command inspection at dependency boundaries.
absence_expression=$(grep -Fx \
  '[[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]]' \
  "${ACTUATOR}" | sed -n '1p')
[[ -n ${absence_expression} ]] || fail 'extract start-inhibit absence contract'
{
  printf 'readonly START_INHIBIT=%q\n' "${START_INHIBIT}"
  printf 'readonly RECOVERY_BASE=campus-link-relay-fault-recovery\n'
  printf 'readonly RECOVERY_CANCEL_TIMEOUT_MILLISECONDS=5000\n'
  printf 'readonly COMMAND_KILL_GRACE_MILLISECONDS=1000\n'
  for function_name in monotonic_ms require_root_file run_bounded \
    assert_start_inhibit remove_start_inhibit cancel_recovery; do
    definition=$(extract_function "${function_name}" "${ACTUATOR}")
    [[ -n ${definition} ]] || fail "extract ${function_name} from actuator"
    printf '%s\n' "${definition}"
  done
  printf 'preflight_start_inhibit_absent() {\n  %s\n}\n' \
    "${absence_expression}"
} > "${HARNESS}"
"${BASH}" -n "${HARNESS}"
# shellcheck source=/dev/null
source "${HARNESS}"

# Git Bash cannot create Unix root ownership on its NTFS workspace.  Preserve
# real type checks and emulate only the stat identity tuple the production host
# supplies.  Individual cases vary this tuple to exercise every exact field.
marker_stat_result=0:0:600:1
stat() {
  local path=${!#}
  if [[ $# -eq 4 && $1 == -c && $2 == '%u:%g:%a:%h' && $3 == -- &&
    ${path} == "${START_INHIBIT}" ]]; then
    printf '%s\n' "${marker_stat_result}"
    return 0
  fi
  "${REAL_STAT}" "$@"
}

clear_marker() {
  if [[ -d ${START_INHIBIT} && ! -L ${START_INHIBIT} ]]; then
    rmdir -- "${START_INHIBIT}"
  else
    rm -f -- "${START_INHIBIT}"
  fi
}

missing_preflight_case() {
  clear_marker
  preflight_start_inhibit_absent
}

regular_stale_case() {
  clear_marker
  printf 'stale\n' > "${START_INHIBIT}"
  ! preflight_start_inhibit_absent
}

symlink_stale_case() {
  clear_marker
  ln -s -- "${tmp}/missing-target" "${START_INHIBIT}"
  ! preflight_start_inhibit_absent
}

directory_stale_case() {
  clear_marker
  mkdir -- "${START_INHIBIT}"
  ! preflight_start_inhibit_absent
}

exact_marker_removal_case() {
  local sentinel=${tmp}/unrelated
  clear_marker
  printf 'inhibit exact-run\n' > "${START_INHIBIT}"
  printf 'keep\n' > "${sentinel}"
  marker_stat_result=0:0:600:1
  inhibit_sha256=$(sha256sum -- "${START_INHIBIT}" | awk '{print $1}')
  start_inhibited=1
  assert_start_inhibit && remove_start_inhibit &&
    [[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]] &&
    [[ ${start_inhibited} -eq 0 && -f ${sentinel} ]]
}

missing_marker_removal_case() {
  clear_marker
  unset inhibit_sha256
  start_inhibited=1
  remove_start_inhibit && [[ ${start_inhibited} -eq 0 ]]
}

wrong_digest_case() {
  clear_marker
  printf 'inhibit exact-run\n' > "${START_INHIBIT}"
  marker_stat_result=0:0:600:1
  inhibit_sha256=$(printf '0%.0s' {1..64})
  start_inhibited=1
  ! remove_start_inhibit && [[ -f ${START_INHIBIT} ]] &&
    [[ ${start_inhibited} -eq 1 ]]
}

wrong_owner_case() {
  clear_marker
  printf 'inhibit exact-run\n' > "${START_INHIBIT}"
  marker_stat_result=1000:0:600:1
  inhibit_sha256=$(sha256sum -- "${START_INHIBIT}" | awk '{print $1}')
  start_inhibited=1
  ! remove_start_inhibit && [[ -f ${START_INHIBIT} ]]
}

wrong_mode_case() {
  clear_marker
  printf 'inhibit exact-run\n' > "${START_INHIBIT}"
  marker_stat_result=0:0:640:1
  inhibit_sha256=$(sha256sum -- "${START_INHIBIT}" | awk '{print $1}')
  start_inhibited=1
  ! remove_start_inhibit && [[ -f ${START_INHIBIT} ]]
}

wrong_link_count_case() {
  clear_marker
  printf 'inhibit exact-run\n' > "${START_INHIBIT}"
  marker_stat_result=0:0:600:2
  inhibit_sha256=$(sha256sum -- "${START_INHIBIT}" | awk '{print $1}')
  start_inhibited=1
  ! remove_start_inhibit && [[ -f ${START_INHIBIT} ]]
}

non_regular_type_case() {
  clear_marker
  mkfifo -- "${START_INHIBIT}"
  marker_stat_result=0:0:600:1
  ! require_root_file "${START_INHIBIT}" 600
}

query_mode=
systemctl_query() {
  printf '<%s>\n' "$*" >> "${QUERY_LOG}"
  case ${query_mode} in
    not-found)
      [[ $* == 'show -p LoadState --value '* ]] || return 91
      printf 'not-found\n'
      ;;
    inspection-error)
      return 92
      ;;
    *)
      return 93
      ;;
  esac
}

recovery_not_found_case() {
  : > "${QUERY_LOG}"
  query_mode=not-found
  recovery_armed=1
  operation_deadline_ms=50000
  cancel_recovery && [[ $(wc -l < "${QUERY_LOG}") -eq 2 ]] &&
    ! grep -Fq 'ActiveState' "${QUERY_LOG}"
}

recovery_inspection_error_case() {
  : > "${QUERY_LOG}"
  query_mode=inspection-error
  recovery_armed=1
  operation_deadline_ms=50000
  ! cancel_recovery && [[ $(wc -l < "${QUERY_LOG}") -eq 1 ]]
}

mock_now_ms=0
monotonic_ms() {
  printf '%s\n' "${mock_now_ms}"
}
timeout_status=0
timeout() {
  printf '<%s>\n' "$@" > "${TIMEOUT_LOG}"
  return "${timeout_status}"
}

deadline_expired_case() {
  : > "${TIMEOUT_LOG}"
  mock_now_ms=1000
  ! run_bounded 1000 500 100 probe-command && [[ ! -s ${TIMEOUT_LOG} ]]
}

deadline_equals_grace_case() {
  : > "${TIMEOUT_LOG}"
  mock_now_ms=1000
  ! run_bounded 1100 500 100 probe-command && [[ ! -s ${TIMEOUT_LOG} ]]
}

deadline_one_ms_after_grace_case() {
  local expected=${tmp}/timeout-one-ms.expected
  : > "${TIMEOUT_LOG}"
  mock_now_ms=1000
  printf '%s\n' '<--signal=TERM>' '<--kill-after=0.100s>' '<0.001s>' \
    '<probe-command>' > "${expected}"
  run_bounded 1101 500 100 probe-command &&
    cmp -s -- "${TIMEOUT_LOG}" "${expected}"
}

absolute_remaining_case() {
  local expected=${tmp}/timeout-remaining.expected
  : > "${TIMEOUT_LOG}"
  mock_now_ms=1000
  printf '%s\n' '<--signal=TERM>' '<--kill-after=0.100s>' '<0.201s>' \
    '<probe-command>' '<argument with space>' > "${expected}"
  run_bounded 1301 500 100 probe-command 'argument with space' &&
    cmp -s -- "${TIMEOUT_LOG}" "${expected}"
}

total_cap_case() {
  local expected=${tmp}/timeout-cap.expected
  : > "${TIMEOUT_LOG}"
  mock_now_ms=1000
  printf '%s\n' '<--signal=TERM>' '<--kill-after=0.100s>' '<0.250s>' \
    '<probe-command>' > "${expected}"
  run_bounded 9000 350 100 probe-command &&
    cmp -s -- "${TIMEOUT_LOG}" "${expected}"
}

printf '1..18\n'
expect_success 'missing inhibit marker satisfies the extracted preflight contract' \
  missing_preflight_case
expect_success 'a stale regular marker is rejected before mutation' regular_stale_case
expect_success 'a dangling stale symlink is rejected before mutation' symlink_stale_case
expect_success 'a stale directory is rejected before mutation' directory_stale_case
expect_success 'the exact owned marker validates and only it is removed' \
  exact_marker_removal_case
expect_success 'an already missing owned marker is an idempotent removal success' \
  missing_marker_removal_case
expect_success 'a wrong marker digest fails closed and preserves state' wrong_digest_case
expect_success 'non-root marker ownership is rejected' wrong_owner_case
expect_success 'a marker with the wrong mode is rejected' wrong_mode_case
expect_success 'a multiply linked marker is rejected' wrong_link_count_case
expect_success 'missing recovery units cancel without a stop or active-state query' \
  recovery_not_found_case
expect_success 'a recovery-unit inspection error fails closed' \
  recovery_inspection_error_case
expect_success 'an expired absolute deadline runs no command' deadline_expired_case
expect_success 'remaining time equal to grace runs no command' \
  deadline_equals_grace_case
expect_success 'one millisecond beyond grace is assigned only to the command' \
  deadline_one_ms_after_grace_case
expect_success 'absolute remaining time and the total cap bound command duration' \
  absolute_remaining_case

# Keep the cap case separate so a future refactor cannot silently use the
# absolute remaining time while ignoring the per-operation ceiling.
expect_success 'the per-operation total cap bounds command plus grace' \
  total_cap_case
expect_success 'a non-regular marker cannot pass the exact file validator' \
  non_regular_type_case
