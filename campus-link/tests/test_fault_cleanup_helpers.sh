#!/usr/bin/env bash
# Executable regressions for bounded, fail-closed fault-rule cleanup.

set -euo pipefail
export LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE=${ROOT}/scripts/fault-in-stream.sh
readonly ROOT SOURCE

extract_function() {
  local name=$1 source=$2
  awk -v signature="${name}() {" '
    $0 == signature { inside = 1 }
    inside { print }
    inside && $0 == "}" { exit }
  ' "${source}"
}

for name in delete_exact_rule_bounded clear_control_block clear_direct_block; do
  definition=$(extract_function "${name}" "${SOURCE}")
  [[ -n ${definition} ]] || exit 1
  eval "${definition}"
done

readonly FAULT_RULE_DELETE_LIMIT=16
readonly FAULT_CLEANUP_COMMAND_MILLISECONDS=2000
readonly FAULT_CLEANUP_KILL_GRACE_MILLISECONDS=500

declare -a scripted_statuses=() calls=()
call_index=0
cleanup_run_bounded() {
  calls+=("$*")
  local status=${scripted_statuses[call_index]:-125}
  call_index=$((call_index + 1))
  return "${status}"
}

reset_script() {
  scripted_statuses=("$@")
  calls=()
  call_index=0
}

absent_rule_case() {
  reset_script 1 0
  delete_exact_rule_bounded 999999 campus-a OUTPUT -p udp -j DROP
  [[ ${#calls[@]} -eq 2 && ${calls[0]} == *' -C OUTPUT '* &&
    ${calls[1]} == *' -S OUTPUT' ]]
}

duplicate_rules_case() {
  reset_script 0 0 0 0 1 0
  delete_exact_rule_bounded 999999 campus-a OUTPUT -p udp -j DROP
  [[ ${#calls[@]} -eq 6 && ${calls[0]} == *' -C OUTPUT '* &&
    ${calls[1]} == *' -D OUTPUT '* && ${calls[2]} == *' -C OUTPUT '* &&
    ${calls[3]} == *' -D OUTPUT '* && ${calls[4]} == *' -C OUTPUT '* &&
    ${calls[5]} == *' -S OUTPUT' ]]
}

inspection_failure_case() {
  reset_script 124
  ! delete_exact_rule_bounded 999999 campus-a OUTPUT -p udp -j DROP
  [[ ${#calls[@]} -eq 1 ]]
}

absence_probe_failure_case() {
  reset_script 1 125
  ! delete_exact_rule_bounded 999999 campus-a OUTPUT -p udp -j DROP
  [[ ${#calls[@]} -eq 2 && ${calls[1]} == *' -S OUTPUT' ]]
}

delete_failure_case() {
  reset_script 0 125
  ! delete_exact_rule_bounded 999999 campus-a OUTPUT -p udp -j DROP
  [[ ${#calls[@]} -eq 2 && ${calls[1]} == *' -D OUTPUT '* ]]
}

delete_limit_case() {
  local -a statuses=()
  local index
  for ((index = 0; index < FAULT_RULE_DELETE_LIMIT; index++)); do
    statuses+=(0 0)
  done
  statuses+=(0)
  reset_script "${statuses[@]}"
  ! delete_exact_rule_bounded 999999 campus-a OUTPUT -p udp -j DROP
  [[ ${#calls[@]} -eq $((2 * FAULT_RULE_DELETE_LIMIT + 1)) ]]
}

partial_clear_continues_case() {
  calls=()
  delete_exact_rule_bounded() {
    calls+=("$*")
    [[ $* != *' OUTPUT '* ]]
  }
  ! clear_control_block campus-a cl-a-wan 999999
  [[ ${#calls[@]} -eq 2 && ${calls[0]} == *' OUTPUT '* &&
    ${calls[1]} == *' INPUT '* ]]
}

tests=0
expect_success() {
  local label=$1
  shift
  tests=$((tests + 1))
  if "$@"; then
    printf 'ok %d - %s\n' "${tests}" "${label}"
  else
    printf 'not ok %d - %s\n' "${tests}" "${label}" >&2
    exit 1
  fi
}

printf '1..7\n'
expect_success 'an absent exact rule is a proven cleanup success' absent_rule_case
expect_success 'duplicate exact rules are deleted and absence is rechecked' \
  duplicate_rules_case
expect_success 'an inspection timeout is not treated as rule absence' \
  inspection_failure_case
expect_success 'a failed chain probe is not treated as rule absence' \
  absence_probe_failure_case
expect_success 'a failed deletion fails without an unbounded retry loop' \
  delete_failure_case
expect_success 'the duplicate deletion cap terminates and fails closed' \
  delete_limit_case
expect_success 'one rule failure does not skip the other cleanup direction' \
  partial_clear_continues_case
