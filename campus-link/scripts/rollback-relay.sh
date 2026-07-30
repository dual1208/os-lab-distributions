#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ROLLBACK_ROOT=/var/lib/campus-link/rollback-relay
readonly SNAPSHOTS=${ROLLBACK_ROOT}/snapshots
readonly ACTIVE=${ROLLBACK_ROOT}/ACTIVE
readonly TRANSACTION_LOCK=/run/campus-link-install-relay.lock
readonly FAULT_RUNTIME_DIR=/run/campus-link-relay-fault
readonly ACTUATOR_LOCK=${FAULT_RUNTIME_DIR}/actuator.lock
readonly START_INHIBIT=${FAULT_RUNTIME_DIR}/inhibit-start
readonly RECOVERY_BASE=campus-link-relay-fault-recovery
readonly AUTHORITY_LOCK=/run/campus-link-provision-relay-fault.lock
readonly FAULT_STATE_DIR=/var/lib/campus-link-relay-fault
readonly USED_DIR=${FAULT_STATE_DIR}/used
readonly EXPECTED_PERMIT=${FAULT_STATE_DIR}/expected-run.env
readonly REVOKED_DIR=${FAULT_STATE_DIR}/revoked
readonly MAX_LEDGER_ENTRIES=4096
readonly FAULT_USER=campus-link-fault
readonly ACTUATOR=/usr/local/libexec/campus-link-relay-restart-actuator
readonly PERMIT_AUTHORIZER=/usr/local/libexec/campus-link-relay-restart-permit-authorize
readonly PERMIT_PUBLIC_KEY=/etc/ssh/campus-link-relay-fault-permit-ed25519.pub.pem
readonly AUTHORIZED_KEYS=/etc/ssh/campus-link-relay-fault-authorized_keys
readonly FAULT_SUDOERS=/etc/sudoers.d/campus-link-relay-fault
readonly SUDO_SECURE_PATH=/usr/sbin:/usr/bin:/sbin:/bin
readonly SUDO_INERT_ENV=CAMPUS_LINK_SUDO_EMPTY
readonly SUDO_ENV_DELETE='BASH_ENV ENV BASHOPTS SHELLOPTS CDPATH GLOBIGNORE IFS PATH GCONV_PATH LOCPATH LD_* LANG LANGUAGE LC_* OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES PYTHONHOME PYTHONPATH PERL5OPT RUBYOPT SYSTEMD_* PAGER LESS MORE TMPDIR TMP TEMP'
readonly requested_transaction_id=${1:-}

read_one_line_file() {
  local path=$1 output_name=$2 line_count
  local -a lines=()
  local -n output=${output_name}
  line_count=$(wc -l < "${path}") || return 1
  [[ ${line_count} =~ ^[0-9]+$ && ${line_count} -eq 1 ]] || return 1
  mapfile -t lines < "${path}" || return 1
  [[ ${#lines[@]} -eq 1 ]] || return 1
  output=${lines[0]}
}

checked_fixed_count() {
  local output_name=$1 needle=$2 file=$3 status=0 value
  local -n output=${output_name}
  value=$(grep -Fxc -- "${needle}" "${file}") || status=$?
  (( status == 0 || status == 1 )) || return 1
  [[ ${value} =~ ^[0-9]+$ ]] || return 1
  (( status == 0 )) || [[ ${value} == 0 ]] || return 1
  output=${value}
}

snapshot_entry_state() {
  local output_name=$1 path=$2 relative=${path#/} present_count absent_count
  local -n output=${output_name}
  checked_fixed_count present_count "present ${relative}" "${SNAPSHOT}/manifest" || return 1
  checked_fixed_count absent_count "absent ${relative}" "${SNAPSHOT}/manifest" || return 1
  (( present_count + absent_count == 1 )) || return 1
  if (( present_count == 1 )); then
    output=present
  else
    output=absent
  fi
}

list_directory_paths() {
  local output_name=$1 directory=$2 inventory
  local -n output=${output_name}
  output=()
  inventory=$(mktemp /run/.campus-link-paths.XXXXXX) || return 1
  if ! find "${directory}" -mindepth 1 -maxdepth 1 -print0 > "${inventory}"; then
    rm -f -- "${inventory}" || :
    return 1
  fi
  if ! mapfile -d '' -t output < "${inventory}"; then
    rm -f -- "${inventory}" || :
    return 1
  fi
  rm -f -- "${inventory}" || return 1
}

collect_extended_matches() {
  local output_name=$1 pattern=$2 rendered=$3 status=0 raw
  local -n output=${output_name}
  output=()
  raw=$(grep -E "${pattern}" <<< "${rendered}") || status=$?
  (( status == 0 || status == 1 )) || return 1
  if (( status == 0 )); then
    mapfile -t output <<< "${raw}" || return 1
  else
    [[ -z ${raw} ]] || return 1
  fi
}

compare_generated_file() {
  local actual=$1 expected result=0
  shift
  expected=$(mktemp /run/.campus-link-expected.XXXXXX) || return 1
  if ! "$@" > "${expected}"; then
    rm -f -- "${expected}" || :
    return 1
  fi
  cmp -s -- "${expected}" "${actual}" || result=$?
  rm -f -- "${expected}" || return 1
  (( result == 0 ))
}

[[ ${EUID} -eq 0 ]]
[[ -z ${requested_transaction_id} || ${requested_transaction_id} =~ ^[a-f0-9]{32}$ ]]

assert_no_pending_recovery() {
  local suffix load_state
  for suffix in timer service; do
    load_state=$(systemctl show -p LoadState --value \
      "${RECOVERY_BASE}.${suffix}") || return 1
    [[ ${load_state} == not-found ]] || return 1
  done
}

validate_inherited_lock() {
  local descriptor=$1 expected=$2 resolved tuple
  [[ -e /proc/$$/fd/${descriptor} ]]
  resolved=$(readlink -f -- "/proc/$$/fd/${descriptor}") || return 1
  [[ ${resolved} == "${expected}" ]]
  tuple=$(stat -Lc '%u:%g:%a:%h' -- "/proc/$$/fd/${descriptor}") || return 1
  [[ ${tuple} == 0:0:600:1 ]]
  flock -n "${descriptor}"
}

inherited_locks=${CAMPUS_LINK_INHERITED_RELAY_MUTATION_LOCKS:-0}
[[ ${inherited_locks} == 0 || ${inherited_locks} == 1 ]]
if [[ ${inherited_locks} == 1 ]]; then
  validate_inherited_lock 9 "${TRANSACTION_LOCK}"
  validate_inherited_lock 7 "${ACTUATOR_LOCK}"
else
  [[ ! -L ${TRANSACTION_LOCK} ]]
  exec 9<>"${TRANSACTION_LOCK}"
  flock -w 30 9
  chown root:root "${TRANSACTION_LOCK}"
  chmod 0600 "${TRANSACTION_LOCK}"
  transaction_lock_tuple=$(stat -c '%u:%g:%a:%h' -- "${TRANSACTION_LOCK}") || exit 1
  [[ ${transaction_lock_tuple} == 0:0:600:1 ]]

  if [[ -e ${FAULT_RUNTIME_DIR} || -L ${FAULT_RUNTIME_DIR} ]]; then
    [[ -d ${FAULT_RUNTIME_DIR} && ! -L ${FAULT_RUNTIME_DIR} ]]
  else
    install -d -m 0700 -o root -g root "${FAULT_RUNTIME_DIR}"
  fi
  fault_runtime_tuple=$(stat -c '%u:%g:%a' -- "${FAULT_RUNTIME_DIR}") || exit 1
  [[ ${fault_runtime_tuple} == 0:0:700 ]]
  [[ ! -L ${ACTUATOR_LOCK} ]]
  exec 7<>"${ACTUATOR_LOCK}"
  flock -w 30 7
  chown root:root "${ACTUATOR_LOCK}"
  chmod 0600 "${ACTUATOR_LOCK}"
  actuator_lock_tuple=$(stat -c '%u:%g:%a:%h' -- "${ACTUATOR_LOCK}") || exit 1
  [[ ${actuator_lock_tuple} == 0:0:600:1 ]]
fi

[[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]] || {
  echo 'A relay-fault start inhibit remains active; refusing rollback.' >&2
  exit 5
}
assert_no_pending_recovery || {
  echo 'A relay-fault recovery unit remains loaded; refusing rollback.' >&2
  exit 5
}

[[ ! -L ${AUTHORITY_LOCK} ]]
exec 8<>"${AUTHORITY_LOCK}"
flock -w 30 8
chown root:root "${AUTHORITY_LOCK}"
chmod 0600 "${AUTHORITY_LOCK}"
authority_lock_tuple=$(stat -c '%u:%g:%a:%h' -- "${AUTHORITY_LOCK}") || exit 1
[[ ${authority_lock_tuple} == 0:0:600:1 ]]

if [[ -n ${requested_transaction_id} ]]; then
  transaction_id=${requested_transaction_id}
else
  [[ -f ${ACTIVE} && ! -L ${ACTIVE} ]]
  read_one_line_file "${ACTIVE}" transaction_id
fi
[[ ${transaction_id} =~ ^[a-f0-9]{32}$ ]]
readonly transaction_id
readonly SNAPSHOT=${SNAPSHOTS}/${transaction_id}
if [[ -e ${SNAPSHOT}/.rolled-back || -L ${SNAPSHOT}/.rolled-back ]]; then
  [[ -f ${SNAPSHOT}/.rolled-back && ! -L ${SNAPSHOT}/.rolled-back ]]
  read_one_line_file "${SNAPSHOT}/.rolled-back" rolled_back_transaction
  [[ ${rolled_back_transaction} == "${transaction_id}" ]]
  exit 0
fi
[[ -d ${SNAPSHOT} && ! -L ${SNAPSHOT} ]]
[[ -f ${SNAPSHOT}/.complete && ! -L ${SNAPSHOT}/.complete ]]
read_one_line_file "${SNAPSHOT}/.complete" complete_transaction
[[ ${complete_transaction} == "${transaction_id}" ]]
[[ -f ${SNAPSHOT}/manifest && ! -L ${SNAPSHOT}/manifest ]]

readonly -a snapshot_paths=(
  /usr/local/bin/campus-link-relay
  /usr/local/libexec/campus-link-rollback-relay
  /usr/local/libexec/campus-link-provision-relay-fault-access
  /usr/local/libexec/campus-link-relay-restart-actuator
  /usr/local/libexec/campus-link-relay-restart-authorized
  /usr/local/libexec/campus-link-relay-restart-permit-authorize
  /etc/systemd/system/campus-link-relay.service
  /etc/ssh/campus-link-relay-fault-authorized_keys
  /etc/ssh/campus-link-relay-fault-permit-ed25519.pub.pem
  /etc/ssh/sshd_config.d/90-campus-link-relay-fault.conf
  /etc/sudoers.d/campus-link-relay-fault
  /etc/campus-link/relay.json
  /etc/campus-link/pki
  /var/lib/campus-link/installed-relay-version
  /var/lib/campus-link/installed-release-manifest.sha256
  /var/lib/campus-link/deployment-attestation.env
)
for path in "${snapshot_paths[@]}"; do
  snapshot_entry_state entry_state "${path}"
done
manifest_line_count=$(wc -l < "${SNAPSHOT}/manifest") || exit 1
[[ ${manifest_line_count} =~ ^[0-9]+$ &&
  ${manifest_line_count} -eq ${#snapshot_paths[@]} ]]

require_root_directory() {
  local path=$1 mode=$2 tuple
  [[ -d ${path} && ! -L ${path} ]] || return 1
  tuple=$(stat -c '%u:%g:%a' -- "${path}") || return 1
  [[ ${tuple} == "0:0:${mode}" ]] || return 1
  return 0
}

require_root_regular_file() {
  local path=$1 mode=$2 tuple
  [[ -f ${path} && ! -L ${path} ]] || return 1
  tuple=$(stat -c '%u:%g:%a:%h' -- "${path}") || return 1
  [[ ${tuple} == "0:0:${mode}:1" ]] || return 1
  return 0
}

validate_preserved_used_ledger() {
  local path name
  local -a paths=()
  if [[ ! -e ${USED_DIR} && ! -L ${USED_DIR} ]]; then
    return
  fi
  require_root_directory "${USED_DIR}" 700 || return 1
  list_directory_paths paths "${USED_DIR}" || return 1
  ((${#paths[@]} <= MAX_LEDGER_ENTRIES)) || return 1
  for path in "${paths[@]}"; do
    name=$(basename -- "${path}") || return 1
    [[ ${name} =~ ^[a-f0-9]{32}$ ]] || return 1
    require_root_regular_file "${path}" 600 || return 1
  done
  return 0
}

quarantine_pending_permit() {
  local path name digest destination expected_size
  local -a revoked=()
  if [[ ! -e ${FAULT_STATE_DIR} && ! -L ${FAULT_STATE_DIR} ]]; then
    return
  fi
  require_root_directory "${FAULT_STATE_DIR}" 700 || return 1
  validate_preserved_used_ledger || return 1
  if [[ ! -e ${EXPECTED_PERMIT} && ! -L ${EXPECTED_PERMIT} ]]; then
    return
  fi
  require_root_regular_file "${EXPECTED_PERMIT}" 600 || return 1
  expected_size=$(stat -c '%s' -- "${EXPECTED_PERMIT}") || return 1
  [[ ${expected_size} =~ ^[0-9]+$ ]] && (( expected_size <= 4096 )) || return 1
  if [[ -e ${REVOKED_DIR} || -L ${REVOKED_DIR} ]]; then
    require_root_directory "${REVOKED_DIR}" 700 || return 1
  else
    install -d -m 0700 -o root -g root "${REVOKED_DIR}" || return 1
  fi
  list_directory_paths revoked "${REVOKED_DIR}" || return 1
  ((${#revoked[@]} <= MAX_LEDGER_ENTRIES)) || return 1
  for path in "${revoked[@]}"; do
    name=$(basename -- "${path}") || return 1
    [[ ${name} =~ ^[a-f0-9]{32}-[a-f0-9]{64}\.env$ ]] || return 1
    require_root_regular_file "${path}" 600 || return 1
  done
  digest=$(sha256sum -- "${EXPECTED_PERMIT}" | awk '{print $1}') || return 1
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]] || return 1
  destination=${REVOKED_DIR}/${transaction_id}-${digest}.env
  if [[ -e ${destination} || -L ${destination} ]]; then
    require_root_regular_file "${destination}" 600 || return 1
    cmp -s -- "${EXPECTED_PERMIT}" "${destination}" || return 1
    rm -f -- "${EXPECTED_PERMIT}" || return 1
  else
    ((${#revoked[@]} < MAX_LEDGER_ENTRIES)) || return 1
    mv -T -- "${EXPECTED_PERMIT}" "${destination}" || return 1
  fi
  [[ ! -e ${EXPECTED_PERMIT} && ! -L ${EXPECTED_PERMIT} ]] || return 1
  require_root_regular_file "${destination}" 600 || return 1
  sync -f -- "${REVOKED_DIR}" || return 1
  sync -f -- "${FAULT_STATE_DIR}" || return 1
  return 0
}

restore_file() {
  local path=$1 relative=${path#/} source=${SNAPSHOT}/rootfs/${path#/}
  local parent tmp entry_state path_name
  snapshot_entry_state entry_state "${path}" || return 1
  if [[ ${entry_state} == present ]]; then
    [[ -f ${source} && ! -L ${source} ]]
    parent=$(dirname "${path}") || return 1
    if [[ -e ${parent} || -L ${parent} ]]; then
      [[ -d ${parent} && ! -L ${parent} ]]
    else
      install -d -m 0755 "${parent}"
    fi
    path_name=$(basename "${path}") || return 1
    tmp=$(mktemp "${parent}/.${path_name}.restore.XXXXXX") || return 1
    cp -a -- "${source}" "${tmp}"
    mv -fT -- "${tmp}" "${path}"
  else
    rm -f -- "${path}"
  fi
}

restore_pki() {
  local path=/etc/campus-link/pki relative=etc/campus-link/pki
  local source=${SNAPSHOT}/rootfs/${relative}
  local staged=/etc/campus-link/.pki.restore.${transaction_id}
  local displaced=/etc/campus-link/.pki.displaced.${transaction_id}
  local entry_state
  install -d -m 0755 /etc/campus-link
  rm -rf -- "${staged}" "${displaced}"
  snapshot_entry_state entry_state "${path}" || return 1
  if [[ ${entry_state} == present ]]; then
    [[ -d ${source} && ! -L ${source} ]]
    cp -a -- "${source}" "${staged}"
  fi
  if [[ -e ${path} || -L ${path} ]]; then
    mv -T -- "${path}" "${displaced}"
  fi
  if [[ -e ${staged} ]]; then
    mv -T -- "${staged}" "${path}"
  fi
  rm -rf -- "${displaced}"
}

validate_effective_environment_policy() {
  local rendered=$1 key rest token
  local -a tokens=()
  while IFS=' ' read -r key rest; do
    case ${key} in
      acceptenv)
        [[ -n ${rest} ]]
        read -r -a tokens <<< "${rest}"
        for token in "${tokens[@]}"; do
          [[ ${token} == LANG || ${token} == 'LC_*' ]] || return 1
        done
        ;;
      setenv) return 1 ;;
    esac
  done <<< "${rendered}"
}

enumerate_sshd_connection_contexts() {
  local source_address=$1 base_file address_file result=0
  base_file=$(mktemp /run/.campus-link-sshd-base.XXXXXX) || return 1
  address_file=$(mktemp /run/.campus-link-sshd-addresses.XXXXXX) || {
    rm -f -- "${base_file}" || :
    return 1
  }
  if ! sshd -T > "${base_file}" || ! ip -j address show > "${address_file}"; then
    rm -f -- "${base_file}" "${address_file}"
    return 1
  fi
  # CAMPUS_LINK_SSHD_CONTEXT_ENUMERATOR
  if ! python3 -B - "${source_address}" "${base_file}" "${address_file}" <<'PY'
import ipaddress
import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


source_text, base_path, address_path = sys.argv[1:]
try:
    source = ipaddress.ip_address(source_text)
except ValueError as exc:
    fail(f"invalid source address: {exc}")
base_raw = Path(base_path).read_bytes()
address_raw = Path(address_path).read_bytes()
if not base_raw or len(base_raw) > 1048576 or b"\x00" in base_raw or b"\r" in base_raw:
    fail("invalid sshd -T output")
if not address_raw or len(address_raw) > 4194304 or b"\x00" in address_raw:
    fail("invalid local-address inventory")
try:
    base_lines = base_raw.decode("utf-8", "strict").splitlines()
    interfaces = json.loads(address_raw.decode("utf-8", "strict"))
except (UnicodeDecodeError, json.JSONDecodeError) as exc:
    fail(f"invalid context inventory encoding: {exc}")

use_dns = [line for line in base_lines if line.startswith("usedns ")]
if use_dns != ["usedns no"]:
    fail("UseDNS must be unambiguously disabled for numeric Match Host evaluation")
listen_values = [line.split(None, 1)[1] for line in base_lines if line.startswith("listenaddress ")]
if not listen_values or len(listen_values) > 32:
    fail("sshd listen-address inventory is empty or unbounded")

configured: dict[int, set[ipaddress.IPv4Address | ipaddress.IPv6Address]] = {4: set(), 6: set()}
if not isinstance(interfaces, list):
    fail("local-address inventory is not a list")
for interface in interfaces:
    if not isinstance(interface, dict) or not isinstance(interface.get("addr_info"), list):
        fail("malformed local-address inventory")
    for item in interface["addr_info"]:
        if not isinstance(item, dict) or item.get("family") not in ("inet", "inet6"):
            continue
        value = item.get("local")
        if not isinstance(value, str):
            fail("local address is not text")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            fail(f"invalid local address: {exc}")
        expected_version = 4 if item["family"] == "inet" else 6
        if address.version != expected_version:
            fail("local address family mismatch")
        if not address.is_unspecified and not address.is_multicast:
            configured[address.version].add(address)

listen_pattern = re.compile(r"^(?:\[([^]]+)\]|([^:]+)):(\d{1,5})$")
contexts: set[tuple[str, int]] = set()
for value in listen_values:
    match = listen_pattern.fullmatch(value)
    if match is None:
        fail("non-numeric or ambiguous ListenAddress output")
    address_text = match.group(1) or match.group(2)
    port = int(match.group(3))
    if not 1 <= port <= 65535:
        fail("invalid SSH listen port")
    try:
        listen_address = ipaddress.ip_address(address_text)
    except ValueError as exc:
        fail(f"non-numeric SSH listen address: {exc}")
    if listen_address.version != source.version:
        continue
    if listen_address.is_unspecified:
        candidates = configured[listen_address.version]
    else:
        if listen_address not in configured[listen_address.version]:
            fail("configured SSH listen address is absent from the local inventory")
        candidates = {listen_address}
    for local_address in candidates:
        contexts.add((str(local_address), port))

if not contexts or len(contexts) > 64:
    fail("no bounded same-family SSH connection context exists")
for local_address, port in sorted(contexts, key=lambda item: (ipaddress.ip_address(item[0]), item[1])):
    print(
        "user=campus-link-fault,"
        f"host={source},addr={source},laddr={local_address},lport={port}"
    )
PY
  then
    result=1
  fi
  rm -f -- "${base_file}" "${address_file}"
  return "${result}"
}

validate_restored_effective_sshd_policy() {
  local rendered=$1 key expected
  local -a matches=()
  while read -r key expected; do
    collect_extended_matches matches "^${key} " "${rendered}" || return 1
    [[ ${#matches[@]} -eq 1 && ${matches[0]} == "${key} ${expected}" ]]
  done <<'EOF'
authenticationmethods publickey
authorizedkeysfile /etc/ssh/campus-link-relay-fault-authorized_keys
authorizedkeyscommand none
authorizedprincipalscommand none
authorizedprincipalsfile none
trustedusercakeys none
pubkeyauthentication yes
hostbasedauthentication no
gssapiauthentication no
passwordauthentication no
kbdinteractiveauthentication no
permitemptypasswords no
permittty no
permituserrc no
permituserenvironment no
disableforwarding yes
allowagentforwarding no
allowstreamlocalforwarding no
allowtcpforwarding no
x11forwarding no
permittunnel no
gatewayports no
usedns no
forcecommand /usr/local/libexec/campus-link-relay-restart-authorized
EOF
  validate_effective_environment_policy "${rendered}"
}

validate_restored_effective_sshd_contexts() {
  local source_address=$1 authority_present=$2 contexts context rendered
  local -a context_lines=()
  [[ ${authority_present} == 0 || ${authority_present} == 1 ]]
  if ! contexts=$(enumerate_sshd_connection_contexts "${source_address}"); then
    return 1
  fi
  mapfile -t context_lines <<< "${contexts}"
  [[ ${#context_lines[@]} -ge 1 && ${#context_lines[@]} -le 64 ]]
  for context in "${context_lines[@]}"; do
    [[ ${context} == user=campus-link-fault,host=*,addr=*,laddr=*,lport=* ]]
    rendered=$(sshd -T -C "${context}") || return 1
    if [[ ${authority_present} == 1 ]]; then
      validate_restored_effective_sshd_policy "${rendered}"
    else
      grep -Fxq 'usedns no' <<< "${rendered}"
      collect_extended_matches permit_environment '^permituserenvironment ' \
        "${rendered}" || return 1
      [[ ${#permit_environment[@]} -eq 1 ]]
      [[ ${permit_environment[0]} == 'permituserenvironment no' ]]
      validate_effective_environment_policy "${rendered}"
    fi
  done
}

restored_fault_source_address() {
  local line line_count prefix middle suffix rest source_cidr key_body source_address
  if [[ ! -e ${AUTHORIZED_KEYS} && ! -L ${AUTHORIZED_KEYS} ]]; then
    printf '%s\n' 127.0.0.1 || return 1
    return 0
  fi
  require_root_regular_file "${AUTHORIZED_KEYS}" 600 || return 1
  line_count=$(wc -l < "${AUTHORIZED_KEYS}") || return 1
  [[ ${line_count} -eq 1 ]] || return 1
  line=$(<"${AUTHORIZED_KEYS}") || return 1
  prefix='restrict,from="'
  middle='",command="/usr/local/libexec/campus-link-relay-restart-authorized" ssh-ed25519 '
  suffix=' campus-link-relay-fault'
  rest=${line#"${prefix}"}
  [[ ${rest} != "${line}" ]] || return 1
  source_cidr=${rest%%"${middle}"*}
  [[ ${rest} != "${source_cidr}" ]] || return 1
  rest=${rest#"${source_cidr}${middle}"}
  key_body=${rest%"${suffix}"}
  [[ ${key_body} != "${rest}" && ${key_body} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
  [[ ${line} == "${prefix}${source_cidr}${middle}${key_body}${suffix}" ]] || return 1
  python3 -B - "${source_cidr}" <<'PY' || return 1
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
if network.prefixlen != network.max_prefixlen:
    raise SystemExit("relay fault source must be one exact host")
PY
  source_address=${source_cidr%/*}
  [[ -n ${source_address} ]] || return 1
  printf '%s\n' "${source_address}" || return 1
  return 0
}

render_current_fault_sudoers() {
  local command
  for command in "${ACTUATOR}" "${PERMIT_AUTHORIZER}"; do
    printf 'Defaults!%s !use_pty, !requiretty, !log_input, !log_output, !log_stdin, !log_stdout, !log_stderr, !log_ttyin, !log_ttyout, !env_file, !restricted_env_file, env_reset, secure_path="%s", env_keep = "%s", env_check = "%s", env_delete += "%s"\n' \
      "${command}" "${SUDO_SECURE_PATH}" "${SUDO_INERT_ENV}" \
      "${SUDO_INERT_ENV}" "${SUDO_ENV_DELETE}"
  done
  printf '%s ALL=(root:root) NOPASSWD:NOSETENV: %s ""\n%s ALL=(root:root) NOPASSWD:NOSETENV: %s ""\n' \
    "${FAULT_USER}" "${ACTUATOR}" "${FAULT_USER}" "${PERMIT_AUTHORIZER}"
}

validate_effective_sudo_policy() {
  local listing_file result=0 listing_tuple
  visudo -cf /etc/sudoers >/dev/null
  listing_file=$(mktemp /run/.campus-link-sudo-policy.XXXXXX) || return 1
  if ! LC_ALL=C /usr/bin/sudo -n -ll -U "${FAULT_USER}" > "${listing_file}"; then
    rm -f -- "${listing_file}"
    return 1
  fi
  [[ -f ${listing_file} && ! -L ${listing_file} ]]
  listing_tuple=$(stat -c '%u:%g:%a:%h' -- "${listing_file}") || return 1
  [[ ${listing_tuple} == 0:0:600:1 ]]
  # CAMPUS_LINK_EFFECTIVE_SUDO_POLICY_PARSER
  if ! python3 -B - "${listing_file}" "${FAULT_USER}" "${FAULT_SUDOERS}" \
    "${SUDO_SECURE_PATH}" "${SUDO_INERT_ENV}" "${SUDO_ENV_DELETE}" \
    "${ACTUATOR}" "${PERMIT_AUTHORIZER}" <<'PY'
import re
import shlex
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


listing_path, user, sudoers_path, secure_path, inert_env, env_delete, *commands = sys.argv[1:]
if len(commands) != 2 or len(set(commands)) != 2:
    fail("exactly two distinct helper commands are required")
raw = Path(listing_path).read_bytes()
if not raw or len(raw) > 131072 or b"\x00" in raw or b"\r" in raw:
    fail("sudo policy listing has invalid framing")
try:
    lines = raw.decode("utf-8", "strict").splitlines()
except UnicodeDecodeError as exc:
    fail(f"sudo policy listing is not UTF-8: {exc}")

user_header = re.compile(
    rf"^User {re.escape(user)} may run the following commands on [^\s:]+:$"
)
header_indexes = [index for index, line in enumerate(lines) if user_header.fullmatch(line)]
if len(header_indexes) != 1:
    fail("sudo policy must contain one effective user-policy section")
user_index = header_indexes[0]

defaults_header = f"Runas and Command-specific defaults for {user}:"
defaults_indexes = [
    index for index, line in enumerate(lines[:user_index]) if line == defaults_header
]
if len(defaults_indexes) != 1:
    fail("sudo policy must enumerate command-specific defaults once")
defaults_lines = [
    line.strip() for line in lines[defaults_indexes[0] + 1 : user_index] if line.strip()
]
if len(defaults_lines) != 2:
    fail("unexpected runas or command-specific Defaults entries exist")


def split_defaults(value: str) -> list[str]:
    parts: list[str] = []
    start = 0
    escaped = False
    quoted = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == "," and not quoted:
            parts.append(value[start:index].strip())
            start = index + 1
    if escaped or quoted:
        fail("malformed command-specific Defaults output")
    parts.append(value[start:].strip())
    if any(not part for part in parts):
        fail("empty command-specific Defaults token")
    return parts


expected_defaults = {
    "!use_pty",
    "!requiretty",
    "!log_input",
    "!log_output",
    "!log_stdin",
    "!log_stdout",
    "!log_stderr",
    "!log_ttyin",
    "!log_ttyout",
    "!env_file",
    "!restricted_env_file",
    "env_reset",
    f"secure_path={secure_path}",
    f"env_keep={inert_env}",
    f"env_check={inert_env}",
    f"env_delete+={env_delete}",
}
seen_default_commands: set[str] = set()
for line in defaults_lines:
    matches = [command for command in commands if line.startswith(f"Defaults!{command} ")]
    if len(matches) != 1:
        fail("unexpected command-specific Defaults binding")
    command = matches[0]
    if command in seen_default_commands:
        fail("duplicate command-specific Defaults binding")
    seen_default_commands.add(command)
    payload = line[len(f"Defaults!{command} ") :]
    normalized: list[str] = []
    for token in split_defaults(payload):
        parsed = shlex.split(token, posix=True)
        if len(parsed) != 1:
            fail("malformed command-specific Defaults token")
        normalized.append(parsed[0])
    if len(normalized) != len(expected_defaults) or set(normalized) != expected_defaults:
        fail("effective command-specific Defaults are not the closed policy")
if seen_default_commands != set(commands):
    fail("a helper lacks command-specific Defaults")

entries: list[tuple[str, frozenset[str], tuple[str, ...]]] = []
index = user_index + 1
while index < len(lines):
    if not lines[index].strip():
        index += 1
        continue
    header = lines[index]
    if header not in ("Sudoers entry:", f"Sudoers entry: {sudoers_path}"):
        fail("effective policy contains a non-local or unexpected grant source")
    index += 1
    fields: dict[str, str] = {}
    granted_commands: list[str] = []
    in_commands = False
    while index < len(lines) and lines[index].strip():
        stripped = lines[index].strip()
        if in_commands:
            if stripped.startswith(("RunAsUsers:", "RunAsGroups:", "Options:", "Commands:")):
                fail("unexpected field after Commands")
            granted_commands.append(stripped)
        else:
            match = re.fullmatch(r"(RunAsUsers|RunAsGroups|Options|Commands):(?: (.*))?", stripped)
            if match is None:
                fail("unexpected sudo grant field")
            name, value = match.group(1), match.group(2) or ""
            if name in fields:
                fail("duplicate sudo grant field")
            fields[name] = value
            if name == "Commands":
                if value:
                    fail("Commands header contains inline data")
                in_commands = True
        index += 1
    if fields.get("RunAsUsers") != "root" or fields.get("RunAsGroups") != "root":
        fail("helper may be run with an unexpected identity")
    if set(fields) != {"RunAsUsers", "RunAsGroups", "Options", "Commands"}:
        fail("sudo grant has unexpected semantics")
    options = frozenset(part.strip() for part in fields["Options"].split(",") if part.strip())
    if options != frozenset(("!authenticate", "!setenv")):
        fail("sudo grant does not enforce NOPASSWD:NOSETENV exactly")
    if len(granted_commands) != 1:
        fail("sudo grant must contain one command")
    entries.append((header, options, tuple(granted_commands)))

if len(entries) != 2:
    fail("effective merged sudo policy has extra or missing grants")
actual_commands = {entry[2][0] for entry in entries}
expected_commands = {f'{command} ""' for command in commands}
if actual_commands != expected_commands:
    fail("effective merged sudo policy is not the two zero-argument helpers")
PY
  then
    result=1
  fi
  rm -f -- "${listing_file}"
  return "${result}"
}

quarantine_pending_permit
rm -f -- "${SNAPSHOT}/.fault-authority-open"
relay_load_state=$(systemctl show -p LoadState --value campus-link-relay.service) || exit 1
if [[ ${relay_load_state} != not-found ]]; then
  systemctl stop campus-link-relay.service >/dev/null 2>&1
fi
for path in "${snapshot_paths[@]}"; do
  if [[ ${path} == /etc/campus-link/pki ]]; then
    restore_pki
  else
    restore_file "${path}"
  fi
done
visudo -cf /etc/sudoers >/dev/null
if [[ -e ${PERMIT_PUBLIC_KEY} || -L ${PERMIT_PUBLIC_KEY} ]]; then
  [[ -f ${PERMIT_PUBLIC_KEY} && ! -L ${PERMIT_PUBLIC_KEY} ]]
  permit_public_tuple=$(stat -c '%u:%g:%a:%h' -- "${PERMIT_PUBLIC_KEY}") || exit 1
  [[ ${permit_public_tuple} == 0:0:600:1 ]]
  [[ -f ${FAULT_SUDOERS} && ! -L ${FAULT_SUDOERS} ]]
  fault_sudoers_tuple=$(stat -c '%u:%g:%a:%h' -- "${FAULT_SUDOERS}") || exit 1
  [[ ${fault_sudoers_tuple} == 0:0:440:1 ]]
  compare_generated_file "${FAULT_SUDOERS}" render_current_fault_sudoers
  validate_effective_sudo_policy
fi
sshd -t
fault_source_address=$(restored_fault_source_address) || {
  echo 'Restored relay fault SSH authority failed closed validation.' >&2
  exit 7
}
if [[ -e ${AUTHORIZED_KEYS} || -L ${AUTHORIZED_KEYS} ]]; then
  validate_restored_effective_sshd_contexts "${fault_source_address}" 1
else
  validate_restored_effective_sshd_contexts "${fault_source_address}" 0
fi
if systemctl is-active --quiet ssh.service; then
  systemctl reload ssh.service
elif systemctl is-active --quiet sshd.service; then
  systemctl reload sshd.service
else
  echo 'No active SSH daemon is available for the restored configuration.' >&2
  exit 7
fi
systemctl daemon-reload
if [[ -f ${SNAPSHOT}/enabled.campus-link-relay.service ]]; then
  systemctl enable campus-link-relay.service >/dev/null
else
  systemctl disable campus-link-relay.service >/dev/null 2>&1
fi
if [[ -f ${SNAPSHOT}/active.campus-link-relay.service ]]; then
  systemctl start campus-link-relay.service
  systemctl is-active --quiet campus-link-relay.service
fi

printf '%s\n' "${transaction_id}" > "${SNAPSHOT}/.rolled-back"
chmod 0600 "${SNAPSHOT}/.rolled-back"
rm -f -- "${SNAPSHOT}/.complete"
if [[ -e ${ACTIVE} || -L ${ACTIVE} ]]; then
  [[ -f ${ACTIVE} && ! -L ${ACTIVE} ]]
  read_one_line_file "${ACTIVE}" active_transaction
  if [[ ${active_transaction} == "${transaction_id}" ]]; then
    rm -f -- "${ACTIVE}"
  fi
fi
