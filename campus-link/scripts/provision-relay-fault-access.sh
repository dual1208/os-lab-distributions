#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ACCESS_DIR=/etc/campus-link/relay-fault
readonly PRIVATE_KEY=${ACCESS_DIR}/id_ed25519
readonly PUBLIC_KEY=${ACCESS_DIR}/id_ed25519.pub
readonly PERMIT_PRIVATE_KEY=${ACCESS_DIR}/permit_ed25519.pem
readonly PERMIT_PUBLIC_KEY=${ACCESS_DIR}/permit_ed25519.pub.pem
readonly TARGET_FILE=${ACCESS_DIR}/target
readonly KNOWN_HOSTS=${ACCESS_DIR}/known_hosts
readonly FAULT_USER=campus-link-fault
readonly AUTHORIZED_KEYS=/etc/ssh/campus-link-relay-fault-authorized_keys
readonly RELAY_PERMIT_PUBLIC_KEY=/etc/ssh/campus-link-relay-fault-permit-ed25519.pub.pem
readonly SSHD_DROP_IN=/etc/ssh/sshd_config.d/90-campus-link-relay-fault.conf
readonly SUDOERS=/etc/sudoers.d/campus-link-relay-fault
readonly AUTHORIZED_COMMAND=/usr/local/libexec/campus-link-relay-restart-authorized
readonly ACTUATOR=/usr/local/libexec/campus-link-relay-restart-actuator
readonly PERMIT_AUTHORIZER=/usr/local/libexec/campus-link-relay-restart-permit-authorize
readonly SUDO_SECURE_PATH=/usr/sbin:/usr/bin:/sbin:/bin
readonly SUDO_INERT_ENV=CAMPUS_LINK_SUDO_EMPTY
readonly SUDO_ENV_DELETE='BASH_ENV ENV BASHOPTS SHELLOPTS CDPATH GLOBIGNORE IFS PATH GCONV_PATH LOCPATH LD_* LANG LANGUAGE LC_* OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES PYTHONHOME PYTHONPATH PERL5OPT RUBYOPT SYSTEMD_* PAGER LESS MORE TMPDIR TMP TEMP'

[[ ${EUID} -eq 0 ]]
exec 8>/run/campus-link-provision-relay-fault.lock
flock -n 8 || {
  echo 'Another campus-link relay-fault provisioning operation is active.' >&2
  exit 5
}

atomic_install() {
  local source=$1 destination=$2 mode=$3 parent tmp destination_name
  parent=$(dirname "${destination}") || return 1
  [[ -d ${parent} && ! -L ${parent} ]]
  destination_name=$(basename "${destination}") || return 1
  tmp=$(mktemp "${parent}/.${destination_name}.XXXXXX") || return 1
  install -m "${mode}" -o root -g root "${source}" "${tmp}"
  mv -fT -- "${tmp}" "${destination}"
}

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

validate_root_file() {
  local path=$1 mode=$2 tuple
  [[ -f ${path} && ! -L ${path} ]]
  tuple=$(stat -c '%u:%g:%a:%h' -- "${path}") || return 1
  [[ ${tuple} == "0:0:${mode}:1" ]]
}

validate_target() {
  local target=$1
  [[ ${target} =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$ ]]
}

load_ed25519_public_key() {
  local path=$1 mode=$2 line
  validate_root_file "${path}" "${mode}"
  read_one_line_file "${path}" line || return 1
  read -r validated_key_type validated_key_body _ <<< "${line}"
  [[ ${validated_key_type} == ssh-ed25519 ]]
  [[ ${validated_key_body} =~ ^[A-Za-z0-9+/]+={0,2}$ ]]
  ssh-keygen -l -f "${path}" >/dev/null
}

validate_openssl_ed25519_public_key() {
  local path=$1 mode=$2 size description
  validate_root_file "${path}" "${mode}"
  size=$(stat -c '%s' -- "${path}") || return 1
  [[ ${size} =~ ^[0-9]+$ ]] && (( size <= 1024 )) || return 1
  grep -Fxq -- '-----BEGIN PUBLIC KEY-----' "${path}"
  grep -Fxq -- '-----END PUBLIC KEY-----' "${path}"
  description=$(openssl pkey -pubin -in "${path}" -text_pub -noout 2>/dev/null |
    sed -n '1p') || return 1
  [[ ${description} == 'ED25519 Public-Key:' ]]
  compare_generated_file "${path}" openssl pkey -pubin -in "${path}" -pubout
}

validate_gate_input() {
  local target=$1 host_public_key_file=$2
  validate_target "${target}"
  load_ed25519_public_key "${host_public_key_file}" 600
}

validate_source_cidr() {
  python3 -B - "$1" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
if network.prefixlen != network.max_prefixlen:
    raise SystemExit("relay fault source must be one exact host")
PY
}

validate_relay_input() {
  local public_key_file=$1 permit_public_key_file=$2 source_cidr=$3
  load_ed25519_public_key "${public_key_file}" 600
  validate_openssl_ed25519_public_key "${permit_public_key_file}" 600
  validate_source_cidr "${source_cidr}"
}

require_transaction_snapshot() {
  local role=$1 transaction_id=${CAMPUS_LINK_TRANSACTION_ID:-} snapshot permit active
  local complete_transaction active_transaction permit_transaction complete_tuple permit_tuple
  [[ ${transaction_id} =~ ^[a-f0-9]{32}$ ]]
  case ${role} in
    edge) snapshot=/var/lib/campus-link/rollback-edge/snapshots/${transaction_id} ;;
    relay) snapshot=/var/lib/campus-link/rollback-relay/snapshots/${transaction_id} ;;
    *) return 2 ;;
  esac
  [[ -d ${snapshot} && ! -L ${snapshot} ]]
  [[ -f ${snapshot}/.complete && ! -L ${snapshot}/.complete ]]
  complete_tuple=$(stat -c '%u:%g:%a:%h' -- "${snapshot}/.complete") || return 1
  [[ ${complete_tuple} == 0:0:600:1 ]]
  read_one_line_file "${snapshot}/.complete" complete_transaction || return 1
  [[ ${complete_transaction} == "${transaction_id}" ]]
  active=/var/lib/campus-link/rollback-${role}/ACTIVE
  validate_root_file "${active}" 600
  read_one_line_file "${active}" active_transaction || return 1
  [[ ${active_transaction} == "${transaction_id}" ]]
  permit=${snapshot}/.fault-authority-open
  [[ -f ${permit} && ! -L ${permit} ]]
  permit_tuple=$(stat -c '%u:%g:%a:%h' -- "${permit}") || return 1
  [[ ${permit_tuple} == 0:0:600:1 ]]
  read_one_line_file "${permit}" permit_transaction || return 1
  [[ ${permit_transaction} == "${transaction_id}" ]]
}

validate_gate_tree() {
  local expected_target=${1:-} expected_host_key=${2:-}
  local actual declared derived host_type host_body access_tuple target_value
  local permit_description expected_target_value expected_known_hosts
  local public_key_line known_hosts_line
  [[ -d ${ACCESS_DIR} && ! -L ${ACCESS_DIR} ]]
  access_tuple=$(stat -c '%u:%g:%a' -- "${ACCESS_DIR}") || return 1
  [[ ${access_tuple} == 0:0:700 ]]
  actual=$(find "${ACCESS_DIR}" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort) || return 1
  [[ ${actual} == $'id_ed25519\nid_ed25519.pub\nknown_hosts\npermit_ed25519.pem\npermit_ed25519.pub.pem\ntarget' ]]
  validate_root_file "${PRIVATE_KEY}" 600
  validate_root_file "${PUBLIC_KEY}" 644
  validate_root_file "${PERMIT_PRIVATE_KEY}" 600
  validate_openssl_ed25519_public_key "${PERMIT_PUBLIC_KEY}" 600
  validate_root_file "${KNOWN_HOSTS}" 600
  validate_root_file "${TARGET_FILE}" 600
  read_one_line_file "${PUBLIC_KEY}" public_key_line || return 1
  read_one_line_file "${KNOWN_HOSTS}" known_hosts_line || return 1
  read_one_line_file "${TARGET_FILE}" target_value || return 1
  grep -Eq '^ssh-ed25519 [A-Za-z0-9+/]+={0,2} campus-link-relay-fault$' "${PUBLIC_KEY}"
  grep -Eq '^campus-link-relay-fault ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' "${KNOWN_HOSTS}"
  validate_target "${target_value}"
  derived=$(ssh-keygen -y -f "${PRIVATE_KEY}" 2>/dev/null) || return 1
  declared=$(cut -d ' ' -f 1-2 "${PUBLIC_KEY}") || return 1
  [[ ${derived} == "${declared}" && ${derived%% *} == ssh-ed25519 ]]
  grep -Fxq -- '-----BEGIN PRIVATE KEY-----' "${PERMIT_PRIVATE_KEY}"
  permit_description=$(openssl pkey -in "${PERMIT_PRIVATE_KEY}" -text_pub -noout 2>/dev/null |
    sed -n '1p') || return 1
  [[ ${permit_description} == 'ED25519 Public-Key:' ]]
  compare_generated_file "${PERMIT_PUBLIC_KEY}" openssl pkey \
    -in "${PERMIT_PRIVATE_KEY}" -pubout
  if [[ -n ${expected_target} || -n ${expected_host_key} ]]; then
    [[ -n ${expected_target} && -n ${expected_host_key} ]]
    validate_gate_input "${expected_target}" "${expected_host_key}"
    host_type=${validated_key_type}
    host_body=${validated_key_body}
    expected_target_value=${expected_target}
    expected_known_hosts="campus-link-relay-fault ${host_type} ${host_body}"
    [[ ${target_value} == "${expected_target_value}" ]]
    [[ ${known_hosts_line} == "${expected_known_hosts}" ]]
  fi
}

provision_gate_host() {
  local target=$1 host_public_key_file=$2 target_source= known_source=
  local permit_private_source= permit_public_source=
  local host_type host_body access_tuple
  require_transaction_snapshot edge
  validate_gate_input "${target}" "${host_public_key_file}"
  host_type=${validated_key_type}
  host_body=${validated_key_body}

  [[ ! -L ${ACCESS_DIR} ]]
  install -d -m 0700 -o root -g root "${ACCESS_DIR}"
  access_tuple=$(stat -c '%u:%g:%a' -- "${ACCESS_DIR}") || return 1
  [[ ${access_tuple} == 0:0:700 ]]
  cleanup_gate_sources() {
    rm -f -- "${target_source:-}" "${known_source:-}" \
      "${permit_private_source:-}" "${permit_public_source:-}"
  }
  trap cleanup_gate_sources EXIT
  if [[ ! -e ${PRIVATE_KEY} && ! -L ${PRIVATE_KEY} ]]; then
    ssh-keygen -q -t ed25519 -N '' -C campus-link-relay-fault -f "${PRIVATE_KEY}"
  fi
  [[ -f ${PRIVATE_KEY} && ! -L ${PRIVATE_KEY} ]]
  [[ -f ${PUBLIC_KEY} && ! -L ${PUBLIC_KEY} ]]
  chown root:root "${PRIVATE_KEY}" "${PUBLIC_KEY}"
  chmod 0600 "${PRIVATE_KEY}"
  chmod 0644 "${PUBLIC_KEY}"

  if [[ ! -e ${PERMIT_PRIVATE_KEY} && ! -L ${PERMIT_PRIVATE_KEY} &&
    ! -e ${PERMIT_PUBLIC_KEY} && ! -L ${PERMIT_PUBLIC_KEY} ]]; then
    permit_private_source=$(mktemp "${ACCESS_DIR}/.permit-private.XXXXXX") || return 1
    permit_public_source=$(mktemp "${ACCESS_DIR}/.permit-public.XXXXXX") || return 1
    openssl genpkey -algorithm ED25519 -out "${permit_private_source}"
    openssl pkey -in "${permit_private_source}" -pubout -out "${permit_public_source}"
    atomic_install "${permit_private_source}" "${PERMIT_PRIVATE_KEY}" 0600
    atomic_install "${permit_public_source}" "${PERMIT_PUBLIC_KEY}" 0600
    rm -f -- "${permit_private_source}" "${permit_public_source}"
    permit_private_source=
    permit_public_source=
  else
    [[ -f ${PERMIT_PRIVATE_KEY} && ! -L ${PERMIT_PRIVATE_KEY} ]]
    [[ -f ${PERMIT_PUBLIC_KEY} && ! -L ${PERMIT_PUBLIC_KEY} ]]
  fi

  target_source=$(mktemp "${ACCESS_DIR}/.target.XXXXXX") || return 1
  known_source=$(mktemp "${ACCESS_DIR}/.known-hosts.XXXXXX") || return 1
  printf '%s\n' "${target}" > "${target_source}"
  printf 'campus-link-relay-fault %s %s\n' "${host_type}" "${host_body}" > "${known_source}"
  atomic_install "${target_source}" "${TARGET_FILE}" 0600
  atomic_install "${known_source}" "${KNOWN_HOSTS}" 0600
  validate_gate_tree "${target}" "${host_public_key_file}"
  cleanup_gate_sources
  trap - EXIT
  printf 'STATUS=pass\nROLE=gate-host\nPRIVATE_KEY_EXPORTED=0\nPUBLIC_KEY_PATH=%s\nPERMIT_PRIVATE_KEY_EXPORTED=0\nPERMIT_PUBLIC_KEY_PATH=%s\n' \
    "${PUBLIC_KEY}" "${PERMIT_PUBLIC_KEY}"
}

validate_fault_account() {
  local group_name group_gid group_members name uid gid home shell
  local shadow_line shadow_name shadow_password shadow_last_change shadow_min
  local shadow_max shadow_warn shadow_inactive shadow_expire shadow_reserved
  local shadow_extra today_unix today_days group_record passwd_record
  local shadow_output primary_group all_groups colon_count
  local -a shadow_lines=()
  group_record=$(getent group "${FAULT_USER}") || return 1
  [[ ${group_record} != *$'\n'* ]] || return 1
  IFS=: read -r group_name _ group_gid group_members <<< "${group_record}" || return 1
  [[ ${group_name} == "${FAULT_USER}" && ${group_gid} =~ ^[0-9]+$ && ${group_gid} != 0 ]] || return 1
  [[ -z ${group_members} ]] || return 1
  passwd_record=$(getent passwd "${FAULT_USER}") || return 1
  [[ ${passwd_record} != *$'\n'* ]] || return 1
  IFS=: read -r name _ uid gid _ home shell <<< "${passwd_record}" || return 1
  [[ ${name} == "${FAULT_USER}" && ${uid} =~ ^[0-9]+$ && ${uid} != 0 ]] || return 1
  [[ ${gid} == "${group_gid}" && ${home} == /nonexistent && ${shell} == /bin/sh ]] || return 1
  primary_group=$(id -gn "${FAULT_USER}") || return 1
  [[ ${primary_group} == "${FAULT_USER}" ]] || return 1
  all_groups=$(id -G "${FAULT_USER}") || return 1
  [[ ${all_groups} == "${gid}" ]] || return 1
  shadow_output=$(getent shadow "${FAULT_USER}") || return 1
  mapfile -t shadow_lines <<< "${shadow_output}" || return 1
  [[ ${#shadow_lines[@]} -eq 1 ]] || return 1
  shadow_line=${shadow_lines[0]}
  colon_count=$(tr -cd ':' <<< "${shadow_line}" | wc -c) || return 1
  [[ ${colon_count} -eq 8 ]] || return 1
  IFS=: read -r shadow_name shadow_password shadow_last_change shadow_min \
    shadow_max shadow_warn shadow_inactive shadow_expire shadow_reserved \
    shadow_extra <<< "${shadow_line}" || return 1
  [[ -z ${shadow_extra} ]] || return 1
  [[ ${shadow_name} == "${FAULT_USER}" && ${shadow_password} == '*NP*' ]] || return 1
  [[ ${shadow_last_change} =~ ^[1-9][0-9]*$ ]] || return 1
  today_unix=$(date -u +%s) || return 1
  [[ ${today_unix} =~ ^[1-9][0-9]*$ ]] || return 1
  today_days=$((today_unix / 86400))
  (( shadow_last_change <= today_days )) || return 1
  [[ ${shadow_min} == 0 && ${shadow_max} == 99999 && ${shadow_warn} == 7 ]] || return 1
  [[ -z ${shadow_inactive} && -z ${shadow_expire} && -z ${shadow_reserved} ]] || return 1
  [[ ! -e /nonexistent && ! -L /nonexistent ]] || return 1
  return 0
}

remove_new_fault_account() {
  local failed=0 user_status=0 group_status=0 user_probe group_probe
  user_probe=$(id "${FAULT_USER}" 2>/dev/null) || user_status=$?
  if (( user_status == 0 )); then
    [[ -n ${user_probe} ]] || failed=1
    userdel "${FAULT_USER}" || failed=1
  elif (( user_status != 1 )) || [[ -n ${user_probe} ]]; then
    failed=1
  fi
  group_probe=$(getent group "${FAULT_USER}") || group_status=$?
  if (( group_status == 0 )); then
    [[ -n ${group_probe} ]] || failed=1
    groupdel "${FAULT_USER}" || failed=1
  elif (( group_status != 2 )) || [[ -n ${group_probe} ]]; then
    failed=1
  fi
  return "${failed}"
}

bootstrap_fault_account() {
  local group_exists=0 user_exists=0 group_status=0 user_status=0
  local group_probe user_probe last_day
  group_probe=$(getent group "${FAULT_USER}") || group_status=$?
  user_probe=$(getent passwd "${FAULT_USER}") || user_status=$?
  case ${group_status} in
    0) [[ -n ${group_probe} ]] || return 1; group_exists=1 ;;
    2) [[ -z ${group_probe} ]] || return 1 ;;
    *) return 1 ;;
  esac
  case ${user_status} in
    0) [[ -n ${user_probe} ]] || return 1; user_exists=1 ;;
    2) [[ -z ${user_probe} ]] || return 1 ;;
    *) return 1 ;;
  esac
  if [[ ${group_exists} -eq 1 || ${user_exists} -eq 1 ]]; then
    [[ ${group_exists} -eq 1 && ${user_exists} -eq 1 ]]
    validate_fault_account
    printf 'STATUS=pass\nROLE=relay-account\nCREATED=0\nAUTHORITY_INSTALLED=0\n'
    return
  fi

  for path in "${AUTHORIZED_KEYS}" "${RELAY_PERMIT_PUBLIC_KEY}" \
    "${SSHD_DROP_IN}" "${SUDOERS}"; do
    [[ ! -e ${path} && ! -L ${path} ]]
  done
  groupadd --system "${FAULT_USER}"
  if ! useradd --system --gid "${FAULT_USER}" --home-dir /nonexistent \
    --no-create-home --shell /bin/sh "${FAULT_USER}"; then
    if ! groupdel "${FAULT_USER}"; then
      echo 'Fault-account bootstrap failed and could not remove its newly created group.' >&2
    fi
    return 1
  fi
  # *NP* is not a usable password hash.  It leaves public-key authentication
  # possible only after the separately transactional Match block is installed.
  last_day=$(date -u +%Y-%m-%d) || return 1
  [[ ${last_day} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
  if ! usermod --password '*NP*' "${FAULT_USER}" ||
    ! chage --lastday "${last_day}" --mindays 0 --maxdays 99999 \
      --warndays 7 --inactive -1 --expiredate -1 "${FAULT_USER}" ||
    ! validate_fault_account; then
    if ! remove_new_fault_account; then
      echo 'Fault-account bootstrap failed and could not remove its newly created identity.' >&2
    fi
    return 1
  fi
  for path in "${AUTHORIZED_KEYS}" "${RELAY_PERMIT_PUBLIC_KEY}" \
    "${SSHD_DROP_IN}" "${SUDOERS}"; do
    if [[ -e ${path} || -L ${path} ]]; then
      if ! remove_new_fault_account; then
        echo 'Fault-account bootstrap found unexpected authority and could not remove its new identity.' >&2
      fi
      return 1
    fi
  done
  printf 'STATUS=pass\nROLE=relay-account\nCREATED=1\nAUTHORITY_INSTALLED=0\n'
}

render_authorized_keys() {
  local source_cidr=$1 key_type=$2 key_body=$3
  printf 'restrict,from="%s",command="/usr/local/libexec/campus-link-relay-restart-authorized" %s %s campus-link-relay-fault\n' \
    "${source_cidr}" "${key_type}" "${key_body}"
}

render_sshd_drop_in() {
  cat <<'EOF'
Match User campus-link-fault
    AuthenticationMethods publickey
    AuthorizedKeysFile /etc/ssh/campus-link-relay-fault-authorized_keys
    AuthorizedKeysCommand none
    AuthorizedPrincipalsCommand none
    AuthorizedPrincipalsFile none
    TrustedUserCAKeys none
    PubkeyAuthentication yes
    HostbasedAuthentication no
    GSSAPIAuthentication no
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitEmptyPasswords no
    PermitTTY no
    PermitUserRC no
    DisableForwarding yes
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    GatewayPorts no
    ForceCommand /usr/local/libexec/campus-link-relay-restart-authorized
Match all
EOF
}

render_sudoers() {
  local command
  for command in "${ACTUATOR}" "${PERMIT_AUTHORIZER}"; do
    printf 'Defaults!%s !use_pty, !requiretty, !log_input, !log_output, !log_stdin, !log_stdout, !log_stderr, !log_ttyin, !log_ttyout, !env_file, !restricted_env_file, env_reset, secure_path="%s", env_keep = "%s", env_check = "%s", env_delete += "%s"\n' \
      "${command}" "${SUDO_SECURE_PATH}" "${SUDO_INERT_ENV}" \
      "${SUDO_INERT_ENV}" "${SUDO_ENV_DELETE}"
  done
  printf '%s ALL=(root:root) NOPASSWD:NOSETENV: %s ""\n%s ALL=(root:root) NOPASSWD:NOSETENV: %s ""\n' \
    "${FAULT_USER}" "${ACTUATOR}" "${FAULT_USER}" "${PERMIT_AUTHORIZER}"
}

validate_privileged_helper() {
  local path=$1 first_line
  validate_root_file "${path}" 755
  first_line=$(sed -n '1p' -- "${path}") || return 1
  [[ ${first_line} == '#!/bin/bash -p' ]]
  grep -Fxq '[[ $- == *p* ]]' "${path}"
  grep -Fxq '[[ -z ${BASH_ENV+x} && -z ${ENV+x} ]]' "${path}"
  grep -Fxq '[[ -z ${LD_PRELOAD+x} && -z ${LD_LIBRARY_PATH+x} && -z ${LD_AUDIT+x} ]]' "${path}"
  grep -Fxq '[[ -z ${OPENSSL_CONF+x} && -z ${OPENSSL_MODULES+x} && -z ${OPENSSL_ENGINES+x} ]]' "${path}"
  grep -Fxq 'sanitize_environment' "${path}"
}

validate_zero_argument_helper() {
  local path=$1
  validate_privileged_helper "${path}"
  grep -Fxq '[[ $# -eq 0 ]]' "${path}"
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
  if ! python3 -B - "${listing_file}" "${FAULT_USER}" "${SUDOERS}" \
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

validate_effective_environment_policy() {
  local rendered=$1 key rest token
  local -a tokens=()
  local -a permit_environment=()
  collect_extended_matches permit_environment '^permituserenvironment ' \
    "${rendered}" || return 1
  [[ ${#permit_environment[@]} -eq 1 ]]
  [[ ${permit_environment[0]} == 'permituserenvironment no' ]]
  # sshd constructs the forced-command environment before the helper can run.
  # Therefore inherited site policy is accepted only for the conventional
  # locale names; trying to blacklist shell/loader variables is not sufficient.
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
  local source_cidr=$1 source_address base_file address_file result=0
  validate_source_cidr "${source_cidr}"
  source_address=${source_cidr%/*}
  [[ -n ${source_address} ]]
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

validate_effective_sshd_environment_contexts() {
  local source_cidr=$1 contexts context rendered
  local -a context_lines=()
  if ! contexts=$(enumerate_sshd_connection_contexts "${source_cidr}"); then
    return 1
  fi
  mapfile -t context_lines <<< "${contexts}"
  [[ ${#context_lines[@]} -ge 1 && ${#context_lines[@]} -le 64 ]]
  for context in "${context_lines[@]}"; do
    [[ ${context} == user=campus-link-fault,host=*,addr=*,laddr=*,lport=* ]]
    rendered=$(sshd -T -C "${context}") || return 1
    grep -Fxq 'usedns no' <<< "${rendered}"
    validate_effective_environment_policy "${rendered}"
  done
}

validate_one_effective_sshd_policy() {
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

validate_effective_sshd_policy() {
  local source_cidr=$1 contexts context rendered
  local -a context_lines=()
  if ! contexts=$(enumerate_sshd_connection_contexts "${source_cidr}"); then
    return 1
  fi
  mapfile -t context_lines <<< "${contexts}"
  [[ ${#context_lines[@]} -ge 1 && ${#context_lines[@]} -le 64 ]]
  for context in "${context_lines[@]}"; do
    [[ ${context} == user=campus-link-fault,host=*,addr=*,laddr=*,lport=* ]]
    rendered=$(sshd -T -C "${context}") || return 1
    validate_one_effective_sshd_policy "${rendered}"
  done
}

validate_relay_state() {
  local public_key_file=$1 permit_public_key_file=$2 source_cidr=$3
  local key_type key_body path mode
  validate_fault_account
  validate_relay_input "${public_key_file}" "${permit_public_key_file}" "${source_cidr}"
  key_type=${validated_key_type}
  key_body=${validated_key_body}
  [[ -x /usr/bin/sudo ]]
  validate_privileged_helper "${AUTHORIZED_COMMAND}"
  validate_zero_argument_helper "${ACTUATOR}"
  validate_zero_argument_helper "${PERMIT_AUTHORIZER}"
  for path in /etc/ssh /etc/ssh/sshd_config.d /etc/sudoers.d; do
    [[ -d ${path} && ! -L ${path} ]]
  done
  for path in "${AUTHORIZED_KEYS}:600" "${RELAY_PERMIT_PUBLIC_KEY}:600" \
    "${SSHD_DROP_IN}:600" "${SUDOERS}:440"; do
    mode=${path##*:}
    validate_root_file "${path%:*}" "${mode}"
  done
  compare_generated_file "${AUTHORIZED_KEYS}" render_authorized_keys \
    "${source_cidr}" "${key_type}" "${key_body}"
  validate_openssl_ed25519_public_key "${RELAY_PERMIT_PUBLIC_KEY}" 600
  cmp -s -- "${permit_public_key_file}" "${RELAY_PERMIT_PUBLIC_KEY}"
  compare_generated_file "${SSHD_DROP_IN}" render_sshd_drop_in
  compare_generated_file "${SUDOERS}" render_sudoers
  visudo -cf "${SUDOERS}" >/dev/null
  validate_effective_sudo_policy
  sshd -t
  validate_effective_sshd_policy "${source_cidr}"
}

validate_relay_baseline() {
  local candidate_source_cidr=$1
  local present=0 absent=0 path line prefix middle suffix rest source_cidr key_body
  local expected_authorized_line
  validate_source_cidr "${candidate_source_cidr}"
  validate_fault_account
  for path in "${AUTHORIZED_KEYS}" "${SSHD_DROP_IN}" "${SUDOERS}"; do
    if [[ -e ${path} || -L ${path} ]]; then
      ((present += 1))
    else
      ((absent += 1))
    fi
  done
  if [[ ${absent} -eq 3 ]]; then
    [[ ! -e ${RELAY_PERMIT_PUBLIC_KEY} && ! -L ${RELAY_PERMIT_PUBLIC_KEY} ]]
    sshd -t
    validate_effective_sshd_environment_contexts "${candidate_source_cidr}"
    return
  fi
  [[ ${present} -eq 3 && ${absent} -eq 0 ]]
  validate_root_file "${AUTHORIZED_KEYS}" 600
  validate_root_file "${SSHD_DROP_IN}" 600
  validate_root_file "${SUDOERS}" 440
  read_one_line_file "${AUTHORIZED_KEYS}" line || return 1
  prefix='restrict,from="'
  middle='",command="/usr/local/libexec/campus-link-relay-restart-authorized" ssh-ed25519 '
  suffix=' campus-link-relay-fault'
  rest=${line#"${prefix}"}
  [[ ${rest} != "${line}" ]]
  source_cidr=${rest%%"${middle}"*}
  [[ ${rest} != "${source_cidr}" ]]
  rest=${rest#"${source_cidr}${middle}"}
  key_body=${rest%"${suffix}"}
  [[ ${key_body} != "${rest}" && ${key_body} =~ ^[A-Za-z0-9+/]+={0,2}$ ]]
  validate_source_cidr "${source_cidr}"
  expected_authorized_line=$(render_authorized_keys \
    "${source_cidr}" ssh-ed25519 "${key_body}") || return 1
  [[ ${line} == "${expected_authorized_line}" ]]
  [[ -x ${AUTHORIZED_COMMAND} ]]
  [[ -x ${ACTUATOR} ]]
  validate_openssl_ed25519_public_key "${RELAY_PERMIT_PUBLIC_KEY}" 600
  validate_privileged_helper "${AUTHORIZED_COMMAND}"
  validate_zero_argument_helper "${ACTUATOR}"
  validate_zero_argument_helper "${PERMIT_AUTHORIZER}"
  compare_generated_file "${SSHD_DROP_IN}" render_sshd_drop_in
  compare_generated_file "${SUDOERS}" render_sudoers
  validate_effective_sudo_policy
  visudo -cf "${SUDOERS}" >/dev/null
  sshd -t
  validate_effective_sshd_policy "${source_cidr}"
  if [[ ${candidate_source_cidr} != "${source_cidr}" ]]; then
    validate_effective_sshd_policy "${candidate_source_cidr}"
  fi
}

reload_sshd() {
  if systemctl is-active --quiet ssh.service; then
    systemctl reload ssh.service
  elif systemctl is-active --quiet sshd.service; then
    systemctl reload sshd.service
  else
    echo 'No active SSH daemon is available for a configuration reload.' >&2
    return 1
  fi
}

provision_relay() {
  local public_key_file=$1 permit_public_key_file=$2 source_cidr=$3
  local key_type key_body source=
  require_transaction_snapshot relay
  validate_fault_account
  validate_relay_input "${public_key_file}" "${permit_public_key_file}" "${source_cidr}"
  key_type=${validated_key_type}
  key_body=${validated_key_body}
  validate_privileged_helper "${AUTHORIZED_COMMAND}"
  validate_zero_argument_helper "${ACTUATOR}"
  validate_zero_argument_helper "${PERMIT_AUTHORIZER}"
  [[ -x /usr/bin/sudo ]]
  [[ -d /etc/ssh && ! -L /etc/ssh ]]
  [[ -d /etc/ssh/sshd_config.d && ! -L /etc/ssh/sshd_config.d ]]
  [[ -d /etc/sudoers.d && ! -L /etc/sudoers.d ]]

  cleanup_relay_source() {
    rm -f -- "${source:-}"
  }
  trap cleanup_relay_source EXIT
  atomic_install "${permit_public_key_file}" "${RELAY_PERMIT_PUBLIC_KEY}" 0600

  source=$(mktemp /etc/ssh/.campus-link-relay-fault-authorized.XXXXXX) || return 1
  render_authorized_keys "${source_cidr}" "${key_type}" "${key_body}" > "${source}"
  atomic_install "${source}" "${AUTHORIZED_KEYS}" 0600
  rm -f -- "${source}"
  source=

  source=$(mktemp /etc/ssh/sshd_config.d/.campus-link-relay-fault.XXXXXX) || return 1
  render_sshd_drop_in > "${source}"
  atomic_install "${source}" "${SSHD_DROP_IN}" 0600
  rm -f -- "${source}"
  source=

  source=$(mktemp /etc/sudoers.d/.campus-link-relay-fault.XXXXXX) || return 1
  render_sudoers > "${source}"
  chmod 0440 "${source}"
  visudo -cf "${source}" >/dev/null
  atomic_install "${source}" "${SUDOERS}" 0440
  rm -f -- "${source}"
  source=

  validate_relay_state "${public_key_file}" "${permit_public_key_file}" "${source_cidr}"
  reload_sshd
  trap - EXIT
  printf 'STATUS=pass\nROLE=relay\nPASSWORD_AUTH=0\nFORWARDING=0\nGENERAL_SHELL=0\n'
}

case ${1:-} in
  validate-gate-input)
    [[ $# -eq 3 ]]
    validate_gate_input "$2" "$3"
    ;;
  validate-gate-state)
    [[ $# -eq 3 ]]
    validate_gate_tree "$2" "$3"
    ;;
  gate-host)
    [[ $# -eq 3 ]]
    provision_gate_host "$2" "$3"
    ;;
  bootstrap-relay-account)
    [[ $# -eq 1 ]]
    bootstrap_fault_account
    ;;
  validate-relay-account)
    [[ $# -eq 1 ]]
    validate_fault_account
    ;;
  validate-relay-input)
    [[ $# -eq 4 ]]
    validate_relay_input "$2" "$3" "$4"
    ;;
  validate-relay-baseline)
    [[ $# -eq 2 ]]
    validate_relay_baseline "$2"
    ;;
  relay-state|validate-relay-state)
    [[ $# -eq 4 ]]
    validate_relay_state "$2" "$3" "$4"
    ;;
  relay)
    [[ $# -eq 4 ]]
    provision_relay "$2" "$3" "$4"
    ;;
  *)
    echo 'usage: provision-relay-fault-access.sh validate-gate-input TARGET HOST_KEY | validate-gate-state TARGET HOST_KEY | gate-host TARGET HOST_KEY | bootstrap-relay-account | validate-relay-account | validate-relay-baseline SOURCE_CIDR | validate-relay-input SSH_PUBLIC_KEY PERMIT_PUBLIC_KEY SOURCE_CIDR | relay-state SSH_PUBLIC_KEY PERMIT_PUBLIC_KEY SOURCE_CIDR | relay SSH_PUBLIC_KEY PERMIT_PUBLIC_KEY SOURCE_CIDR' >&2
    exit 2
    ;;
esac
