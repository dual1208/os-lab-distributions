#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly STAGE_INPUT=${1:?usage: install-relay.sh STAGING_DIRECTORY FAULT_PUBLIC_KEY PERMIT_PUBLIC_KEY SOURCE_CIDR}
readonly FAULT_PUBLIC_KEY=${2:?usage: install-relay.sh STAGING_DIRECTORY FAULT_PUBLIC_KEY PERMIT_PUBLIC_KEY SOURCE_CIDR}
readonly PERMIT_PUBLIC_KEY=${3:?usage: install-relay.sh STAGING_DIRECTORY FAULT_PUBLIC_KEY PERMIT_PUBLIC_KEY SOURCE_CIDR}
readonly FAULT_SOURCE_CIDR=${4:?usage: install-relay.sh STAGING_DIRECTORY FAULT_PUBLIC_KEY PERMIT_PUBLIC_KEY SOURCE_CIDR}
readonly ROOT=/etc/campus-link
readonly ROLLBACK_ROOT=/var/lib/campus-link/rollback-relay
readonly SNAPSHOTS=${ROLLBACK_ROOT}/snapshots
readonly ACTIVE=${ROLLBACK_ROOT}/ACTIVE
readonly TRANSACTION_LOCK=/run/campus-link-install-relay.lock
readonly FAULT_RUNTIME_DIR=/run/campus-link-relay-fault
readonly ACTUATOR_LOCK=${FAULT_RUNTIME_DIR}/actuator.lock
readonly START_INHIBIT=${FAULT_RUNTIME_DIR}/inhibit-start
readonly RECOVERY_BASE=campus-link-relay-fault-recovery
readonly FAULT_STATE_DIR=/var/lib/campus-link-relay-fault
readonly USED_DIR=${FAULT_STATE_DIR}/used
readonly EXPECTED_PERMIT=${FAULT_STATE_DIR}/expected-run.env
readonly REVOKED_DIR=${FAULT_STATE_DIR}/revoked
readonly MAX_LEDGER_ENTRIES=4096
if [[ -n ${CAMPUS_LINK_TRANSACTION_ID:-} ]]; then
  transaction_id=${CAMPUS_LINK_TRANSACTION_ID}
else
  transaction_id=$(openssl rand -hex 16) || exit 1
fi
readonly transaction_id

[[ ${EUID} -eq 0 ]]
[[ ${transaction_id} =~ ^[a-f0-9]{32}$ ]]
[[ ${STAGE_INPUT} =~ ^/[A-Za-z0-9._/-]+$ && ${STAGE_INPUT} != / && -d ${STAGE_INPUT} && ! -L ${STAGE_INPUT} ]]
[[ ${FAULT_PUBLIC_KEY} =~ ^/[A-Za-z0-9._/-]+$ && ${FAULT_PUBLIC_KEY} != / ]]
[[ ${PERMIT_PUBLIC_KEY} =~ ^/[A-Za-z0-9._/-]+$ && ${PERMIT_PUBLIC_KEY} != / ]]
exec {stage_dir_fd}<"${STAGE_INPUT}"
readonly stage_dir_fd
# All later lookups stay anchored to the opened directory inode.  The trailing
# /. makes the procfs descriptor resolve as a directory rather than as a
# command-line symlink, while retaining the open-file-description binding.
readonly STAGE=/proc/$$/fd/${stage_dir_fd}/.
readonly -a stage_names=(
  campus-link-relay relay-control.crt relay-control.key control-ca.crt relay.json
  campus-link-relay.service install-relay.sh rollback-relay.sh provision-relay-identity.sh VERSION
  relay-restart-authorized.sh relay-restart-actuator.sh relay-restart-permit-authorize.sh
  provision-relay-fault-access.sh
  SOURCE_TREE.sha256 SOURCE_COMMIT MANIFEST.sha256
)

validate_stage_custody() {
  local stage=$1 name path tuple uid gid mode links permissions
  [[ -d ${stage} && ! -L ${stage} ]] || return 1
  tuple=$(stat -c '%u:%g:%a' -- "${stage}") || return 1
  [[ ${tuple} == 0:0:700 ]] || return 1
  for name in "${stage_names[@]}"; do
    path=${stage}/${name}
    [[ -f ${path} && ! -L ${path} && -s ${path} ]] || return 1
    tuple=$(stat -c '%u:%g:%a:%h' -- "${path}") || return 1
    IFS=: read -r uid gid mode links <<< "${tuple}" || return 1
    [[ ${uid} == 0 && ${gid} == 0 && ${links} == 1 && ${mode} =~ ^[0-7]{3,4}$ ]] || return 1
    permissions=$((8#${mode}))
    (( (permissions & 07022) == 0 )) || return 1
  done
}

read_complete_nul_inventory() {
  local input=$1 output_name=$2 input_size consumed=0 item
  local LC_ALL=C
  local -n output=${output_name}
  output=()
  input_size=$(stat -c '%s' -- "${input}") || return 1
  (( input_size > 0 )) || return 1
  while IFS= read -r -d '' item; do
    output+=("${item}")
    consumed=$((consumed + ${#item} + 1))
  done < "${input}"
  (( consumed == input_size && ${#output[@]} > 0 ))
}

read_complete_line_inventory() {
  local input=$1 output_name=$2 input_size consumed=0 item
  local LC_ALL=C
  local -n output=${output_name}
  output=()
  input_size=$(stat -c '%s' -- "${input}") || return 1
  (( input_size > 0 )) || return 1
  while IFS= read -r item; do
    output+=("${item}")
    consumed=$((consumed + ${#item} + 1))
  done < "${input}"
  (( consumed == input_size && ${#output[@]} > 0 ))
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

validate_stage_inventory() {
  local stage=$1 inventory name expected found
  local -a actual_names=()
  inventory=$(mktemp) || return 1
  if ! find "${stage}" -mindepth 1 -maxdepth 1 -printf '%f\0' > "${inventory}"; then
    rm -f -- "${inventory}"
    return 1
  fi
  if ! read_complete_nul_inventory "${inventory}" actual_names; then
    rm -f -- "${inventory}"
    return 1
  fi
  rm -f -- "${inventory}" || return 1
  (( ${#actual_names[@]} == ${#stage_names[@]} )) || return 1
  for name in "${actual_names[@]}"; do
    found=0
    for expected in "${stage_names[@]}"; do
      [[ ${name} == "${expected}" ]] && found=$((found + 1))
    done
    (( found == 1 )) || return 1
  done
}

validate_manifest_inventory() {
  local manifest=$1 output_name=$2 size line logical previous=
  local pattern='^[a-f0-9]{64}  [A-Za-z0-9._/-]+$'
  local LC_ALL=C
  local -n output=${output_name}
  size=$(stat -c '%s' -- "${manifest}") || return 1
  [[ ${size} =~ ^[0-9]+$ ]] && (( size <= 65536 )) || return 1
  read_complete_line_inventory "${manifest}" "${output_name}" || return 1
  for line in "${output[@]}"; do
    [[ ${line} =~ ${pattern} ]] || return 1
    logical=${line#*  }
    [[ -z ${previous} || ${previous} < ${logical} ]] || return 1
    previous=${logical}
  done
}

assert_no_extended_regex_match() {
  local pattern=$1 input=$2 status=0
  grep -Eq "${pattern}" "${input}" || status=$?
  (( status == 1 ))
}

validate_stage_custody "${STAGE}"
validate_stage_inventory "${STAGE}"
for name in "${stage_names[@]}"; do
  [[ -f ${STAGE}/${name} && ! -L ${STAGE}/${name} && -s ${STAGE}/${name} ]]
done
assert_no_extended_regex_match '"data_|/data"' "${STAGE}/relay.json"
pki_reference_count=$(grep -oF "${ROOT}/pki/" "${STAGE}/relay.json" | wc -l) || exit 1
[[ ${pki_reference_count} -eq 3 ]]

declare -a manifest_lines=()
validate_manifest_inventory "${STAGE}/MANIFEST.sha256" manifest_lines
readonly -a manifest_lines
stage_manifest_sha256=$(sha256sum -- "${STAGE}/MANIFEST.sha256" | awk '{print $1}') || exit 1
[[ ${stage_manifest_sha256} =~ ^[a-f0-9]{64}$ ]]
readonly stage_manifest_sha256

verify_manifest_entry() {
  local logical_name=$1 staged_file=$2 candidate line expected actual
  local -a matches=()
  for candidate in "${manifest_lines[@]}"; do
    [[ ${candidate#*  } == "${logical_name}" ]] && matches+=("${candidate}")
  done
  [[ ${#matches[@]} -eq 1 ]]
  line=${matches[0]}
  [[ ${line#*  } == "${logical_name}" ]]
  expected=${line%% *}
  actual=$(sha256sum "${STAGE}/${staged_file}" | awk '{print $1}') || return 1
  [[ ${actual} == "${expected}" ]]
}

verify_stage_manifest_bindings() {
  verify_manifest_entry bin/campus-link-relay campus-link-relay &&
    verify_manifest_entry config/relay.json relay.json &&
    verify_manifest_entry scripts/install-relay.sh install-relay.sh &&
    verify_manifest_entry scripts/rollback-relay.sh rollback-relay.sh &&
    verify_manifest_entry scripts/provision-relay-identity.sh provision-relay-identity.sh &&
    verify_manifest_entry scripts/provision-relay-fault-access.sh provision-relay-fault-access.sh &&
    verify_manifest_entry scripts/relay-restart-actuator.sh relay-restart-actuator.sh &&
    verify_manifest_entry scripts/relay-restart-authorized.sh relay-restart-authorized.sh &&
    verify_manifest_entry scripts/relay-restart-permit-authorize.sh relay-restart-permit-authorize.sh &&
    verify_manifest_entry systemd/campus-link-relay.service campus-link-relay.service &&
    verify_manifest_entry relay-pki/control-ca.crt control-ca.crt &&
    verify_manifest_entry relay-pki/relay-control.crt relay-control.crt &&
    verify_manifest_entry relay-pki/relay-control.key relay-control.key &&
    verify_manifest_entry VERSION VERSION &&
    verify_manifest_entry SOURCE_TREE.sha256 SOURCE_TREE.sha256 &&
    verify_manifest_entry SOURCE_COMMIT SOURCE_COMMIT
}

verify_stage_manifest_bindings
version=$(<"${STAGE}/VERSION") || exit 1
source_commit=$(<"${STAGE}/SOURCE_COMMIT") || exit 1
[[ ${source_commit} =~ ^[a-f0-9]{40}$ ]]
read -r source_tree_digest source_tree_name < "${STAGE}/SOURCE_TREE.sha256" || exit 1
[[ ${source_tree_digest} =~ ^[a-f0-9]{64}$ && ${source_tree_name} == source-tree ]]
source_tree_line_count=$(wc -l < "${STAGE}/SOURCE_TREE.sha256") || exit 1
[[ ${source_tree_line_count} =~ ^[0-9]+$ && ${source_tree_line_count} -eq 1 ]]
[[ ${version} == "phase1-${source_commit:0:12}-${source_tree_digest:0:12}" ]]

cert_public=$(openssl x509 -in "${STAGE}/relay-control.crt" -pubkey -noout |
  openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256) || exit 1
key_public=$(openssl pkey -in "${STAGE}/relay-control.key" -pubout -outform DER 2>/dev/null |
  openssl dgst -sha256) || exit 1
[[ ${cert_public} == "${key_public}" ]]

revalidate_stage_candidate() {
  local current_manifest_sha256
  validate_stage_custody "${STAGE}" || return 1
  validate_stage_inventory "${STAGE}" || return 1
  current_manifest_sha256=$(sha256sum -- "${STAGE}/MANIFEST.sha256" | awk '{print $1}') || return 1
  [[ ${current_manifest_sha256} == "${stage_manifest_sha256}" ]] || return 1
  verify_stage_manifest_bindings
}

assert_relay_pki_allowlist() {
  local require_complete=$1 entry inventory
  local -a entries=()
  if [[ ! -e ${ROOT}/pki && ! -L ${ROOT}/pki ]]; then
    [[ ${require_complete} -eq 0 ]] || return 1
    return 0
  fi
  [[ -d ${ROOT}/pki && ! -L ${ROOT}/pki ]] || return 1
  inventory=$(mktemp) || return 1
  if ! find "${ROOT}/pki" -mindepth 1 -maxdepth 1 -printf '%f\n' |
    LC_ALL=C sort > "${inventory}"; then
    rm -f -- "${inventory}" || :
    return 1
  fi
  if [[ -s ${inventory} ]] && ! read_complete_line_inventory "${inventory}" entries; then
    rm -f -- "${inventory}" || :
    return 1
  fi
  rm -f -- "${inventory}" || return 1
  for entry in "${entries[@]}"; do
    case ${entry} in
      control-ca.crt|relay-control.crt|relay-control.key) ;;
      *) return 1 ;;
    esac
    [[ -f ${ROOT}/pki/${entry} && ! -L ${ROOT}/pki/${entry} ]] || return 1
  done
  if [[ ${require_complete} -eq 1 ]]; then
    [[ ${entries[*]} == 'control-ca.crt relay-control.crt relay-control.key' ]] || \
      return 1
  fi
  return 0
}

assert_no_pending_recovery() {
  local suffix load_state
  for suffix in timer service; do
    load_state=$(systemctl show -p LoadState --value \
      "${RECOVERY_BASE}.${suffix}") || return 1
    [[ ${load_state} == not-found ]] || return 1
  done
}
[[ ! -L ${TRANSACTION_LOCK} ]]
exec 9<>"${TRANSACTION_LOCK}"
flock -n 9 || {
  echo 'Another campus-link relay installation is active.' >&2
  exit 5
}
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
flock -w 30 7 || {
  echo 'Timed out waiting for the relay-fault actuator lock.' >&2
  exit 5
}
chown root:root "${ACTUATOR_LOCK}"
chmod 0600 "${ACTUATOR_LOCK}"
actuator_lock_tuple=$(stat -c '%u:%g:%a:%h' -- "${ACTUATOR_LOCK}") || exit 1
[[ ${actuator_lock_tuple} == 0:0:600:1 ]]
[[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]] || {
  echo 'A relay-fault start inhibit remains active; refusing deployment.' >&2
  exit 5
}
assert_no_pending_recovery || {
  echo 'A relay-fault recovery unit remains loaded; refusing deployment.' >&2
  exit 5
}

assert_relay_pki_allowlist 0 || {
  echo 'Relay PKI directory is outside its exact entry allowlist.' >&2
  exit 4
}

# Account provisioning is a separate, one-time prerequisite. Creating the
# identity here would be an uncaptured mutation before the candidate preflight.
getent group campus-link >/dev/null
relay_passwd_record=$(getent passwd campus-link) || exit 1
[[ ${relay_passwd_record} != *$'\n'* ]]
IFS=: read -r relay_name _ relay_uid relay_gid _ relay_home relay_shell \
  <<< "${relay_passwd_record}" || exit 1
[[ ${relay_name} == campus-link && ${relay_uid} =~ ^[0-9]+$ && ${relay_uid} != 0 ]]
[[ ${relay_home} == /nonexistent ]]
[[ ${relay_shell} == /usr/sbin/nologin || ${relay_shell} == /sbin/nologin ]]
relay_primary_group=$(id -gn campus-link) || exit 1
relay_primary_gid=$(id -g campus-link) || exit 1
relay_groups=$(id -G campus-link) || exit 1
[[ ${relay_primary_group} == campus-link && ${relay_primary_gid} == "${relay_gid}" ]]
[[ ${relay_groups} == "${relay_gid}" ]]
command -v sshd >/dev/null
command -v visudo >/dev/null
[[ -x /usr/bin/sudo ]]
/bin/bash "${STAGE}/provision-relay-fault-access.sh" validate-relay-account
/bin/bash "${STAGE}/provision-relay-fault-access.sh" \
  validate-relay-baseline "${FAULT_SOURCE_CIDR}"
/bin/bash "${STAGE}/provision-relay-fault-access.sh" \
  validate-relay-input "${FAULT_PUBLIC_KEY}" "${PERMIT_PUBLIC_KEY}" "${FAULT_SOURCE_CIDR}"

preflight=$(mktemp -d /run/campus-link-relay-preflight.XXXXXX) || exit 1
chown root:campus-link "${preflight}"
chmod 0750 "${preflight}"
cleanup() {
  if ! rm -rf -- "${preflight}"; then
    echo "Warning: could not remove relay preflight directory ${preflight}." >&2
    return 1
  fi
}
cleanup_on_exit() {
  local status=$? cleanup_failed=0
  trap - EXIT
  if ! cleanup; then
    cleanup_failed=1
  fi
  if [[ ${status} -eq 0 && ${cleanup_failed} -eq 1 ]]; then
    exit 6
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT
install -m 0755 "${STAGE}/campus-link-relay" "${preflight}/campus-link-relay"
install -m 0644 -o root -g campus-link "${STAGE}/relay-control.crt" "${preflight}/relay-control.crt"
install -m 0640 -o root -g campus-link "${STAGE}/relay-control.key" "${preflight}/relay-control.key"
install -m 0644 -o root -g campus-link "${STAGE}/control-ca.crt" "${preflight}/control-ca.crt"
sed "s#${ROOT}/pki/#${preflight}/#g" "${STAGE}/relay.json" > "${preflight}/relay.json"
chown root:campus-link "${preflight}/relay.json"
chmod 0640 "${preflight}/relay.json"
runuser -u campus-link -- "${preflight}/campus-link-relay" -check-config -config "${preflight}/relay.json"

atomic_install() {
  local source=$1 destination=$2 mode=$3 owner=$4 group=$5 parent tmp destination_name
  parent=$(dirname "${destination}") || return 1
  if [[ -e ${parent} || -L ${parent} ]]; then
    [[ -d ${parent} && ! -L ${parent} ]]
  else
    install -d -m 0755 "${parent}"
  fi
  destination_name=$(basename "${destination}") || return 1
  tmp=$(mktemp "${parent}/.${destination_name}.XXXXXX") || return 1
  install -m "${mode}" -o "${owner}" -g "${group}" "${source}" "${tmp}"
  mv -fT -- "${tmp}" "${destination}"
}

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

snapshot_path() {
  local snapshot=$1 path=$2 relative=${path#/}
  local relative_parent
  if [[ -e ${path} || -L ${path} ]]; then
    [[ ! -L ${path} ]]
    relative_parent=$(dirname "${relative}") || return 1
    install -d -m 0700 "${snapshot}/rootfs/${relative_parent}"
    cp -a -- "${path}" "${snapshot}/rootfs/${relative}"
    printf 'present %s\n' "${relative}" >> "${snapshot}/manifest"
  else
    printf 'absent %s\n' "${relative}" >> "${snapshot}/manifest"
  fi
}

snapshot_active=0
record_relay_unit_state() {
  local snapshot=$1 active_state enabled_state enabled_status=0
  active_state=$(systemctl show --property=ActiveState --value \
    campus-link-relay.service) || return 1
  case ${active_state} in
    active) touch "${snapshot}/active.campus-link-relay.service" || return 1 ;;
    inactive|failed|not-found) ;;
    *) return 1 ;;
  esac
  enabled_state=$(systemctl is-enabled campus-link-relay.service 2>/dev/null) || \
    enabled_status=$?
  if (( enabled_status == 0 )); then
    [[ -n ${enabled_state} ]] || return 1
    touch "${snapshot}/enabled.campus-link-relay.service" || return 1
  else
    (( enabled_status == 1 )) || return 1
    case ${enabled_state} in
      disabled|static|indirect|generated|transient|masked|masked-runtime|not-found) ;;
      *) return 1 ;;
    esac
  fi
}

activate_snapshot() {
  local snapshot_tmp old_active active_tmp
  install -d -m 0700 "${ROLLBACK_ROOT}" "${SNAPSHOTS}"
  [[ ! -e ${SNAPSHOTS}/${transaction_id} ]]
  snapshot_tmp=$(mktemp -d "${SNAPSHOTS}/.${transaction_id}.XXXXXX") || return 1
  install -d -m 0700 "${snapshot_tmp}/rootfs"
  : > "${snapshot_tmp}/manifest"
  chmod 0600 "${snapshot_tmp}/manifest"
  for path in "${snapshot_paths[@]}"; do
    snapshot_path "${snapshot_tmp}" "${path}"
  done
  record_relay_unit_state "${snapshot_tmp}"
  printf '%s\n' "${transaction_id}" > "${snapshot_tmp}/.complete"
  chmod 0600 "${snapshot_tmp}/.complete"
  mv -T -- "${snapshot_tmp}" "${SNAPSHOTS}/${transaction_id}"
  old_active=
  if [[ -e ${ACTIVE} || -L ${ACTIVE} ]]; then
    [[ -f ${ACTIVE} && ! -L ${ACTIVE} ]] || return 1
    old_active=$(cat -- "${ACTIVE}") || return 1
    [[ ${old_active} =~ ^[a-f0-9]{32}$ ]] || return 1
  fi
  active_tmp=$(mktemp "${ROLLBACK_ROOT}/.ACTIVE.XXXXXX") || return 1
  printf '%s\n' "${transaction_id}" > "${active_tmp}"
  chmod 0600 "${active_tmp}"
  mv -fT -- "${active_tmp}" "${ACTIVE}"
  snapshot_active=1
  if [[ ${old_active} =~ ^[a-f0-9]{32}$ && ${old_active} != "${transaction_id}" ]]; then
    rm -rf -- "${SNAPSHOTS}/${old_active}"
  fi
}

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

revalidate_stage_candidate
quarantine_pending_permit
activate_snapshot
rollback_on_error() {
  local status=$?
  trap - ERR EXIT
  if [[ ${snapshot_active} -eq 1 ]]; then
    if ! CAMPUS_LINK_INHERITED_RELAY_MUTATION_LOCKS=1 \
      /bin/bash "${STAGE}/rollback-relay.sh" "${transaction_id}"; then
      echo "Warning: relay rollback failed for transaction ${transaction_id}; preserving original exit status ${status}." >&2
    fi
  fi
  if ! cleanup; then
    : # cleanup emitted a bounded warning; preserve the original failure below
  fi
  exit "${status}"
}
trap rollback_on_error ERR

relay_active_state=$(systemctl show --property=ActiveState --value \
  campus-link-relay.service) || exit 1
case ${relay_active_state} in
  active) systemctl stop campus-link-relay.service ;;
  inactive|failed|not-found) ;;
  *) exit 1 ;;
esac
tcp_listeners=$(ss -H -ltn '( sport = :443 )') || exit 1
udp_listeners=$(ss -H -lun '( sport = :443 )') || exit 1
if [[ -n ${tcp_listeners} || -n ${udp_listeners} ]]; then
  echo 'TCP or UDP port 443 is owned by another service; refusing installation.' >&2
  exit 3
fi

revalidate_stage_candidate
install -d -m 0755 /usr/local/libexec
install -d -m 0750 -o root -g campus-link "${ROOT}/pki"
atomic_install "${STAGE}/control-ca.crt" "${ROOT}/pki/control-ca.crt" 0644 root campus-link
atomic_install "${STAGE}/relay-control.crt" "${ROOT}/pki/relay-control.crt" 0644 root campus-link
atomic_install "${STAGE}/relay-control.key" "${ROOT}/pki/relay-control.key" 0640 root campus-link
assert_relay_pki_allowlist 1
pki_tuple=$(stat -c '%U:%G:%a' "${ROOT}/pki") || exit 1
control_ca_tuple=$(stat -c '%U:%G:%a' "${ROOT}/pki/control-ca.crt") || exit 1
relay_cert_tuple=$(stat -c '%U:%G:%a' "${ROOT}/pki/relay-control.crt") || exit 1
relay_key_tuple=$(stat -c '%U:%G:%a' "${ROOT}/pki/relay-control.key") || exit 1
[[ ${pki_tuple} == root:campus-link:750 ]]
[[ ${control_ca_tuple} == root:campus-link:644 ]]
[[ ${relay_cert_tuple} == root:campus-link:644 ]]
[[ ${relay_key_tuple} == root:campus-link:640 ]]
install -m 0640 -o root -g campus-link "${STAGE}/relay.json" "${preflight}/final-relay.json"
runuser -u campus-link -- "${preflight}/campus-link-relay" -check-config -config "${preflight}/final-relay.json"
atomic_install "${STAGE}/campus-link-relay" /usr/local/bin/campus-link-relay 0755 root root
atomic_install "${STAGE}/rollback-relay.sh" /usr/local/libexec/campus-link-rollback-relay 0755 root root
atomic_install "${STAGE}/provision-relay-fault-access.sh" /usr/local/libexec/campus-link-provision-relay-fault-access 0755 root root
atomic_install "${STAGE}/relay-restart-actuator.sh" /usr/local/libexec/campus-link-relay-restart-actuator 0755 root root
atomic_install "${STAGE}/relay-restart-authorized.sh" /usr/local/libexec/campus-link-relay-restart-authorized 0755 root root
atomic_install "${STAGE}/relay-restart-permit-authorize.sh" /usr/local/libexec/campus-link-relay-restart-permit-authorize 0755 root root
fault_authority_permit=${SNAPSHOTS}/${transaction_id}/.fault-authority-open
[[ ! -e ${fault_authority_permit} && ! -L ${fault_authority_permit} ]]
printf '%s\n' "${transaction_id}" > "${fault_authority_permit}"
chmod 0600 "${fault_authority_permit}"
CAMPUS_LINK_TRANSACTION_ID=${transaction_id} \
  /bin/bash /usr/local/libexec/campus-link-provision-relay-fault-access \
    relay "${FAULT_PUBLIC_KEY}" "${PERMIT_PUBLIC_KEY}" "${FAULT_SOURCE_CIDR}"
rm -f -- "${fault_authority_permit}"
/bin/bash /usr/local/libexec/campus-link-provision-relay-fault-access \
  validate-relay-state "${FAULT_PUBLIC_KEY}" "${PERMIT_PUBLIC_KEY}" "${FAULT_SOURCE_CIDR}"
atomic_install "${STAGE}/relay.json" "${ROOT}/relay.json" 0640 root campus-link
atomic_install "${STAGE}/campus-link-relay.service" /etc/systemd/system/campus-link-relay.service 0644 root root
runuser -u campus-link -- /usr/local/bin/campus-link-relay -check-config -config "${ROOT}/relay.json"
systemctl daemon-reload
systemctl enable --now campus-link-relay.service
systemctl is-active --quiet campus-link-relay.service
install -d -m 0700 /var/lib/campus-link
version_tmp=$(mktemp /var/lib/campus-link/.installed-relay-version.XXXXXX) || exit 1
install -m 0600 "${STAGE}/VERSION" "${version_tmp}"
mv -fT -- "${version_tmp}" /var/lib/campus-link/installed-relay-version
manifest_digest=$(sha256sum "${STAGE}/MANIFEST.sha256" | awk '{print $1}') || exit 1
[[ ${manifest_digest} =~ ^[a-f0-9]{64}$ ]]
cat > "${preflight}/deployment-attestation.env" <<EOF
VERSION=${version}
SOURCE_TREE_SHA256=${source_tree_digest}
MANIFEST_SHA256=${manifest_digest}
EOF
chmod 0600 "${preflight}/deployment-attestation.env"
atomic_install "${STAGE}/MANIFEST.sha256" /var/lib/campus-link/installed-release-manifest.sha256 0600 root root
atomic_install "${preflight}/deployment-attestation.env" /var/lib/campus-link/deployment-attestation.env 0600 root root
trap - ERR
trap cleanup_on_exit EXIT
