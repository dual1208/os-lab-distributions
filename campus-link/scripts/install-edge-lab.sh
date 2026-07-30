#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly RELAY_ADDRESS=${2:?usage: install-edge-lab.sh REPO_ROOT RELAY_HOST_OR_IP RELAY_HOST_ED25519_PUBLIC_KEY}
readonly RELAY_HOST_PUBLIC_KEY=${3:?usage: install-edge-lab.sh REPO_ROOT RELAY_HOST_OR_IP RELAY_HOST_ED25519_PUBLIC_KEY}
readonly ROOT=/etc/campus-link
readonly BUILD=/srv/openwrt-lab/build/campus-link
readonly ROLLBACK_ROOT=/var/lib/campus-link/rollback-edge
readonly SNAPSHOTS=${ROLLBACK_ROOT}/snapshots
readonly ACTIVE=${ROLLBACK_ROOT}/ACTIVE
readonly CIRCUIT_URI=spiffe://campus-link/home-pair-1
readonly AUTH_HELPER=${REPO_ROOT}/campus-link/scripts/pki-public-authorizations.sh
if [[ -n ${CAMPUS_LINK_TRANSACTION_ID:-} ]]; then
  transaction_id=${CAMPUS_LINK_TRANSACTION_ID}
else
  transaction_id=$(openssl rand -hex 16) || exit 1
fi
readonly transaction_id

[[ ${EUID} -eq 0 ]]
[[ ${CAMPUS_LINK_LAB_ONLY:-} == 1 ]] || {
  echo 'Refusing all-in-one edge-lab installation without CAMPUS_LINK_LAB_ONLY=1.' >&2
  exit 2
}
[[ ${transaction_id} =~ ^[a-f0-9]{32}$ ]]
[[ -f ${AUTH_HELPER} && ! -L ${AUTH_HELPER} ]]
command -v runuser >/dev/null

valid_relay_address() {
  local value=$1 part
  local -a parts=()
  [[ ${#value} -ge 1 && ${#value} -le 253 ]] || return 1
  [[ ${value} != .* && ${value} != *. && ${value} != *..* ]] || return 1
  IFS=. read -r -a parts <<< "${value}"
  if [[ ${value} =~ ^[0-9.]+$ ]]; then
    [[ ${#parts[@]} -eq 4 ]] || return 1
    for part in "${parts[@]}"; do
      [[ ${part} =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
      ((10#${part} <= 255)) || return 1
    done
    return 0
  fi
  for part in "${parts[@]}"; do
    [[ ${#part} -ge 1 && ${#part} -le 63 ]] || return 1
    [[ ${part} =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || return 1
  done
}
valid_relay_address "${RELAY_ADDRESS}"

command_output_matches() {
  local pattern=$1 output
  shift
  output=$("$@") || return 1
  grep -- "${pattern}" <<< "${output}" >/dev/null
}

checked_stat_equals() {
  local expected=$1 actual
  shift
  actual=$(stat "$@") || return 1
  [[ ${actual} == "${expected}" ]]
}

checked_line_count() {
  local destination=$1 path=$2 output parsed_count extra
  output=$(wc -l < "${path}") || return 1
  [[ ${output} != *$'\n'* ]] || return 1
  read -r parsed_count extra <<< "${output}" || return 1
  [[ -z ${extra:-} && ${parsed_count} =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  printf -v "${destination}" '%s' "${parsed_count}"
}

checked_line_count_equals() {
  local expected=$1 path=$2 count
  checked_line_count count "${path}" || return 1
  [[ ${count} == "${expected}" ]]
}

checked_sha256() {
  local destination=$1 path=$2 output parsed_digest
  output=$(sha256sum -- "${path}") || return 1
  [[ ${output} != *$'\n'* ]] || return 1
  parsed_digest=${output%% *}
  [[ ${parsed_digest} =~ ^[a-f0-9]{64}$ && ${output} == "${parsed_digest}  "* ]] || return 1
  printf -v "${destination}" '%s' "${parsed_digest}"
}

file_lacks_pattern() {
  local mode=$1 pattern=$2 path=$3 status
  [[ ${mode} == E || ${mode} == F || ${mode} == Ev ]] || return 1
  if grep "-${mode}" -- "${pattern}" "${path}" >/dev/null; then
    return 1
  else
    status=$?
  fi
  [[ ${status} -eq 1 ]]
}

assert_unit_not_active() {
  local unit=$1 status
  if systemctl is-active --quiet "${unit}"; then
    return 1
  else
    status=$?
  fi
  [[ ${status} -eq 3 || ${status} -eq 4 ]]
}

# This candidate migration intentionally does not provision or alter the lab
# endpoint/firewall baseline because that state is outside its rollback tuple.
[[ -f /var/lib/campus-link/a11-b22-firewall.complete &&
  ! -L /var/lib/campus-link/a11-b22-firewall.complete ]]
command_output_matches '10.81.0.11/24' ip -n oslab-a address show dev ep-a
command_output_matches '10.82.0.22/24' ip -n oslab-b address show dev ep-b
for gate_unit in \
  campus-link-full-qualification.service \
  campus-link-accelerated-fault.service \
  campus-link-fault-in-stream.service \
  campus-link-nat-rebinding.service \
  campus-link-24h-soak.service \
  campus-link-7d-burn-in.service \
  campus-link-qualification-chain.service; do
  assert_unit_not_active "${gate_unit}"
done

exec 9>/run/campus-link-install-edge.lock
flock -n 9 || {
  echo 'Another campus-link edge installation is active.' >&2
  exit 5
}

assert_service_identity() {
  local name=$1 passwd_name passwd_home passwd_shell passwd_record
  local primary_group primary_gid all_groups
  getent group "${name}" >/dev/null || return 1
  passwd_record=$(getent passwd "${name}") || return 1
  [[ ${passwd_record} != *$'\n'* ]] || return 1
  IFS=: read -r passwd_name _ _ _ _ passwd_home passwd_shell \
    <<< "${passwd_record}" || return 1
  [[ ${passwd_name} == "${name}" && ${passwd_home} == /nonexistent ]] || return 1
  [[ ${passwd_shell} == /usr/sbin/nologin || ${passwd_shell} == /sbin/nologin ]] || \
    return 1
  primary_group=$(id -gn "${name}") || return 1
  primary_gid=$(id -g "${name}") || return 1
  all_groups=$(id -G "${name}") || return 1
  [[ ${primary_group} == "${name}" && ${all_groups} == "${primary_gid}" ]] || \
    return 1
  return 0
}

assert_identity_lacks_group() {
  local name=$1 forbidden_gid=$2 group_listing group
  local -a groups=()
  [[ ${forbidden_gid} =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  group_listing=$(id -G "${name}") || return 1
  [[ -n ${group_listing} && ${group_listing} != *$'\n'* ]] || return 1
  read -r -a groups <<< "${group_listing}" || return 1
  [[ ${#groups[@]} -gt 0 ]] || return 1
  for group in "${groups[@]}"; do
    [[ ${group} =~ ^(0|[1-9][0-9]*)$ && ${group} != "${forbidden_gid}" ]] || \
      return 1
  done
}

assert_service_identity campus-link-a
assert_service_identity campus-link-b
site_a_uid=$(id -u campus-link-a) || exit 1
site_b_uid=$(id -u campus-link-b) || exit 1
site_a_gid=$(id -g campus-link-a) || exit 1
site_b_gid=$(id -g campus-link-b) || exit 1
[[ ${site_a_uid} != "${site_b_uid}" && ${site_a_gid} != "${site_b_gid}" ]]
assert_identity_lacks_group campus-link-a "${site_b_gid}"
assert_identity_lacks_group campus-link-b "${site_a_gid}"

candidate_dir=$(mktemp -d /run/campus-link-edge-candidate.XXXXXX) || exit 1
release_tmp=
snapshot_active=0
cleanup() {
  local failed=0
  if ! rm -rf -- "${candidate_dir}"; then
    echo "Warning: could not remove edge candidate directory ${candidate_dir}." >&2
    failed=1
  fi
  if [[ -n ${release_tmp} ]]; then
    if ! rm -rf -- "${release_tmp}"; then
      echo "Warning: could not remove temporary release directory ${release_tmp}." >&2
      failed=1
    fi
  fi
  return "${failed}"
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
rollback_on_error() {
  local status=$?
  trap - ERR EXIT
  if [[ ${snapshot_active} -eq 1 ]]; then
    if ! /bin/bash "${REPO_ROOT}/campus-link/scripts/rollback-edge.sh" "${transaction_id}"; then
      echo "Warning: edge rollback failed for transaction ${transaction_id}; preserving original exit status ${status}." >&2
    fi
  fi
  if ! cleanup; then
    : # cleanup emitted a bounded warning; preserve the original failure below
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT

read_authorization() {
  local key=$1 file=$2 line
  local -a lines=() matches=()
  [[ ${key} =~ ^[A-Z][A-Z0-9_]*$ ]] || return 1
  mapfile -t lines < "${file}" || return 1
  for line in "${lines[@]}"; do
    if [[ ${line} == "${key}="* ]]; then
      matches+=("${line}")
    fi
  done
  [[ ${#matches[@]} -eq 1 ]] || return 1
  line=${matches[0]}
  [[ ${line%%=*} == "${key}" ]] || return 1
  printf '%s' "${line#*=}"
}

render_edge_configs() {
  local output_dir=$1 credential_root=$2
  umask 077
  cat > "${output_dir}/edge-a.json" <<EOF
{"site":"site-a","role":"client","generation":"${generation_a}","circuit":"home-pair-1","deployment_id":"${transaction_id}","prefix":"10.81.0.0/24","remote_prefix":"10.82.0.0/24","relay_address":"${RELAY_ADDRESS}:443","control_server_name":"gz.campus-link","control_cert":"${credential_root}/site-a/site-a-control.crt","control_key":"${credential_root}/site-a/site-a-control.key","control_ca":"${credential_root}/site-a/control-ca.crt","local_control_identity":{"uri":"${site_a_control_uri}","current_spki":"${site_a_control_pin}"},"control_identity":{"uri":"${relay_control_uri}","current_spki":"${relay_control_pin}"},"data_server_name":"site-b.campus-link","data_cert":"${credential_root}/site-a/site-a-data.crt","data_key":"${credential_root}/site-a/site-a-data.key","data_ca":"${credential_root}/site-a/data-ca.crt","local_data_identity":{"uri":"${site_a_data_uri}","current_spki":"${site_a_data_pin}"},"data_identity":{"uri":"${site_b_data_uri}","current_spki":"${site_b_data_pin}"},"tun_name":"cl0","mtu":1200,"status_path":"/run/campus-link/site-a/status.json"}
EOF
  cat > "${output_dir}/edge-b.json" <<EOF
{"site":"site-b","role":"server","generation":"${generation_b}","circuit":"home-pair-1","deployment_id":"${transaction_id}","prefix":"10.82.0.0/24","remote_prefix":"10.81.0.0/24","relay_address":"${RELAY_ADDRESS}:443","control_server_name":"gz.campus-link","control_cert":"${credential_root}/site-b/site-b-control.crt","control_key":"${credential_root}/site-b/site-b-control.key","control_ca":"${credential_root}/site-b/control-ca.crt","local_control_identity":{"uri":"${site_b_control_uri}","current_spki":"${site_b_control_pin}"},"control_identity":{"uri":"${relay_control_uri}","current_spki":"${relay_control_pin}"},"data_server_name":"site-b.campus-link","data_cert":"${credential_root}/site-b/site-b-data.crt","data_key":"${credential_root}/site-b/site-b-data.key","data_ca":"${credential_root}/site-b/data-ca.crt","local_data_identity":{"uri":"${site_b_data_uri}","current_spki":"${site_b_data_pin}"},"data_identity":{"uri":"${site_a_data_uri}","current_spki":"${site_a_data_pin}"},"tun_name":"cl0","mtu":1200,"status_path":"/run/campus-link/site-b/status.json"}
EOF
  chmod 0600 "${output_dir}/edge-a.json" "${output_dir}/edge-b.json"
}

stage_edge_credentials() {
  local source=$1 destination=$2 site file
  install -d -m 0700 "${destination}" "${destination}/site-a" "${destination}/site-b"
  for site in site-a site-b; do
    for file in control-ca.crt data-ca.crt "${site}-control.crt" "${site}-control.key" \
      "${site}-data.crt" "${site}-data.key"; do
      install -m 0600 "${source}/${file}" "${destination}/${site}/${file}"
    done
  done
}

atomic_install_owned() {
  local source=$1 destination=$2 mode=$3 owner=$4 group=$5 parent destination_name tmp
  parent=$(dirname "${destination}") || return 1
  destination_name=$(basename "${destination}") || return 1
  [[ -d ${parent} && ! -L ${parent} ]]
  tmp=$(mktemp "${parent}/.${destination_name}.XXXXXX") || return 1
  install -m "${mode}" -o "${owner}" -g "${group}" "${source}" "${tmp}"
  mv -fT -- "${tmp}" "${destination}"
}

install_edge_credentials() {
  local source=$1 destination=$2 site file
  install -d -m 0750 -o root -g campus-link-a "${destination}/site-a"
  install -d -m 0750 -o root -g campus-link-b "${destination}/site-b"
  for site in site-a site-b; do
    for file in control-ca.crt data-ca.crt "${site}-control.crt" "${site}-control.key" \
      "${site}-data.crt" "${site}-data.key"; do
      atomic_install_owned "${source}/${site}/${file}" "${destination}/${site}/${file}" \
        0640 root "campus-link-${site#site-}"
    done
  done
}

assert_edge_tree() {
  local site=$1 root=$2 allow_absent=$3 group actual expected entry
  group="campus-link-${site#site-}"
  if [[ ! -e ${root}/${site} && ! -L ${root}/${site} ]]; then
    [[ ${allow_absent} -eq 1 ]]
    return
  fi
  [[ -d ${root}/${site} && ! -L ${root}/${site} ]]
  checked_stat_equals "root:${group}:750" -c '%U:%G:%a' "${root}/${site}"
  expected=$(printf '%s\n' control-ca.crt data-ca.crt edge.json \
    "${site}-control.crt" "${site}-control.key" "${site}-data.crt" "${site}-data.key" |
    LC_ALL=C sort) || return 1
  actual=$(find "${root}/${site}" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort) || return 1
  [[ ${actual} == "${expected}" ]]
  while IFS= read -r entry; do
    [[ -f ${root}/${site}/${entry} && ! -L ${root}/${site}/${entry} ]]
    checked_stat_equals "root:${group}:640" -c '%U:%G:%a' "${root}/${site}/${entry}"
  done <<< "${expected}"
}

assert_no_unit_overrides() {
  local unit base
  local -a units=(
    campus-link-topology.service campus-link-edge-a.service
    campus-link-edge-b.service campus-link-external.target
  )
  local -a bases=(
    /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system
    /usr/lib/systemd/system /lib/systemd/system
    /etc/systemd/system.control /run/systemd/system.control
  )
  for base in "${bases[@]}"; do
    for unit in "${units[@]}"; do
      [[ ! -e ${base}/${unit}.d && ! -L ${base}/${unit}.d ]]
    done
  done
}

assert_installed_edge_unit() {
  local site=$1 peer unit
  peer=a
  [[ ${site} == a ]] && peer=b
  unit=/etc/systemd/system/campus-link-edge-${site}.service
  [[ -f ${unit} && ! -L ${unit} ]]
  grep -Fx "User=campus-link-${site}" "${unit}" >/dev/null
  grep -Fx "Group=campus-link-${site}" "${unit}" >/dev/null
  grep -Fx 'CapabilityBoundingSet=' "${unit}" >/dev/null
  grep -Fx 'AmbientCapabilities=' "${unit}" >/dev/null
  grep -Fx 'NoNewPrivileges=true' "${unit}" >/dev/null
  grep -Fx 'DevicePolicy=closed' "${unit}" >/dev/null
  grep -Fx 'DeviceAllow=/dev/net/tun rw' "${unit}" >/dev/null
  grep -Fx "NetworkNamespacePath=/run/netns/campus-${site}" "${unit}" >/dev/null
  grep -F 'InaccessiblePaths=' "${unit}" >/dev/null
  grep -F -- "-/etc/campus-link/site-${peer}" "${unit}" >/dev/null
  grep -F -- '-/etc/campus-link/pki' "${unit}" >/dev/null
  grep -F -- '-/var/lib/campus-link' "${unit}" >/dev/null
  grep -F -- '-/srv/openwrt-lab' "${unit}" >/dev/null
}

assert_current_security_tuple() {
  local topology=/usr/local/libexec/campus-link-topology
  local configure=/usr/local/libexec/campus-link-configure-tun
  if [[ ! -e ${topology} && ! -L ${topology} && ! -e ${configure} && ! -L ${configure} ]]; then
    [[ ! -e /etc/systemd/system/campus-link-edge-a.service &&
      ! -L /etc/systemd/system/campus-link-edge-a.service ]]
    [[ ! -e /etc/systemd/system/campus-link-edge-b.service &&
      ! -L /etc/systemd/system/campus-link-edge-b.service ]]
    [[ ! -e ${ROOT}/site-a && ! -L ${ROOT}/site-a ]]
    [[ ! -e ${ROOT}/site-b && ! -L ${ROOT}/site-b ]]
    return
  fi
  [[ -f ${topology} && ! -L ${topology} && -f ${configure} && ! -L ${configure} ]]
  grep -F 'validate_host_forwarding_baseline' "${topology}" >/dev/null
  grep -F 'campus-link requires the host FORWARD policy to be DROP' "${topology}" >/dev/null
  grep -F -- '-s "${WAN_A_ADDRESS}/32" -o "${wan}"' "${topology}" >/dev/null
  grep -F -- '-s "${WAN_B_ADDRESS}/32" -o "${wan}"' "${topology}" >/dev/null
  grep -F 'metric 10 mtu 1200' "${topology}" >/dev/null
  grep -F 'TCPMSS --clamp-mss-to-pmtu' "${topology}" >/dev/null
  file_lacks_pattern E '^[[:space:]]*sysctl -q -w net\.ipv4\.ip_forward=' "${topology}"
  file_lacks_pattern F 'iptables -w -I FORWARD 1 -i "${WAN_A_HOST}" -m comment' "${topology}"
  file_lacks_pattern F 'iptables -w -I FORWARD 1 -i "${WAN_B_HOST}" -m comment' "${topology}"
  grep -F 'mtu 1200' "${configure}" >/dev/null
  grep -F 'TCPMSS --clamp-mss-to-pmtu' "${configure}" >/dev/null
  assert_installed_edge_unit a
  assert_installed_edge_unit b
  assert_edge_tree site-a "${ROOT}" 0
  assert_edge_tree site-b "${ROOT}" 0
}

assert_relay_fault_access_bootstrap() {
  local expected_target=${1:-} expected_host_key=${2:-} require_permit=${3:-1}
  local directory=${ROOT}/relay-fault private public known_hosts target
  local permit_private permit_public actual declared derived
  local expected_host_type expected_host_body has_permit=0
  local private_description public_description derived_public_tmp
  local target_value known_hosts_value
  private=${directory}/id_ed25519
  public=${directory}/id_ed25519.pub
  permit_private=${directory}/permit_ed25519.pem
  permit_public=${directory}/permit_ed25519.pub.pem
  known_hosts=${directory}/known_hosts
  target=${directory}/target
  command -v ssh-keygen >/dev/null
  command -v openssl >/dev/null
  [[ ${require_permit} == 0 || ${require_permit} == 1 ]]
  [[ -d ${directory} && ! -L ${directory} ]]
  checked_stat_equals 0:0:700 -c '%u:%g:%a' -- "${directory}"
  actual=$(find "${directory}" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort) || return 1
  if [[ ${actual} == $'id_ed25519\nid_ed25519.pub\nknown_hosts\npermit_ed25519.pem\npermit_ed25519.pub.pem\ntarget' ]]; then
    has_permit=1
  else
    [[ ${require_permit} -eq 0 ]]
    [[ ${actual} == $'id_ed25519\nid_ed25519.pub\nknown_hosts\ntarget' ]]
  fi
  checked_stat_equals 0:0:600:1 -c '%u:%g:%a:%h' -- "${private}"
  checked_stat_equals 0:0:644:1 -c '%u:%g:%a:%h' -- "${public}"
  checked_stat_equals 0:0:600:1 -c '%u:%g:%a:%h' -- "${known_hosts}"
  checked_stat_equals 0:0:600:1 -c '%u:%g:%a:%h' -- "${target}"
  checked_line_count_equals 1 "${public}"
  checked_line_count_equals 1 "${known_hosts}"
  checked_line_count_equals 1 "${target}"
  grep -E '^ssh-ed25519 [A-Za-z0-9+/]+={0,2} campus-link-relay-fault$' "${public}" >/dev/null
  grep -E '^campus-link-relay-fault ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' "${known_hosts}" >/dev/null
  grep -E '^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$' "${target}" >/dev/null
  derived=$(ssh-keygen -y -f "${private}" 2>/dev/null) || return 1
  declared=$(cut -d ' ' -f 1-2 "${public}") || return 1
  [[ ${derived} == "${declared}" && ${derived%% *} == ssh-ed25519 ]]
  if [[ ${has_permit} -eq 1 ]]; then
    checked_stat_equals 0:0:600:1 -c '%u:%g:%a:%h' -- "${permit_private}"
    checked_stat_equals 0:0:600:1 -c '%u:%g:%a:%h' -- "${permit_public}"
    grep -Fx -- '-----BEGIN PRIVATE KEY-----' "${permit_private}" >/dev/null
    grep -Fx -- '-----BEGIN PUBLIC KEY-----' "${permit_public}" >/dev/null
    private_description=$(openssl pkey -in "${permit_private}" -text_pub -noout 2>/dev/null) || return 1
    public_description=$(openssl pkey -pubin -in "${permit_public}" -text_pub -noout 2>/dev/null) || return 1
    [[ ${private_description%%$'\n'*} == 'ED25519 Public-Key:' ]]
    [[ ${public_description%%$'\n'*} == 'ED25519 Public-Key:' ]]
    derived_public_tmp=$(mktemp "${candidate_dir}/.permit-public.XXXXXX") || return 1
    if ! openssl pkey -in "${permit_private}" -pubout \
      > "${derived_public_tmp}" 2>/dev/null; then
      rm -f -- "${derived_public_tmp}"
      return 1
    fi
    if ! cmp -s -- "${derived_public_tmp}" "${permit_public}"; then
      rm -f -- "${derived_public_tmp}"
      return 1
    fi
    rm -f -- "${derived_public_tmp}" || return 1
  fi
  if [[ -n ${expected_target} || -n ${expected_host_key} ]]; then
    [[ -n ${expected_target} && -n ${expected_host_key} ]]
    read -r expected_host_type expected_host_body _ < "${expected_host_key}" || return 1
    [[ ${expected_host_type} == ssh-ed25519 ]]
    [[ ${expected_host_body} =~ ^[A-Za-z0-9+/]+={0,2}$ ]]
    IFS= read -r target_value < "${target}" || return 1
    IFS= read -r known_hosts_value < "${known_hosts}" || return 1
    [[ ${target_value} == "${expected_target}" ]]
    [[ ${known_hosts_value} == \
      "campus-link-relay-fault ${expected_host_type} ${expected_host_body}" ]]
  fi
  runuser -u campus-link-a -- test ! -r "${private}"
  runuser -u campus-link-b -- test ! -r "${private}"
  if [[ ${has_permit} -eq 1 ]]; then
    runuser -u campus-link-a -- test ! -r "${permit_private}"
    runuser -u campus-link-b -- test ! -r "${permit_private}"
    runuser -u campus-link-a -- test ! -r "${permit_public}"
    runuser -u campus-link-b -- test ! -r "${permit_public}"
  fi
}

assert_relay_fault_access_baseline() {
  if [[ ! -e ${ROOT}/relay-fault && ! -L ${ROOT}/relay-fault ]]; then
    return
  fi
  assert_relay_fault_access_bootstrap '' '' 0
}

render_relay_config() {
  local output=$1 pki_root=$2
  umask 077
  cat > "${output}" <<EOF
{"control_listen":":443","udp_listen":":443","control_cert":"${pki_root}/relay-control.crt","control_key":"${pki_root}/relay-control.key","control_ca":"${pki_root}/control-ca.crt","local_control_identity":{"uri":"${relay_control_uri}","current_spki":"${relay_control_pin}"},"circuit":"home-pair-1","deployment_id":"${transaction_id}","epoch_state_path":"/var/lib/campus-link-relay/rendezvous-epochs.json","prefixes":{"site-a":"10.81.0.0/24","site-b":"10.82.0.0/24"},"control_identities":{"site-a":{"uri":"${site_a_control_uri}","current_spki":"${site_a_control_pin}"},"site-b":{"uri":"${site_b_control_uri}","current_spki":"${site_b_control_pin}"}},"status_path":"/run/campus-link/status.json"}
EOF
  chmod 0600 "${output}"
}

atomic_install() {
  local source=$1 destination=$2 mode=$3 parent destination_name tmp
  parent=$(dirname "${destination}") || return 1
  destination_name=$(basename "${destination}") || return 1
  if [[ -e ${parent} || -L ${parent} ]]; then
    [[ -d ${parent} && ! -L ${parent} ]]
  else
    install -d -m 0755 "${parent}"
  fi
  tmp=$(mktemp "${parent}/.${destination_name}.XXXXXX") || return 1
  install -m "${mode}" "${source}" "${tmp}"
  mv -fT -- "${tmp}" "${destination}"
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

verify_source_checkout() {
  local expected_commit actual_commit untracked
  expected_commit=$(<"${BUILD}/SOURCE_COMMIT") || return 1
  [[ ${expected_commit} =~ ^[a-f0-9]{40}$ ]] || return 1
  actual_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD) || return 1
  [[ ${actual_commit} == "${expected_commit}" ]] || return 1
  git -C "${REPO_ROOT}" diff --quiet -- \
    campus-link lab cloud/cloud-init.yaml scripts/Deploy-CampusLink.ps1 || return 1
  git -C "${REPO_ROOT}" diff --cached --quiet -- \
    campus-link lab cloud/cloud-init.yaml scripts/Deploy-CampusLink.ps1 || return 1
  untracked=$(git -C "${REPO_ROOT}" ls-files --others -- \
    campus-link lab cloud/cloud-init.yaml scripts/Deploy-CampusLink.ps1) || return 1
  [[ -z ${untracked} ]] || return 1
  return 0
}

assemble_release() {
  local source path expected digest manifest_digest source_digest source_commit version displaced
  local tracked_listing manifest_lines expected_lines source_tree_lines source_name
  local -a tracked_paths=()
  release_tmp=$(mktemp -d "${BUILD}/.release.${transaction_id}.XXXXXX") || return 1
  chmod 0700 "${release_tmp}"
  tracked_listing=$(mktemp "${release_tmp}/.tracked.XXXXXX") || return 1
  verify_source_checkout
  install -d -m 0700 \
    "${release_tmp}/bin" "${release_tmp}/config" "${release_tmp}/scripts" \
    "${release_tmp}/systemd" "${release_tmp}/lab" "${release_tmp}/tests"
  install -m 0644 "${BUILD}/VERSION" "${release_tmp}/VERSION"
  install -m 0644 "${BUILD}/SOURCE_TREE.sha256" "${release_tmp}/SOURCE_TREE.sha256"
  install -m 0644 "${BUILD}/SOURCE_COMMIT" "${release_tmp}/SOURCE_COMMIT"
  install -m 0755 "${BUILD}/campus-link-edge" "${release_tmp}/bin/campus-link-edge"
  install -m 0755 "${BUILD}/campus-link-relay" "${release_tmp}/bin/campus-link-relay"
  install -m 0755 "${BUILD}/campus-linkctl" "${release_tmp}/bin/campus-linkctl"
  install -m 0600 "${candidate_dir}/edge-a.json" "${release_tmp}/config/edge-a.json"
  install -m 0600 "${candidate_dir}/edge-b.json" "${release_tmp}/config/edge-b.json"
  install -m 0600 "${candidate_dir}/relay.json" "${release_tmp}/config/relay.json"
  git -C "${REPO_ROOT}" ls-files -z -- 'campus-link/scripts/*.sh' | \
    LC_ALL=C sort -z > "${tracked_listing}" || return 1
  read_complete_nul_inventory "${tracked_listing}" tracked_paths || return 1
  for path in "${tracked_paths[@]}"; do
    source=${REPO_ROOT}/${path}
    path=${path#campus-link/scripts/}
    [[ ${path} =~ ^[A-Za-z0-9._-]+\.sh$ ]]
    install -m 0755 "${source}" "${release_tmp}/scripts/${path}"
  done
  git -C "${REPO_ROOT}" ls-files -z -- 'campus-link/systemd/*' | \
    LC_ALL=C sort -z > "${tracked_listing}" || return 1
  read_complete_nul_inventory "${tracked_listing}" tracked_paths || return 1
  for path in "${tracked_paths[@]}"; do
    source=${REPO_ROOT}/${path}
    path=${path#campus-link/systemd/}
    [[ ${path} =~ ^[A-Za-z0-9._@-]+$ ]]
    install -m 0644 "${source}" "${release_tmp}/systemd/${path}"
  done
  git -C "${REPO_ROOT}" ls-files -z -- 'lab/*' | \
    LC_ALL=C sort -z > "${tracked_listing}" || return 1
  read_complete_nul_inventory "${tracked_listing}" tracked_paths || return 1
  for path in "${tracked_paths[@]}"; do
    source=${REPO_ROOT}/${path}
    path=${path#lab/}
    [[ ${path} =~ ^[A-Za-z0-9._-]+$ ]]
    if [[ ${path} == *.service ]]; then
      install -m 0644 "${source}" "${release_tmp}/lab/${path}"
    else
      install -m 0755 "${source}" "${release_tmp}/lab/${path}"
    fi
  done
  git -C "${REPO_ROOT}" ls-files -z -- 'campus-link/tests/*.py' | \
    LC_ALL=C sort -z > "${tracked_listing}" || return 1
  read_complete_nul_inventory "${tracked_listing}" tracked_paths || return 1
  for path in "${tracked_paths[@]}"; do
    source=${REPO_ROOT}/${path}
    path=${path#campus-link/tests/}
    [[ ${path} =~ ^[A-Za-z0-9._-]+\.py$ ]]
    install -m 0755 "${source}" "${release_tmp}/tests/${path}"
  done
  rm -f -- "${tracked_listing}" || return 1
  expected=${candidate_dir}/release-files.expected
  find "${release_tmp}" -type f -printf '%P\n' | LC_ALL=C sort > "${expected}" || return 1
  [[ -s ${expected} ]]
  {
    cat "${expected}"
    printf '%s\n' \
      relay-pki/control-ca.crt \
      relay-pki/relay-control.crt \
      relay-pki/relay-control.key
  } | LC_ALL=C sort > "${candidate_dir}/manifest-files.expected" || return 1
  : > "${release_tmp}/MANIFEST.sha256"
  while IFS= read -r path; do
    [[ ${path} =~ ^[A-Za-z0-9._/-]+$ && ${path} != MANIFEST.sha256 ]]
    case ${path} in
      relay-pki/control-ca.crt) source=${ROOT}/pki/control-ca.crt ;;
      relay-pki/relay-control.crt) source=${ROOT}/pki/relay-control.crt ;;
      relay-pki/relay-control.key) source=${ROOT}/pki/relay-control.key ;;
      *) source=${release_tmp}/${path} ;;
    esac
    checked_sha256 digest "${source}" || return 1
    printf '%s  %s\n' "${digest}" "${path}" >> "${release_tmp}/MANIFEST.sha256"
  done < "${candidate_dir}/manifest-files.expected"
  chmod 0600 "${release_tmp}/MANIFEST.sha256"
  checked_line_count manifest_lines "${release_tmp}/MANIFEST.sha256" || return 1
  checked_line_count expected_lines "${candidate_dir}/manifest-files.expected" || return 1
  [[ ${manifest_lines} == "${expected_lines}" ]]
  checked_line_count_equals 1 "${release_tmp}/VERSION" || return 1
  checked_line_count_equals 1 "${release_tmp}/SOURCE_COMMIT" || return 1
  IFS= read -r version < "${release_tmp}/VERSION" || return 1
  IFS= read -r source_commit < "${release_tmp}/SOURCE_COMMIT" || return 1
  [[ ${source_commit} =~ ^[a-f0-9]{40}$ ]]
  read -r source_digest source_name < "${release_tmp}/SOURCE_TREE.sha256" || return 1
  [[ ${source_digest} =~ ^[a-f0-9]{64}$ && ${source_name} == source-tree ]]
  checked_line_count_equals 1 "${release_tmp}/SOURCE_TREE.sha256" || return 1
  [[ ${version} == "phase1-${source_commit:0:12}-${source_digest:0:12}" ]]
  checked_sha256 manifest_digest "${release_tmp}/MANIFEST.sha256" || return 1
  verify_source_checkout
  cat > "${candidate_dir}/deployment-attestation.env" <<EOF
VERSION=${version}
SOURCE_TREE_SHA256=${source_digest}
MANIFEST_SHA256=${manifest_digest}
EOF
  chmod 0600 "${candidate_dir}/deployment-attestation.env"

  displaced=${BUILD}/.release.displaced.${transaction_id}
  rm -rf -- "${displaced}"
  if [[ -e ${BUILD}/release || -L ${BUILD}/release ]]; then
    [[ -d ${BUILD}/release && ! -L ${BUILD}/release ]]
    mv -T -- "${BUILD}/release" "${displaced}"
  fi
  mv -T -- "${release_tmp}" "${BUILD}/release"
  release_tmp=
  rm -rf -- "${displaced}"
}

assert_no_release_symlinks() {
  local release=$1 inventory status=0
  inventory=$(mktemp "${candidate_dir}/release-symlinks.XXXXXX") || return 1
  if ! find "${release}" -type l -print0 -quit > "${inventory}"; then
    status=1
  elif [[ -s ${inventory} ]]; then
    status=1
  fi
  rm -f -- "${inventory}" || return 1
  (( status == 0 ))
}

verify_release() {
  local release=${BUILD}/release actual expected path source expected_digest actual_digest
  local manifest_size match_output
  [[ -d ${release} && ! -L ${release} ]]
  [[ -f ${release}/scripts/relay-restart-transport.sh &&
    ! -L ${release}/scripts/relay-restart-transport.sh &&
    -x ${release}/scripts/relay-restart-transport.sh ]]
  assert_no_release_symlinks "${release}"
  find "${release}" -type d -printf '%P\n' | LC_ALL=C sort > "${candidate_dir}/release-dirs.actual" || return 1
  printf '%s\n' '' bin config lab scripts systemd tests | LC_ALL=C sort > "${candidate_dir}/release-dirs.expected" || return 1
  cmp -s -- "${candidate_dir}/release-dirs.expected" "${candidate_dir}/release-dirs.actual"
  expected=${candidate_dir}/release-files.expected
  actual=${candidate_dir}/release-files.actual
  {
    cat "${expected}"
    printf '%s\n' MANIFEST.sha256
  } | LC_ALL=C sort > "${candidate_dir}/release-files.with-manifest.expected" || return 1
  find "${release}" -type f -printf '%P\n' | LC_ALL=C sort > "${actual}" || return 1
  cmp -s -- "${candidate_dir}/release-files.with-manifest.expected" "${actual}"
  manifest_size=$(stat -c '%s' "${release}/MANIFEST.sha256") || return 1
  [[ ${manifest_size} =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  (( manifest_size <= 65536 )) || return 1
  file_lacks_pattern Ev '^[a-f0-9]{64}  [A-Za-z0-9._/-]+$' "${release}/MANIFEST.sha256"
  awk '{print $2}' "${release}/MANIFEST.sha256" > "${candidate_dir}/manifest-files.actual" || return 1
  cmp -s -- "${candidate_dir}/manifest-files.expected" "${candidate_dir}/manifest-files.actual"
  while IFS= read -r path; do
    match_output=$(grep -F "  ${path}" "${release}/MANIFEST.sha256") || return 1
    [[ ${match_output} != *$'\n'* && ${match_output#*  } == "${path}" ]] || return 1
    expected_digest=${match_output%% *}
    case ${path} in
      relay-pki/control-ca.crt) source=${ROOT}/pki/control-ca.crt ;;
      relay-pki/relay-control.crt) source=${ROOT}/pki/relay-control.crt ;;
      relay-pki/relay-control.key) source=${ROOT}/pki/relay-control.key ;;
      *) source=${release}/${path} ;;
    esac
    checked_sha256 actual_digest "${source}" || return 1
    [[ ${actual_digest} == "${expected_digest}" ]]
  done < "${candidate_dir}/manifest-files.expected"
}

snapshot_path() {
  local snapshot=$1 path=$2 relative=${path#/} relative_parent
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
  for unit in campus-link-topology.service campus-link-edge-a.service campus-link-edge-b.service campus-link-external.target; do
    systemctl is-active --quiet "${unit}" && touch "${snapshot_tmp}/active.${unit}"
    systemctl is-enabled --quiet "${unit}" && touch "${snapshot_tmp}/enabled.${unit}"
  done
  printf '%s\n' "${transaction_id}" > "${snapshot_tmp}/.complete"
  chmod 0600 "${snapshot_tmp}/.complete"
  mv -T -- "${snapshot_tmp}" "${SNAPSHOTS}/${transaction_id}"
  old_active=
  if [[ -e ${ACTIVE} || -L ${ACTIVE} ]]; then
    [[ -f ${ACTIVE} && ! -L ${ACTIVE} ]] || return 1
    checked_line_count_equals 1 "${ACTIVE}" || return 1
    IFS= read -r old_active < "${ACTIVE}" || return 1
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
  /usr/local/bin/campus-link-edge
  /usr/local/bin/campus-linkctl
  /usr/local/libexec/campus-link-topology
  /usr/local/libexec/campus-link-configure-tun
  /usr/local/libexec/campus-link-smoke-external
  /usr/local/libexec/campus-link-restore-offline
  /usr/local/libexec/campus-link-qualify-a11-b22
  /usr/local/libexec/campus-link-test-edge-recovery
  /usr/local/libexec/campus-link-test-netem
  /usr/local/libexec/campus-link-test-relay-recovery-watch
  /usr/local/libexec/gate-evidence.sh
  /usr/local/libexec/campus-link-gate-evidence
  /usr/local/libexec/campus-link-qualification-chain
  /usr/local/libexec/campus-link-a11-b22.py
  /usr/local/libexec/campus-link-stream-transport.py
  /usr/local/libexec/campus-link-status-gate.py
  /usr/local/libexec/campus-link-nat-rebind-gate.py
  /usr/local/libexec/campus-link-soak-a11-b22
  /usr/local/libexec/campus-link-accelerated-fault-soak
  /usr/local/libexec/campus-link-fault-in-stream
  /usr/local/libexec/campus-link-nat-rebinding-gate
  /usr/local/libexec/campus-link-relay-restart-driver
  /usr/local/libexec/campus-link-relay-restart-transport
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
  /etc/campus-link/edge-a.json
  /etc/campus-link/edge-b.json
  /etc/campus-link/site-a
  /etc/campus-link/site-b
  /etc/campus-link/pki
  /etc/campus-link/relay-fault
  /var/lib/campus-link/installed-edge-version
  /var/lib/campus-link/installed-release-manifest.sha256
  /var/lib/campus-link/deployment-attestation.env
  /var/lib/campus-link/a11-b22-firewall.complete
  /var/lib/campus-link/router-only.enabled
)

"${REPO_ROOT}/campus-link/scripts/build.sh" "${REPO_ROOT}"

pki_source=${ROOT}/pki
new_pki=0
if [[ -e ${pki_source} || -L ${pki_source} ]]; then
  [[ -d ${pki_source} && ! -L ${pki_source} ]]
  CAMPUS_LINK_LAB_ONLY=1 CAMPUS_LINK_ALLOW_AUTHORIZATION_MIGRATION=1 \
    CAMPUS_LINK_PKI_ROOT=${pki_source} \
    "${REPO_ROOT}/campus-link/scripts/generate-lab-pki.sh"
else
  pki_source=${candidate_dir}/pki
  new_pki=1
  CAMPUS_LINK_LAB_ONLY=1 CAMPUS_LINK_PKI_ROOT=${pki_source} \
    "${REPO_ROOT}/campus-link/scripts/generate-lab-pki.sh"
fi

/bin/bash "${AUTH_HELPER}" "${pki_source}" "${candidate_dir}/authorization.env"
authorization_migration=0
if [[ ${new_pki} -eq 0 ]]; then
  if cmp -s -- "${candidate_dir}/authorization.env" "${pki_source}/authorization.env"; then
    authorization_migration=0
  else
    authorization_compare_status=$?
    [[ ${authorization_compare_status} -eq 1 ]] || exit 1
    authorization_migration=1
  fi
fi
checked_line_count_equals 10 "${candidate_dir}/authorization.env"
relay_control_uri=$(read_authorization RELAY_CONTROL_URI "${candidate_dir}/authorization.env") || exit 1
relay_control_pin=$(read_authorization RELAY_CONTROL_PIN "${candidate_dir}/authorization.env") || exit 1
site_a_control_uri=$(read_authorization SITE_A_CONTROL_URI "${candidate_dir}/authorization.env") || exit 1
site_a_control_pin=$(read_authorization SITE_A_CONTROL_PIN "${candidate_dir}/authorization.env") || exit 1
site_b_control_uri=$(read_authorization SITE_B_CONTROL_URI "${candidate_dir}/authorization.env") || exit 1
site_b_control_pin=$(read_authorization SITE_B_CONTROL_PIN "${candidate_dir}/authorization.env") || exit 1
site_a_data_uri=$(read_authorization SITE_A_DATA_URI "${candidate_dir}/authorization.env") || exit 1
site_a_data_pin=$(read_authorization SITE_A_DATA_PIN "${candidate_dir}/authorization.env") || exit 1
site_b_data_uri=$(read_authorization SITE_B_DATA_URI "${candidate_dir}/authorization.env") || exit 1
site_b_data_pin=$(read_authorization SITE_B_DATA_PIN "${candidate_dir}/authorization.env") || exit 1
readonly relay_control_uri relay_control_pin site_a_control_uri site_a_control_pin
readonly site_b_control_uri site_b_control_pin site_a_data_uri site_a_data_pin
readonly site_b_data_uri site_b_data_pin
[[ ${relay_control_uri} == "${CIRCUIT_URI}/relay/control" ]]
[[ ${site_a_control_uri} == "${CIRCUIT_URI}/site-a/control" ]]
[[ ${site_b_control_uri} == "${CIRCUIT_URI}/site-b/control" ]]
[[ ${site_a_data_uri} == "${CIRCUIT_URI}/site-a/data" ]]
[[ ${site_b_data_uri} == "${CIRCUIT_URI}/site-b/data" ]]

generation_a=$(openssl rand -hex 16) || exit 1
generation_b=$(openssl rand -hex 16) || exit 1
[[ ${generation_a} =~ ^[a-f0-9]{32}$ && ${generation_b} =~ ^[a-f0-9]{32}$ ]]
[[ ${generation_a} != "${generation_b}" ]]
stage_edge_credentials "${pki_source}" "${candidate_dir}/edge-credentials"
render_edge_configs "${candidate_dir}" "${candidate_dir}/edge-credentials"
render_relay_config "${candidate_dir}/relay.json" "${pki_source}"
"${BUILD}/campus-link-edge" -check-config -config "${candidate_dir}/edge-a.json"
"${BUILD}/campus-link-edge" -check-config -config "${candidate_dir}/edge-b.json"
"${BUILD}/campus-link-relay" -check-config -config "${candidate_dir}/relay.json"
assert_edge_tree site-a "${ROOT}" 1
assert_edge_tree site-b "${ROOT}" 1
assert_no_unit_overrides
assert_current_security_tuple
/bin/bash "${REPO_ROOT}/campus-link/scripts/provision-relay-fault-access.sh" \
  validate-gate-input "${RELAY_ADDRESS}" "${RELAY_HOST_PUBLIC_KEY}"
assert_relay_fault_access_baseline

activate_snapshot
trap rollback_on_error ERR

install -d -m 0755 /usr/local/libexec /usr/local/bin "${ROOT}"
if [[ ${new_pki} -eq 1 ]]; then
  pki_candidate=${ROOT}/.pki.candidate.${transaction_id}
  [[ ! -e ${pki_candidate} && ! -L ${pki_candidate} ]]
  cp -a -- "${pki_source}" "${pki_candidate}"
  mv -T -- "${pki_candidate}" "${ROOT}/pki"
elif [[ ${authorization_migration} -eq 1 ]]; then
  atomic_install "${candidate_dir}/authorization.env" "${ROOT}/pki/authorization.env" 0600
fi

install_edge_credentials "${candidate_dir}/edge-credentials" "${ROOT}"
render_edge_configs "${candidate_dir}" "${ROOT}"
render_relay_config "${candidate_dir}/relay.json" "${ROOT}/pki"
"${BUILD}/campus-link-edge" -check-config -config "${candidate_dir}/edge-a.json"
"${BUILD}/campus-link-edge" -check-config -config "${candidate_dir}/edge-b.json"
"${BUILD}/campus-link-relay" -check-config -config "${candidate_dir}/relay.json"
assemble_release
verify_release

readonly RELEASE=${BUILD}/release
fault_authority_permit=${SNAPSHOTS}/${transaction_id}/.fault-authority-open
[[ ! -e ${fault_authority_permit} && ! -L ${fault_authority_permit} ]]
printf '%s\n' "${transaction_id}" > "${fault_authority_permit}"
chmod 0600 "${fault_authority_permit}"
CAMPUS_LINK_TRANSACTION_ID=${transaction_id} \
  /bin/bash "${RELEASE}/scripts/provision-relay-fault-access.sh" \
    gate-host "${RELAY_ADDRESS}" "${RELAY_HOST_PUBLIC_KEY}"
rm -f -- "${fault_authority_permit}"
assert_relay_fault_access_bootstrap "${RELAY_ADDRESS}" "${RELAY_HOST_PUBLIC_KEY}"
atomic_install "${RELEASE}/bin/campus-link-edge" /usr/local/bin/campus-link-edge 0755
atomic_install "${RELEASE}/bin/campus-linkctl" /usr/local/bin/campus-linkctl 0755
for script in topology configure-tun smoke-external restore-offline; do
  atomic_install "${RELEASE}/scripts/${script}.sh" \
    "/usr/local/libexec/campus-link-${script}" 0755
done
atomic_install "${RELEASE}/scripts/qualify-a11-b22.sh" /usr/local/libexec/campus-link-qualify-a11-b22 0755
atomic_install "${RELEASE}/scripts/test-edge-recovery.sh" /usr/local/libexec/campus-link-test-edge-recovery 0755
atomic_install "${RELEASE}/scripts/test-netem.sh" /usr/local/libexec/campus-link-test-netem 0755
atomic_install "${RELEASE}/scripts/test-relay-recovery-watch.sh" /usr/local/libexec/campus-link-test-relay-recovery-watch 0755
atomic_install "${RELEASE}/scripts/gate-evidence.sh" /usr/local/libexec/campus-link-gate-evidence 0755
atomic_install "${RELEASE}/scripts/qualification-chain.sh" /usr/local/libexec/campus-link-qualification-chain 0755
atomic_install "${RELEASE}/tests/a11_b22.py" /usr/local/libexec/campus-link-a11-b22.py 0755
atomic_install "${RELEASE}/tests/stream_transport.py" /usr/local/libexec/campus-link-stream-transport.py 0755
atomic_install "${RELEASE}/tests/status_gate.py" /usr/local/libexec/campus-link-status-gate.py 0755
atomic_install "${RELEASE}/tests/nat_rebind_gate.py" /usr/local/libexec/campus-link-nat-rebind-gate.py 0755
atomic_install "${RELEASE}/scripts/soak-a11-b22.sh" /usr/local/libexec/campus-link-soak-a11-b22 0755
atomic_install "${RELEASE}/scripts/accelerated-fault-soak.sh" /usr/local/libexec/campus-link-accelerated-fault-soak 0755
atomic_install "${RELEASE}/scripts/fault-in-stream.sh" /usr/local/libexec/campus-link-fault-in-stream 0755
atomic_install "${RELEASE}/scripts/nat-rebinding-gate.sh" /usr/local/libexec/campus-link-nat-rebinding-gate 0755
atomic_install "${RELEASE}/scripts/relay-restart-driver.sh" /usr/local/libexec/campus-link-relay-restart-driver 0755
atomic_install "${RELEASE}/scripts/relay-restart-transport.sh" /usr/local/libexec/campus-link-relay-restart-transport 0755
atomic_install "${RELEASE}/scripts/rollback-edge.sh" /usr/local/libexec/campus-link-rollback-edge 0755
atomic_install "${RELEASE}/lab/openwrt-lab-topology" /usr/local/libexec/openwrt-lab-topology 0755
atomic_install "${RELEASE}/lab/openwrt-lab-start" /usr/local/libexec/openwrt-lab-start 0755
atomic_install "${RELEASE}/lab/openwrt-lab-stop" /usr/local/libexec/openwrt-lab-stop 0755
atomic_install "${RELEASE}/lab/openwrt-lab-smoke" /usr/local/libexec/openwrt-lab-smoke 0755
atomic_install "${RELEASE}/lab/openwrt-lab-console-config" /usr/local/libexec/openwrt-lab-console-config 0755
for unit in \
  campus-link-topology.service \
  campus-link-edge-a.service \
  campus-link-edge-b.service \
  campus-link-external.target \
  campus-link-full-qualification.service \
  campus-link-accelerated-fault.service \
  campus-link-fault-in-stream.service \
  campus-link-nat-rebinding.service \
  campus-link-24h-soak.service \
  campus-link-7d-burn-in.service \
  campus-link-qualification-chain.service; do
  atomic_install "${RELEASE}/systemd/${unit}" "/etc/systemd/system/${unit}" 0644
done
atomic_install_owned "${RELEASE}/config/edge-a.json" "${ROOT}/site-a/edge.json" 0640 root campus-link-a
atomic_install_owned "${RELEASE}/config/edge-b.json" "${ROOT}/site-b/edge.json" 0640 root campus-link-b
rm -f -- "${ROOT}/edge-a.json" "${ROOT}/edge-b.json"
rm -f -- /usr/local/libexec/gate-evidence.sh
assert_edge_tree site-a "${ROOT}" 0
assert_edge_tree site-b "${ROOT}" 0
runuser --user campus-link-a --group campus-link-a -- \
  /usr/local/bin/campus-link-edge -check-config -config "${ROOT}/site-a/edge.json"
runuser --user campus-link-b --group campus-link-b -- \
  /usr/local/bin/campus-link-edge -check-config -config "${ROOT}/site-b/edge.json"

install -d -m 0700 /var/lib/campus-link
router_only_tmp=$(mktemp /var/lib/campus-link/.router-only.enabled.XXXXXX) || exit 1
printf 'FORMAT=1\nTRANSACTION_ID=%s\n' "${transaction_id}" > "${router_only_tmp}"
chmod 0600 "${router_only_tmp}"
mv -fT -- "${router_only_tmp}" /var/lib/campus-link/router-only.enabled
systemctl daemon-reload
assert_no_unit_overrides
systemctl enable campus-link-external.target
checked_line_count_equals 1 "${RELEASE}/VERSION"
IFS= read -r version < "${RELEASE}/VERSION" || exit 1
version_tmp=$(mktemp /var/lib/campus-link/.installed-edge-version.XXXXXX) || exit 1
printf '%s\n' "${version}" > "${version_tmp}"
chmod 0600 "${version_tmp}"
mv -fT -- "${version_tmp}" /var/lib/campus-link/installed-edge-version
atomic_install "${RELEASE}/MANIFEST.sha256" /var/lib/campus-link/installed-release-manifest.sha256 0600
atomic_install "${candidate_dir}/deployment-attestation.env" /var/lib/campus-link/deployment-attestation.env 0600
rm -f -- "${BUILD}/relay.json"
trap - ERR
trap cleanup_on_exit EXIT
