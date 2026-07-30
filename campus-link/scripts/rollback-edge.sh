#!/usr/bin/env bash
set -euo pipefail

readonly ROLLBACK_ROOT=/var/lib/campus-link/rollback-edge
readonly SNAPSHOTS=${ROLLBACK_ROOT}/snapshots
readonly ACTIVE=${ROLLBACK_ROOT}/ACTIVE

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

if [[ -n ${1:-} ]]; then
  transaction_id=$1
else
  [[ -f ${ACTIVE} && ! -L ${ACTIVE} ]]
  read_one_line_file "${ACTIVE}" transaction_id
fi

[[ ${EUID} -eq 0 ]]
exec 8>/run/campus-link-provision-relay-fault.lock
flock -w 30 8
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
rm -f -- "${SNAPSHOT}/.fault-authority-open"

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

for path in "${snapshot_paths[@]}"; do
  snapshot_entry_state entry_state "${path}"
done
manifest_line_count=$(wc -l < "${SNAPSHOT}/manifest") || exit 1
[[ ${manifest_line_count} =~ ^[0-9]+$ &&
  ${manifest_line_count} -eq ${#snapshot_paths[@]} ]]

assert_no_fixed_match() {
  local pattern=$1 file=$2 status=0 matches
  matches=$(grep -F -- "${pattern}" "${file}") || status=$?
  (( status == 1 )) && [[ -z ${matches} ]]
}

assert_no_extended_match() {
  local pattern=$1 file=$2 status=0 matches
  matches=$(grep -E -- "${pattern}" "${file}") || status=$?
  (( status == 1 )) && [[ -z ${matches} ]]
}

validate_stored_site_tree() {
  local site=$1 group dir expected actual entry tuple
  group="campus-link-${site#site-}"
  dir=${SNAPSHOT}/rootfs/etc/campus-link/${site}
  [[ -d ${dir} && ! -L ${dir} ]]
  tuple=$(stat -c '%U:%G:%a' "${dir}") || return 1
  [[ ${tuple} == "root:${group}:750" ]]
  expected=$(printf '%s\n' control-ca.crt data-ca.crt edge.json \
    "${site}-control.crt" "${site}-control.key" "${site}-data.crt" "${site}-data.key" |
    LC_ALL=C sort) || return 1
  actual=$(find "${dir}" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort) || return 1
  [[ ${actual} == "${expected}" ]]
  while IFS= read -r entry; do
    [[ -f ${dir}/${entry} && ! -L ${dir}/${entry} ]]
    tuple=$(stat -c '%U:%G:%a:%h' "${dir}/${entry}") || return 1
    [[ ${tuple} == "root:${group}:640:1" ]]
  done <<< "${expected}"
}

validate_stored_edge_unit() {
  local site=$1 peer unit
  peer=a
  [[ ${site} == a ]] && peer=b
  unit=${SNAPSHOT}/rootfs/etc/systemd/system/campus-link-edge-${site}.service
  [[ -f ${unit} && ! -L ${unit} ]]
  grep -Fxq "User=campus-link-${site}" "${unit}"
  grep -Fxq "Group=campus-link-${site}" "${unit}"
  grep -Fxq 'CapabilityBoundingSet=' "${unit}"
  grep -Fxq 'AmbientCapabilities=' "${unit}"
  grep -Fxq 'NoNewPrivileges=true' "${unit}"
  grep -Fxq 'DevicePolicy=closed' "${unit}"
  grep -Fxq 'DeviceAllow=/dev/net/tun rw' "${unit}"
  grep -Fxq "NetworkNamespacePath=/run/netns/campus-${site}" "${unit}"
  grep -Fq 'InaccessiblePaths=' "${unit}"
  grep -Fq -- "-/etc/campus-link/site-${peer}" "${unit}"
  grep -Fq -- '-/etc/campus-link/pki' "${unit}"
  grep -Fq -- '-/var/lib/campus-link' "${unit}"
  grep -Fq -- '-/srv/openwrt-lab' "${unit}"
}

validate_snapshot_security_tuple() {
  local topology=/usr/local/libexec/campus-link-topology
  local configure=/usr/local/libexec/campus-link-configure-tun
  local stored_topology=${SNAPSHOT}/rootfs/${topology#/}
  local stored_configure=${SNAPSHOT}/rootfs/${configure#/}
  local topology_state configure_state edge_a_state edge_b_state site_a_state site_b_state
  snapshot_entry_state topology_state "${topology}" || return 1
  snapshot_entry_state configure_state "${configure}" || return 1
  snapshot_entry_state edge_a_state /etc/systemd/system/campus-link-edge-a.service || return 1
  snapshot_entry_state edge_b_state /etc/systemd/system/campus-link-edge-b.service || return 1
  snapshot_entry_state site_a_state /etc/campus-link/site-a || return 1
  snapshot_entry_state site_b_state /etc/campus-link/site-b || return 1
  if [[ ${topology_state} == absent && ${configure_state} == absent ]]; then
    [[ ${edge_a_state} == absent && ${edge_b_state} == absent ]]
    [[ ${site_a_state} == absent && ${site_b_state} == absent ]]
    return 0
  fi
  [[ ${topology_state} == present && ${configure_state} == present ]]
  [[ ${edge_a_state} == present && ${edge_b_state} == present ]]
  [[ ${site_a_state} == present && ${site_b_state} == present ]]
  [[ -f ${stored_topology} && ! -L ${stored_topology} ]]
  [[ -f ${stored_configure} && ! -L ${stored_configure} ]]
  grep -Fq 'KILL_SWITCH_METRIC=32760' "${stored_topology}"
  grep -Fq 'route add unreachable "${remote_prefix}"' "${stored_topology}"
  grep -Fq 'campus-link-private-prefix-kill-switch' "${stored_topology}"
  grep -Fq 'validate_host_forwarding_baseline' "${stored_topology}"
  grep -Fq "campus-link requires the host FORWARD policy to be DROP" "${stored_topology}"
  grep -Fq -- '-s "${WAN_A_ADDRESS}/32" -o "${wan}"' "${stored_topology}"
  grep -Fq -- '-s "${WAN_B_ADDRESS}/32" -o "${wan}"' "${stored_topology}"
  grep -Fq 'metric 10 mtu 1200' "${stored_topology}"
  grep -Fq 'TCPMSS --clamp-mss-to-pmtu' "${stored_topology}"
  assert_no_extended_match '^[[:space:]]*sysctl -q -w net\.ipv4\.ip_forward=' "${stored_topology}"
  assert_no_fixed_match 'iptables -w -I FORWARD 1 -i "${WAN_A_HOST}" -m comment' "${stored_topology}"
  assert_no_fixed_match 'iptables -w -I FORWARD 1 -i "${WAN_B_HOST}" -m comment' "${stored_topology}"
  grep -Fq 'KILL_SWITCH_METRIC=32760' "${stored_configure}"
  grep -Fq 'route show type unreachable "${REMOTE_PREFIX}"' "${stored_configure}"
  grep -Fq 'campus-link-private-prefix-kill-switch' "${stored_configure}"
  grep -Fq 'mtu 1200' "${stored_configure}"
  grep -Fq 'TCPMSS --clamp-mss-to-pmtu' "${stored_configure}"
  validate_stored_edge_unit a
  validate_stored_edge_unit b
  validate_stored_site_tree site-a
  validate_stored_site_tree site-b
}

# Never roll a live topology back to a version that can expose a private prefix,
# shared-host forwarding, root parsers, or peer credentials. A pre-campus-link
# snapshot is safe because stopping the target removes the namespaces entirely.
validate_snapshot_security_tuple

restore_file() {
  local path=$1 relative=${path#/} source=${SNAPSHOT}/rootfs/${path#/}
  local parent tmp entry_state path_name
  snapshot_entry_state entry_state "${path}" || return 1
  if [[ ${entry_state} == present ]]; then
    [[ -f ${source} && ! -L ${source} ]]
    parent=$(dirname "${path}") || return 1
    install -d -m 0755 "${parent}"
    path_name=$(basename "${path}") || return 1
    tmp=$(mktemp "${parent}/.${path_name}.restore.XXXXXX") || return 1
    cp -a -- "${source}" "${tmp}"
    mv -fT -- "${tmp}" "${path}"
  else
    rm -f -- "${path}"
  fi
}

restore_tree() {
  local path=$1 relative=${1#/} name entry_state
  local source=${SNAPSHOT}/rootfs/${relative}
  name=$(basename "${path}") || return 1
  local staged=/etc/campus-link/.${name}.restore.${transaction_id}
  local displaced=/etc/campus-link/.${name}.displaced.${transaction_id}
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

assert_unit_inactive() {
  local unit=$1 state
  state=$(systemctl show --property=ActiveState --value "${unit}" 2>/dev/null) || return 1
  [[ ${state} == inactive || ${state} == failed || ${state} == not-found ]]
}

stop_unit_if_loaded() {
  local unit=$1 load
  load=$(systemctl show --property=LoadState --value "${unit}" 2>/dev/null) || return 1
  if [[ ${load} != not-found ]]; then
    systemctl stop "${unit}" >/dev/null
  fi
  assert_unit_inactive "${unit}"
}

for unit in campus-link-external.target campus-link-edge-a.service \
  campus-link-edge-b.service campus-link-topology.service; do
  stop_unit_if_loaded "${unit}"
done
for path in "${snapshot_paths[@]}"; do
  case ${path} in
    /etc/campus-link/pki|/etc/campus-link/relay-fault|/etc/campus-link/site-a|/etc/campus-link/site-b)
      restore_tree "${path}"
      ;;
    *) restore_file "${path}" ;;
  esac
done
systemctl daemon-reload
for unit in campus-link-topology.service campus-link-edge-a.service campus-link-edge-b.service campus-link-external.target; do
  if [[ -f ${SNAPSHOT}/enabled.${unit} ]]; then
    systemctl enable "${unit}" >/dev/null
  else
    systemctl disable "${unit}" >/dev/null 2>&1
  fi
done
if [[ -f ${SNAPSHOT}/active.campus-link-external.target ]]; then
  systemctl start campus-link-external.target
elif [[ -f ${SNAPSHOT}/active.campus-link-topology.service ]]; then
  systemctl start campus-link-topology.service
fi
for unit in campus-link-edge-a.service campus-link-edge-b.service; do
  if [[ -f ${SNAPSHOT}/active.${unit} ]]; then
    systemctl start "${unit}"
  else
    unit_active_state=$(systemctl show --property=ActiveState --value "${unit}") || exit 1
    case ${unit_active_state} in
      active) systemctl stop "${unit}" ;;
      inactive|failed|not-found) ;;
      *) exit 1 ;;
    esac
  fi
done
for unit in campus-link-topology.service campus-link-edge-a.service \
  campus-link-edge-b.service campus-link-external.target; do
  if [[ -f ${SNAPSHOT}/active.${unit} ]]; then
    systemctl is-active --quiet "${unit}"
  else
    assert_unit_inactive "${unit}"
  fi
done
if [[ -f ${SNAPSHOT}/active.campus-link-external.target ||
  -f ${SNAPSHOT}/active.campus-link-edge-a.service ||
  -f ${SNAPSHOT}/active.campus-link-edge-b.service ]]; then
  systemctl is-active --quiet campus-link-topology.service
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
