#!/usr/bin/env bash
set -euo pipefail

readonly TABLE_COMMENT=campus-link
readonly WAN_A_HOST=clwan-a-host
readonly WAN_B_HOST=clwan-b-host
readonly WAN_A_ADDRESS=100.64.10.2
readonly WAN_B_ADDRESS=100.64.10.6
readonly STATE_ROOT=/run/campus-link
readonly KILL_SWITCH_METRIC=32760
readonly KILL_SWITCH_COMMENT=campus-link-private-prefix-kill-switch
readonly TCPMSS_COMMENT=campus-link-tcp-mss
readonly WAN_DEVICE_STATE=${STATE_ROOT}/wan-device

wan_device() {
  local routes device
  routes=$(ip -4 route show default) || return 1
  device=$(awk 'NR == 1 { print $5 }' <<< "${routes}") || return 1
  [[ ${device} =~ ^[A-Za-z0-9_.:-]{1,15}$ && ${device} != *$'\n'* ]] || return 1
  printf '%s\n' "${device}"
}

command_output_matches() {
  local pattern=$1 output
  shift
  output=$("$@") || return 1
  grep -- "${pattern}" <<< "${output}" >/dev/null
}

assert_route_lookup_unreachable() {
  local namespace=$1 destination=$2 output status
  if output=$(ip -n "${namespace}" route get "${destination}" 2>&1); then
    return 1
  else
    status=$?
  fi
  [[ ${status} -eq 2 && ${output} == *'Network is unreachable'* ]]
}

inventory_lacks_namespace() {
  local inventory=$1 forbidden=$2 line name
  while IFS= read -r line; do
    name=${line%%[[:space:]]*}
    [[ ${name} != "${forbidden}" ]] || return 1
  done <<< "${inventory}"
}

inventory_lacks_link() {
  local inventory=$1 forbidden=$2 line remainder name
  while IFS= read -r line; do
    [[ ${line} == *': '* ]] || return 1
    remainder=${line#*: }
    name=${remainder%%:*}
    name=${name%%@*}
    [[ ${name} != "${forbidden}" ]] || return 1
  done <<< "${inventory}"
}

delete_rule() {
  local table=$1
  shift
  while iptables -w -t "${table}" -C "$@" 2>/dev/null; do
    iptables -w -t "${table}" -D "$@"
  done
}

validate_host_forwarding_baseline() {
  local forward_value rules
  IFS= read -r forward_value < /proc/sys/net/ipv4/ip_forward || return 1
  [[ ${forward_value} == 1 ]] || {
    echo 'campus-link requires a pre-managed host IPv4 forwarding baseline' >&2
    return 1
  }
  rules=$(iptables -w -S FORWARD) || return 1
  grep -Fx -- '-P FORWARD DROP' <<< "${rules}" >/dev/null || {
    echo 'campus-link requires the host FORWARD policy to be DROP' >&2
    return 1
  }
}

down() {
  local wan wan_discovery_ok=1
  wan=''
  if [[ -f ${WAN_DEVICE_STATE} && ! -L ${WAN_DEVICE_STATE} ]]; then
    if ! wan=$(<"${WAN_DEVICE_STATE}"); then
      wan=''
      wan_discovery_ok=0
    elif [[ ! ${wan} =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; then
      wan=''
      wan_discovery_ok=0
    fi
  elif [[ -e ${WAN_DEVICE_STATE} || -L ${WAN_DEVICE_STATE} ]]; then
    wan_discovery_ok=0
  fi
  if [[ -z ${wan} ]]; then
    if ! wan=$(wan_device); then
      wan=''
      wan_discovery_ok=0
    fi
  fi
  if [[ -n ${wan} ]]; then
    delete_rule nat POSTROUTING -s "${WAN_A_ADDRESS}/32" -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
    delete_rule nat POSTROUTING -s "${WAN_B_ADDRESS}/32" -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
    delete_rule filter FORWARD -i "${WAN_A_HOST}" -s "${WAN_A_ADDRESS}/32" -o "${wan}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
    delete_rule filter FORWARD -i "${WAN_B_HOST}" -s "${WAN_B_ADDRESS}/32" -o "${wan}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
    delete_rule filter FORWARD -i "${wan}" -d "${WAN_A_ADDRESS}/32" -o "${WAN_A_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
    delete_rule filter FORWARD -i "${wan}" -d "${WAN_B_ADDRESS}/32" -o "${WAN_B_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
    # Remove the broader pre-hardening NAT rule during migration.
    delete_rule nat POSTROUTING -s 100.64.10.0/29 -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
  fi
  # Remove the broader pre-hardening filter rules during migration.
  delete_rule filter FORWARD -i "${WAN_A_HOST}" -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  delete_rule filter FORWARD -i "${WAN_B_HOST}" -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  delete_rule filter FORWARD -o "${WAN_A_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  delete_rule filter FORWARD -o "${WAN_B_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  ip netns del campus-a 2>/dev/null || true
  ip netns del campus-b 2>/dev/null || true
  ip link del "${WAN_A_HOST}" 2>/dev/null || true
  ip link del "${WAN_B_HOST}" 2>/dev/null || true
  ip link del br-campus-a 2>/dev/null || true
  ip link del br-campus-b 2>/dev/null || true
  rm -f "${STATE_ROOT}"/site-a.json "${STATE_ROOT}"/site-a.json.tmp \
    "${STATE_ROOT}"/site-b.json "${STATE_ROOT}"/site-b.json.tmp \
    "${STATE_ROOT}"/external-smoke.status "${STATE_ROOT}"/allowed-http.log \
    "${STATE_ROOT}"/blocked-http.log "${WAN_DEVICE_STATE}"
  rm -rf -- "${STATE_ROOT}/site-a" "${STATE_ROOT}/site-b"
  rmdir "${STATE_ROOT}" 2>/dev/null || true
  (( wan_discovery_ok == 1 ))
}

make_edge() {
  local ns=$1 transit_ns=$2 transit_host=$3 bridge=$4 transit_ip=$5 local_prefix=$6
  local remote_prefix=$7 wan_ns=$8 wan_host=$9 wan_ip=${10} wan_gateway=${11}
  local service_user=${12} status_dir=${13} scope service_uid route_line sysctl_value
  service_uid=$(id -u "${service_user}") || return 1
  [[ ${service_uid} =~ ^[0-9]+$ ]]
  install -d -m 0750 -o "${service_user}" -g "${service_user}" "${STATE_ROOT}/${status_dir}"
  ip netns add "${ns}"
  ip netns exec "${ns}" sysctl -q -w net.ipv4.ip_forward=0
  # Switching host->router mode resets per-interface IPv4 policy. Do it while
  # the namespace has no connected links, then apply the hardened values once.
  ip netns exec "${ns}" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.all.accept_source_route=0
  ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.default.accept_source_route=0
  ip -n "${ns}" link set lo up
  ip link add "${transit_ns}" type veth peer name "${transit_host}"
  ip link set "${transit_ns}" netns "${ns}"
  ip link set "${transit_host}" master "${bridge}"
  ip link set "${transit_host}" up
  ip -n "${ns}" address add "${transit_ip}" dev "${transit_ns}"
  ip -n "${ns}" link set "${transit_ns}" up
  ip -n "${ns}" route add "${local_prefix}" via "${transit_ip%.*}.1"
  ip link add "${wan_host}" type veth peer name "${wan_ns}"
  ip link set "${wan_ns}" netns "${ns}"
  ip address add "${wan_gateway}/30" dev "${wan_host}"
  ip link set "${wan_host}" up
  ip -n "${ns}" address add "${wan_ip}/30" dev "${wan_ns}"
  ip -n "${ns}" link set "${wan_ns}" up
  ip netns exec "${ns}" ip tuntap add dev cl0 mode tun user "${service_uid}"
  ip -n "${ns}" link set cl0 mtu 1200 up
  ip -n "${ns}" route add unreachable "${remote_prefix}" metric "${KILL_SWITCH_METRIC}"
  ip netns exec "${ns}" iptables -w -I OUTPUT 1 -d "${remote_prefix}" -o "${wan_ns}" \
    -m comment --comment "${KILL_SWITCH_COMMENT}" -j REJECT
  ip netns exec "${ns}" iptables -w -I FORWARD 1 -d "${remote_prefix}" -o "${wan_ns}" \
    -m comment --comment "${KILL_SWITCH_COMMENT}" -j REJECT
  ip netns exec "${ns}" iptables -w -t mangle -I FORWARD 1 -d "${remote_prefix}" \
    -o cl0 -p tcp --tcp-flags SYN,RST SYN -m comment --comment "${TCPMSS_COMMENT}" \
    -j TCPMSS --clamp-mss-to-pmtu
  for scope in all default lo "${transit_ns}" "${wan_ns}" cl0; do
    ip netns exec "${ns}" sysctl -q -w "net.ipv4.conf.${scope}.accept_source_route=0"
    sysctl_value=$(ip netns exec "${ns}" sysctl -n "net.ipv4.conf.${scope}.accept_source_route") || return 1
    [[ ${sysctl_value} == 0 ]]
  done
  sysctl_value=$(ip netns exec "${ns}" sysctl -n net.ipv4.ip_forward) || return 1
  [[ ${sysctl_value} == 1 ]]
  command_output_matches "^unreachable ${remote_prefix//./\\.} .*metric ${KILL_SWITCH_METRIC}( |$)" \
    ip -n "${ns}" route show type unreachable "${remote_prefix}"
  ip netns exec "${ns}" iptables -w -C OUTPUT -d "${remote_prefix}" -o "${wan_ns}" \
    -m comment --comment "${KILL_SWITCH_COMMENT}" -j REJECT
  ip netns exec "${ns}" iptables -w -C FORWARD -d "${remote_prefix}" -o "${wan_ns}" \
    -m comment --comment "${KILL_SWITCH_COMMENT}" -j REJECT
  ip netns exec "${ns}" iptables -w -t mangle -C FORWARD -d "${remote_prefix}" \
    -o cl0 -p tcp --tcp-flags SYN,RST SYN -m comment --comment "${TCPMSS_COMMENT}" \
    -j TCPMSS --clamp-mss-to-pmtu
  ip -n "${ns}" route add default via "${wan_gateway}"
  assert_route_lookup_unreachable "${ns}" "${remote_prefix%/*}"
  ip -n "${ns}" route add "${remote_prefix}" dev cl0 metric 10 mtu 1200
  command_output_matches ' dev cl0 ' ip -n "${ns}" route get "${remote_prefix%/*}"
  route_line=$(ip -n "${ns}" route show "${remote_prefix}") || return 1
  grep ' dev cl0 ' <<< " ${route_line} " >/dev/null
  grep -E '(^| )metric 10( |$)' <<< "${route_line}" >/dev/null
  grep -E '(^| )mtu 1200( |$)' <<< "${route_line}" >/dev/null
  command_output_matches "^unreachable ${remote_prefix//./\\.} .*metric ${KILL_SWITCH_METRIC}( |$)" \
    ip -n "${ns}" route show type unreachable "${remote_prefix}"
}

failed_up() {
  local status=$?
  trap - ERR
  set +e
  down
  set -e
  exit "${status}"
}

up() {
  local wan namespace_inventory link_inventory sysctl_value
  trap failed_up ERR
  wan=$(wan_device) || return 1
  [[ -n ${wan} ]]
  command -v iptables >/dev/null
  validate_host_forwarding_baseline
  down
  install -d -m 0755 "${STATE_ROOT}"
  printf '%s\n' "${wan}" > "${WAN_DEVICE_STATE}"
  chmod 0600 "${WAN_DEVICE_STATE}"

  # Preserve both QEMU routers and bridges. A campus-mode baseline must never
  # create this plaintext relay; these removals also make an older baseline
  # fail closed during migration.
  ip netns del oslab-relay 2>/dev/null || true
  ip link del br-relay-a 2>/dev/null || true
  ip link del br-relay-b 2>/dev/null || true
  namespace_inventory=$(ip netns list) || return 1
  inventory_lacks_namespace "${namespace_inventory}" oslab-relay
  link_inventory=$(ip -o link show) || return 1
  inventory_lacks_link "${link_inventory}" br-relay-a
  inventory_lacks_link "${link_inventory}" br-relay-b
  make_edge campus-a cl-a-transit br-campus-a br-a-transit 172.31.1.2/30 \
    10.81.0.0/24 10.82.0.0/24 cl-a-wan "${WAN_A_HOST}" 100.64.10.2 100.64.10.1 \
    campus-link-a site-a
  make_edge campus-b cl-b-transit br-campus-b br-b-transit 172.31.2.2/30 \
    10.82.0.0/24 10.81.0.0/24 cl-b-wan "${WAN_B_HOST}" 100.64.10.6 100.64.10.5 \
    campus-link-b site-b
  iptables -w -I FORWARD 1 -i "${WAN_A_HOST}" -s "${WAN_A_ADDRESS}/32" -o "${wan}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -I FORWARD 1 -i "${WAN_B_HOST}" -s "${WAN_B_ADDRESS}/32" -o "${wan}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -I FORWARD 1 -i "${wan}" -d "${WAN_A_ADDRESS}/32" -o "${WAN_A_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -I FORWARD 1 -i "${wan}" -d "${WAN_B_ADDRESS}/32" -o "${WAN_B_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -t nat -I POSTROUTING 1 -s "${WAN_A_ADDRESS}/32" -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
  iptables -w -t nat -I POSTROUTING 1 -s "${WAN_B_ADDRESS}/32" -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
  iptables -w -C FORWARD -i "${WAN_A_HOST}" -s "${WAN_A_ADDRESS}/32" -o "${wan}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -C FORWARD -i "${WAN_B_HOST}" -s "${WAN_B_ADDRESS}/32" -o "${wan}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -C FORWARD -i "${wan}" -d "${WAN_A_ADDRESS}/32" -o "${WAN_A_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -C FORWARD -i "${wan}" -d "${WAN_B_ADDRESS}/32" -o "${WAN_B_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -t nat -C POSTROUTING -s "${WAN_A_ADDRESS}/32" -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
  iptables -w -t nat -C POSTROUTING -s "${WAN_B_ADDRESS}/32" -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
  for host_veth in "${WAN_A_HOST}" "${WAN_B_HOST}"; do
    for setting in accept_source_route accept_redirects send_redirects; do
      sysctl -q -w "net.ipv4.conf.${host_veth}.${setting}=0"
      sysctl_value=$(sysctl -n "net.ipv4.conf.${host_veth}.${setting}") || return 1
      [[ ${sysctl_value} == 0 ]]
    done
  done
  trap - ERR
}

case ${1:-} in
  up) up ;;
  down) down ;;
  *) echo 'usage: topology.sh up|down' >&2; exit 2 ;;
esac
