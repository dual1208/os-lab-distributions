#!/usr/bin/env bash
set -euo pipefail

readonly TABLE_COMMENT=campus-link
readonly WAN_A_HOST=clwan-a-host
readonly WAN_B_HOST=clwan-b-host
readonly STATE_ROOT=/run/campus-link

wan_device() {
  ip -4 route show default | awk 'NR == 1 { print $5 }'
}

delete_rule() {
  local table=$1
  shift
  while iptables -w -t "${table}" -C "$@" 2>/dev/null; do
    iptables -w -t "${table}" -D "$@"
  done
}

down() {
  local wan prior_forwarding
  wan=$(wan_device || true)
  if [[ -n ${wan} ]]; then
    delete_rule nat POSTROUTING -s 100.64.10.0/29 -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
  fi
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
  if [[ -s ${STATE_ROOT}/ip_forward.before ]]; then
    prior_forwarding=$(<"${STATE_ROOT}/ip_forward.before")
    [[ ${prior_forwarding} == 0 || ${prior_forwarding} == 1 ]]
    sysctl -q -w "net.ipv4.ip_forward=${prior_forwarding}"
  fi
  rm -f "${STATE_ROOT}"/site-a.json "${STATE_ROOT}"/site-a.json.tmp \
    "${STATE_ROOT}"/site-b.json "${STATE_ROOT}"/site-b.json.tmp \
    "${STATE_ROOT}"/external-smoke.status "${STATE_ROOT}"/allowed-http.log \
    "${STATE_ROOT}"/blocked-http.log "${STATE_ROOT}"/ip_forward.before
  rmdir "${STATE_ROOT}" 2>/dev/null || true
}

make_edge() {
  local ns=$1 transit_ns=$2 transit_host=$3 bridge=$4 transit_ip=$5 local_prefix=$6
  local wan_ns=$7 wan_host=$8 wan_ip=$9 wan_gateway=${10}
  ip netns add "${ns}"
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
  ip -n "${ns}" route add default via "${wan_gateway}"
}

up() {
  local wan
  wan=$(wan_device)
  [[ -n ${wan} ]]
  command -v iptables >/dev/null
  down
  install -d -m 0755 "${STATE_ROOT}"
  cat /proc/sys/net/ipv4/ip_forward > "${STATE_ROOT}/ip_forward.before"

  # Preserve both QEMU routers and bridges; replace only the plaintext relay.
  ip netns del oslab-relay 2>/dev/null || true
  make_edge campus-a cl-a-transit br-campus-a br-a-transit 172.31.1.2/30 10.81.0.0/24 cl-a-wan "${WAN_A_HOST}" 100.64.10.2 100.64.10.1
  make_edge campus-b cl-b-transit br-campus-b br-b-transit 172.31.2.2/30 10.82.0.0/24 cl-b-wan "${WAN_B_HOST}" 100.64.10.6 100.64.10.5
  sysctl -q -w net.ipv4.ip_forward=1
  iptables -w -I FORWARD 1 -i "${WAN_A_HOST}" -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -I FORWARD 1 -i "${WAN_B_HOST}" -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -I FORWARD 1 -o "${WAN_A_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -I FORWARD 1 -o "${WAN_B_HOST}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${TABLE_COMMENT}" -j ACCEPT
  iptables -w -t nat -I POSTROUTING 1 -s 100.64.10.0/29 -o "${wan}" -m comment --comment "${TABLE_COMMENT}" -j MASQUERADE
}

case ${1:-} in
  up) up ;;
  down) down ;;
  *) echo 'usage: topology.sh up|down' >&2; exit 2 ;;
esac
