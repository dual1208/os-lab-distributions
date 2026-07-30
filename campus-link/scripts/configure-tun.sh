#!/usr/bin/env bash
set -euo pipefail

readonly NAMESPACE=${1:?usage: configure-tun.sh NAMESPACE REMOTE_PREFIX}
readonly REMOTE_PREFIX=${2:?usage: configure-tun.sh NAMESPACE REMOTE_PREFIX}
readonly KILL_SWITCH_METRIC=32760
readonly KILL_SWITCH_COMMENT=campus-link-private-prefix-kill-switch
readonly TCPMSS_COMMENT=campus-link-tcp-mss
case "${NAMESPACE}:${REMOTE_PREFIX}" in
  campus-a:10.82.0.0/24) WAN_DEVICE=cl-a-wan; TRANSIT_DEVICE=cl-a-transit; REMOTE_PROBE=10.82.0.1 ;;
  campus-b:10.81.0.0/24) WAN_DEVICE=cl-b-wan; TRANSIT_DEVICE=cl-b-transit; REMOTE_PROBE=10.81.0.1 ;;
  *) echo 'refusing unexpected namespace or route' >&2; exit 2 ;;
esac
readonly WAN_DEVICE TRANSIT_DEVICE REMOTE_PROBE
route_line=

ip -n "${NAMESPACE}" route show type unreachable "${REMOTE_PREFIX}" | \
  grep -Eq "^unreachable ${REMOTE_PREFIX//./\\.} .*metric ${KILL_SWITCH_METRIC}( |$)"
ip netns exec "${NAMESPACE}" iptables -w -C OUTPUT -d "${REMOTE_PREFIX}" \
  -o "${WAN_DEVICE}" -m comment --comment "${KILL_SWITCH_COMMENT}" -j REJECT
ip netns exec "${NAMESPACE}" iptables -w -C FORWARD -d "${REMOTE_PREFIX}" \
  -o "${WAN_DEVICE}" -m comment --comment "${KILL_SWITCH_COMMENT}" -j REJECT
ip netns exec "${NAMESPACE}" iptables -w -t mangle -C FORWARD -d "${REMOTE_PREFIX}" \
  -o cl0 -p tcp --tcp-flags SYN,RST SYN -m comment --comment "${TCPMSS_COMMENT}" \
  -j TCPMSS --clamp-mss-to-pmtu
for _ in {1..50}; do
  if ip -n "${NAMESPACE}" link show cl0 >/dev/null 2>&1; then
    for scope in all default lo cl0 "${TRANSIT_DEVICE}" "${WAN_DEVICE}"; do
      [[ $(ip netns exec "${NAMESPACE}" sysctl -n "net.ipv4.conf.${scope}.accept_source_route") == 0 ]] || {
        echo "IPv4 source routing is not disabled for ${NAMESPACE}/${scope}" >&2
        exit 1
      }
    done
    [[ $(ip netns exec "${NAMESPACE}" sysctl -n net.ipv4.ip_forward) == 1 ]] || {
      echo "IPv4 forwarding is not enabled for ${NAMESPACE}" >&2
      exit 1
    }
    ip -n "${NAMESPACE}" link show cl0 | grep -q 'mtu 1200'
    route_line=$(ip -n "${NAMESPACE}" route show "${REMOTE_PREFIX}")
    grep -q ' dev cl0 ' <<< " ${route_line} "
    grep -Eq '(^| )metric 10( |$)' <<< "${route_line}"
    grep -Eq '(^| )mtu 1200( |$)' <<< "${route_line}"
    ip -n "${NAMESPACE}" route get "${REMOTE_PROBE}" | grep -q ' dev cl0 '
    ip -n "${NAMESPACE}" route show type unreachable "${REMOTE_PREFIX}" | \
      grep -Eq "^unreachable ${REMOTE_PREFIX//./\\.} .*metric ${KILL_SWITCH_METRIC}( |$)"
    exit 0
  fi
  sleep 0.2
done
echo "campus-link TUN did not appear in ${NAMESPACE}" >&2
exit 1
