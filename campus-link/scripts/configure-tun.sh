#!/usr/bin/env bash
set -euo pipefail

readonly NAMESPACE=${1:?usage: configure-tun.sh NAMESPACE REMOTE_PREFIX}
readonly REMOTE_PREFIX=${2:?usage: configure-tun.sh NAMESPACE REMOTE_PREFIX}
case "${NAMESPACE}:${REMOTE_PREFIX}" in
  campus-a:10.82.0.0/24|campus-b:10.81.0.0/24) ;;
  *) echo 'refusing unexpected namespace or route' >&2; exit 2 ;;
esac
for _ in {1..60}; do
  if ip -n "${NAMESPACE}" link show cl0 >/dev/null 2>&1; then
    ip -n "${NAMESPACE}" link set cl0 mtu 1280 up
    ip -n "${NAMESPACE}" route replace "${REMOTE_PREFIX}" dev cl0
    exit 0
  fi
  sleep 1
done
echo "campus-link TUN did not appear in ${NAMESPACE}" >&2
exit 1
