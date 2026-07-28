#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly RELAY_ADDRESS=${2:?usage: install-edge-lab.sh REPO_ROOT RELAY_HOST_OR_IP}
readonly ROOT=/etc/campus-link
readonly BUILD=/srv/openwrt-lab/build/campus-link
readonly ROLLBACK=/var/lib/campus-link/rollback-edge

[[ ${EUID} -eq 0 ]]
[[ ${RELAY_ADDRESS} != *:* ]]
"${REPO_ROOT}/campus-link/scripts/build.sh" "${REPO_ROOT}"
"${REPO_ROOT}/campus-link/scripts/generate-lab-pki.sh"

version=$(<"${BUILD}/VERSION")
installed_version=$(cat /var/lib/campus-link/installed-edge-version 2>/dev/null || true)
if [[ -x /usr/local/bin/campus-link-edge && ${installed_version} != "${version}" ]]; then
  install -d -m 0700 "${ROLLBACK}"
  install -m 0755 /usr/local/bin/campus-link-edge "${ROLLBACK}/campus-link-edge"
  [[ ! -x /usr/local/bin/campus-linkctl ]] || install -m 0755 /usr/local/bin/campus-linkctl "${ROLLBACK}/campus-linkctl"
  for name in edge-a.json edge-b.json; do
    [[ ! -f ${ROOT}/${name} ]] || install -m 0600 "${ROOT}/${name}" "${ROLLBACK}/${name}"
  done
  for name in campus-link-edge-a.service campus-link-edge-b.service; do
    [[ ! -f /etc/systemd/system/${name} ]] || install -m 0644 "/etc/systemd/system/${name}" "${ROLLBACK}/${name}"
  done
  printf '%s\n' "${installed_version:-unversioned}" > "${ROLLBACK}/VERSION"
  touch "${ROLLBACK}/.complete"
fi
rollback_on_error() {
  if [[ -f ${ROLLBACK}/.complete ]]; then
    "${REPO_ROOT}/campus-link/scripts/rollback-edge.sh" || true
  fi
}
trap rollback_on_error ERR

install -d -m 0755 /usr/local/libexec /usr/local/bin "${ROOT}"
install -m 0755 "${BUILD}/campus-link-edge" /usr/local/bin/campus-link-edge
install -m 0755 "${BUILD}/campus-linkctl" /usr/local/bin/campus-linkctl
for script in topology configure-tun smoke-external restore-offline; do
  install -m 0755 "${REPO_ROOT}/campus-link/scripts/${script}.sh" "/usr/local/libexec/campus-link-${script}"
done
install -m 0755 "${REPO_ROOT}/campus-link/scripts/qualify-a11-b22.sh" /usr/local/libexec/campus-link-qualify-a11-b22
install -m 0755 "${REPO_ROOT}/campus-link/scripts/test-edge-recovery.sh" /usr/local/libexec/campus-link-test-edge-recovery
install -m 0755 "${REPO_ROOT}/campus-link/scripts/test-netem.sh" /usr/local/libexec/campus-link-test-netem
install -m 0755 "${REPO_ROOT}/campus-link/scripts/test-relay-recovery-watch.sh" /usr/local/libexec/campus-link-test-relay-recovery-watch
install -m 0755 "${REPO_ROOT}/campus-link/scripts/soak-a11-b22.sh" /usr/local/libexec/campus-link-soak-a11-b22
install -m 0755 "${REPO_ROOT}/campus-link/scripts/accelerated-fault-soak.sh" /usr/local/libexec/campus-link-accelerated-fault-soak
install -m 0755 "${REPO_ROOT}/campus-link/scripts/rollback-edge.sh" /usr/local/libexec/campus-link-rollback-edge
install -m 0755 "${REPO_ROOT}/lab/openwrt-lab-topology" /usr/local/libexec/openwrt-lab-topology
install -m 0755 "${REPO_ROOT}/lab/openwrt-lab-console-config" /usr/local/libexec/openwrt-lab-console-config
for unit in campus-link-topology.service campus-link-edge-a.service campus-link-edge-b.service campus-link-external.target; do
  install -m 0644 "${REPO_ROOT}/campus-link/systemd/${unit}" "/etc/systemd/system/${unit}"
done

generation=$(openssl rand -hex 16)
umask 077
cat > "${ROOT}/edge-a.json" <<EOF
{"site":"site-a","role":"client","generation":"${generation}","circuit":"home-pair-1","prefix":"10.81.0.0/24","remote_prefix":"10.82.0.0/24","relay_address":"${RELAY_ADDRESS}:443","control_server_name":"gz.campus-link","control_cert":"${ROOT}/pki/site-a-control.crt","control_key":"${ROOT}/pki/site-a-control.key","control_ca":"${ROOT}/pki/control-ca.crt","data_server_name":"site-b.campus-link","data_peer_name":"site-b.campus-link","data_cert":"${ROOT}/pki/site-a-data.crt","data_key":"${ROOT}/pki/site-a-data.key","data_ca":"${ROOT}/pki/data-ca.crt","tun_name":"cl0","mtu":1280,"status_path":"/run/campus-link/site-a.json"}
EOF
cat > "${ROOT}/edge-b.json" <<EOF
{"site":"site-b","role":"server","generation":"${generation}","circuit":"home-pair-1","prefix":"10.82.0.0/24","remote_prefix":"10.81.0.0/24","relay_address":"${RELAY_ADDRESS}:443","control_server_name":"gz.campus-link","control_cert":"${ROOT}/pki/site-b-control.crt","control_key":"${ROOT}/pki/site-b-control.key","control_ca":"${ROOT}/pki/control-ca.crt","data_server_name":"site-b.campus-link","data_peer_name":"site-a","data_cert":"${ROOT}/pki/site-b-data.crt","data_key":"${ROOT}/pki/site-b-data.key","data_ca":"${ROOT}/pki/data-ca.crt","tun_name":"cl0","mtu":1280,"status_path":"/run/campus-link/site-b.json"}
EOF
chmod 0600 "${ROOT}/edge-a.json" "${ROOT}/edge-b.json"
ip -n oslab-a address show dev ep-a | grep -q '10.81.0.11/24' || ip -n oslab-a address add 10.81.0.11/24 dev ep-a
ip -n oslab-b address show dev ep-b | grep -q '10.82.0.22/24' || ip -n oslab-b address add 10.82.0.22/24 dev ep-b
install -d -m 0700 /var/lib/campus-link
if [[ ! -f /var/lib/campus-link/a11-b22-firewall.complete ]]; then
  /usr/local/libexec/openwrt-lab-console-config
  touch /var/lib/campus-link/a11-b22-firewall.complete
fi
systemctl daemon-reload
systemctl enable campus-link-external.target
printf '%s\n' "${version}" > /var/lib/campus-link/installed-edge-version
trap - ERR
