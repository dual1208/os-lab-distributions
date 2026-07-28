#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=/srv/openwrt-lab/repo
if [[ ${EUID} -ne 0 ]]; then
  echo 'install-openwrt-lab.sh must run as root' >&2
  exit 2
fi
grep -qx 'EXIT=0' /srv/openwrt-lab/build/x86-lab-build.exit
install -d -m 0755 /usr/local/libexec
for name in openwrt-lab-start openwrt-lab-stop openwrt-lab-topology \
  openwrt-lab-console-config openwrt-lab-smoke openwrt-lab-reset \
  openwrt-lab-status; do
  install -m 0755 "${REPO_ROOT}/lab/${name}" "/usr/local/libexec/${name}"
done
install -m 0644 "${REPO_ROOT}/lab/openwrt-lab.service" /etc/systemd/system/openwrt-lab.service
systemctl daemon-reload
systemctl enable --now openwrt-lab.service
systemctl is-active openwrt-lab.service
