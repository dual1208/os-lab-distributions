#!/usr/bin/env bash
set -euo pipefail

readonly BACKUP=/var/lib/campus-link/rollback-edge
[[ ${EUID} -eq 0 ]]
[[ -f ${BACKUP}/.complete && -x ${BACKUP}/campus-link-edge ]]
systemctl stop campus-link-edge-a.service campus-link-edge-b.service
install -m 0755 "${BACKUP}/campus-link-edge" /usr/local/bin/campus-link-edge
[[ ! -x ${BACKUP}/campus-linkctl ]] || install -m 0755 "${BACKUP}/campus-linkctl" /usr/local/bin/campus-linkctl
for name in edge-a.json edge-b.json; do
  [[ ! -f ${BACKUP}/${name} ]] || install -m 0600 "${BACKUP}/${name}" "/etc/campus-link/${name}"
done
for name in campus-link-edge-a.service campus-link-edge-b.service; do
  [[ ! -f ${BACKUP}/${name} ]] || install -m 0644 "${BACKUP}/${name}" "/etc/systemd/system/${name}"
done
install -d -m 0700 /var/lib/campus-link
install -m 0600 "${BACKUP}/VERSION" /var/lib/campus-link/installed-edge-version
systemctl daemon-reload
systemctl restart campus-link-edge-a.service campus-link-edge-b.service
systemctl is-active --quiet campus-link-edge-a.service campus-link-edge-b.service
