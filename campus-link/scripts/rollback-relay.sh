#!/usr/bin/env bash
set -euo pipefail

readonly BACKUP=/var/lib/campus-link/rollback-relay
readonly ROOT=/etc/campus-link
[[ ${EUID} -eq 0 ]]
[[ -f ${BACKUP}/.complete && -x ${BACKUP}/campus-link-relay ]]
systemctl stop campus-link-relay.service
install -m 0755 "${BACKUP}/campus-link-relay" /usr/local/bin/campus-link-relay
[[ ! -f ${BACKUP}/relay.json ]] || install -m 0640 -o root -g campus-link "${BACKUP}/relay.json" "${ROOT}/relay.json"
[[ ! -f ${BACKUP}/campus-link-relay.service ]] || install -m 0644 "${BACKUP}/campus-link-relay.service" /etc/systemd/system/campus-link-relay.service
[[ ! -f ${BACKUP}/control-ca.crt ]] || install -m 0644 "${BACKUP}/control-ca.crt" "${ROOT}/pki/control-ca.crt"
[[ ! -f ${BACKUP}/relay-control.crt ]] || install -m 0644 "${BACKUP}/relay-control.crt" "${ROOT}/pki/relay-control.crt"
[[ ! -f ${BACKUP}/relay-control.key ]] || install -m 0640 -o root -g campus-link "${BACKUP}/relay-control.key" "${ROOT}/pki/relay-control.key"
install -d -m 0700 /var/lib/campus-link
install -m 0600 "${BACKUP}/VERSION" /var/lib/campus-link/installed-relay-version
systemctl daemon-reload
systemctl restart campus-link-relay.service
systemctl is-active --quiet campus-link-relay.service
