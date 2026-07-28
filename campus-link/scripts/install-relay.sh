#!/usr/bin/env bash
set -euo pipefail

readonly STAGE=${1:?usage: install-relay.sh STAGING_DIRECTORY}
readonly ROOT=/etc/campus-link

[[ ${EUID} -eq 0 ]]
if ss -H -ltn '( sport = :443 )' | grep -q . || ss -H -lun '( sport = :443 )' | grep -q .; then
  echo 'TCP or UDP port 443 is already owned; refusing installation.' >&2
  exit 3
fi
for required in campus-link-relay relay-control.crt relay-control.key control-ca.crt; do
  [[ -s ${STAGE}/${required} ]]
done
if find "${STAGE}" -maxdepth 1 -type f \( -name '*data*' -o -name 'site-*' -o -name '*-ca.key' \) | grep -q .; then
  echo 'Data-plane or CA-signing private material found in relay stage.' >&2
  exit 4
fi

getent group campus-link >/dev/null || groupadd --system campus-link
id -u campus-link >/dev/null 2>&1 || useradd --system --gid campus-link --home-dir /nonexistent --shell /usr/sbin/nologin campus-link
install -d -m 0750 -o root -g campus-link "${ROOT}/pki"
install -m 0755 "${STAGE}/campus-link-relay" /usr/local/bin/campus-link-relay
install -m 0644 "${STAGE}/control-ca.crt" "${ROOT}/pki/control-ca.crt"
install -m 0644 "${STAGE}/relay-control.crt" "${ROOT}/pki/relay-control.crt"
install -m 0640 -o root -g campus-link "${STAGE}/relay-control.key" "${ROOT}/pki/relay-control.key"
cat > "${ROOT}/relay.json" <<EOF
{"control_listen":":443","udp_listen":":443","control_cert":"${ROOT}/pki/relay-control.crt","control_key":"${ROOT}/pki/relay-control.key","control_ca":"${ROOT}/pki/control-ca.crt","circuit":"home-pair-1","prefixes":{"site-a":"10.81.0.0/24","site-b":"10.82.0.0/24"},"status_path":"/run/campus-link/status.json"}
EOF
chmod 0640 "${ROOT}/relay.json"
chown root:campus-link "${ROOT}/relay.json"
install -m 0644 "${STAGE}/campus-link-relay.service" /etc/systemd/system/campus-link-relay.service
systemctl daemon-reload
systemctl enable --now campus-link-relay.service
systemctl is-active --quiet campus-link-relay.service
