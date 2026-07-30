#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]]
exec 9>/run/campus-link-install-edge.lock
flock -n 9 || {
  echo 'Refusing offline restore while deployment or qualification holds the campus-link lock.' >&2
  exit 5
}
for unit in \
  campus-link-qualification-chain.service \
  campus-link-full-qualification.service \
  campus-link-accelerated-fault.service \
  campus-link-fault-in-stream.service \
  campus-link-nat-rebinding.service \
  campus-link-24h-soak.service \
  campus-link-7d-burn-in.service; do
  ! systemctl is-active --quiet "${unit}" || {
    echo "Refusing offline restore while ${unit} is active." >&2
    exit 6
  }
done
systemctl disable --now campus-link-external.target
rm -f -- \
  /run/campus-link/qualification-run.manifest \
  /run/campus-link/a11-b22-full.result \
  /run/campus-link/accelerated-fault-soak.result \
  /run/campus-link/fault-in-stream.result \
  /run/campus-link/nat-rebinding.result \
  /run/campus-link/a11-b22-soak-24-hour.result \
  /run/campus-link/a11-b22-soak-24-hour.failure \
  /run/campus-link/a11-b22-soak-seven-day.result \
  /run/campus-link/a11-b22-soak-seven-day.failure
rm -f -- /var/lib/campus-link/router-only.enabled
systemctl restart openwrt-lab.service
systemctl is-active --quiet openwrt-lab.service
grep -qx 'STATUS=pass' /run/openwrt-lab/smoke.status
grep -qx 'MODE=plaintext' /run/openwrt-lab/smoke.status
