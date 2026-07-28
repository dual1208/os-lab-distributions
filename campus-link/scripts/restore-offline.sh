#!/usr/bin/env bash
set -euo pipefail

systemctl disable --now campus-link-external.target
systemctl restart openwrt-lab.service
systemctl is-active --quiet openwrt-lab.service
grep -qx 'STATUS=pass' /run/openwrt-lab/smoke.status
