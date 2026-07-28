#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly DURATION=${2:-3600}
readonly RESULT=/run/campus-link/accelerated-fault-soak.result
[[ ${DURATION} =~ ^[0-9]+$ && ${DURATION} -ge 3600 ]]
while systemctl is-active --quiet campus-link-full-qualification.service && \
      [[ ! -f /run/campus-link/a11-b22-full.result ]]; do
  sleep 60
done
[[ -f /run/campus-link/a11-b22-full.result ]]
rm -f "${RESULT}"
started=$(date +%s)
deadline=$((started + DURATION))
cycles=0
trials=0

while (( $(date +%s) < deadline )); do
  /usr/local/libexec/campus-link-test-edge-recovery "${REPO_ROOT}" full
  cycles=$((cycles + 1))
  trials=$((trials + 30))
done

elapsed=$(( $(date +%s) - started ))
printf 'STATUS=pass\nDURATION_SECONDS=%s\nCYCLES=%s\nEDGE_KILL_TRIALS=%s\n' \
  "${elapsed}" "${cycles}" "${trials}" > "${RESULT}"
cat "${RESULT}"
