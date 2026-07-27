#!/usr/bin/env bash
set -uo pipefail

readonly VERIFIER=/home/build/oslab/verify-lfs-public-release.sh
readonly LOG=/home/build/oslab/lfs-public-verify.log
readonly EXIT_FILE=/home/build/oslab/lfs-public-verify.exit

if [[ ${EUID} -ne 0 ]]; then
  echo 'run-lfs-public-verification.sh must run as root' >&2
  exit 2
fi

rm -f "${EXIT_FILE}"
printf 'START=%s\n' "$(date -u +%FT%TZ)" > "${LOG}"
"${VERIFIER}" >> "${LOG}" 2>&1
rc=$?
{
  printf 'EXIT=%s\n' "${rc}"
  printf 'END=%s\n' "$(date -u +%FT%TZ)"
} | tee "${EXIT_FILE}" >> "${LOG}"
exit "${rc}"
