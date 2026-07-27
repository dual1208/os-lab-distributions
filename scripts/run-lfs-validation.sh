#!/usr/bin/env bash
set -uo pipefail

readonly VALIDATOR=/home/build/oslab/validate-lfs-release.sh
readonly LOG=/home/build/oslab/lfs-validation.log
readonly EXIT_FILE=/home/build/oslab/lfs-validation.exit

if [[ ${EUID} -ne 0 ]]; then
  echo 'run-lfs-validation.sh must run as root' >&2
  exit 2
fi

rm -f "${EXIT_FILE}"
printf 'START=%s\n' "$(date -u +%FT%TZ)" > "${LOG}"
"${VALIDATOR}" /srv/oslab-output >> "${LOG}" 2>&1
rc=$?
{
  printf 'EXIT=%s\n' "${rc}"
  printf 'END=%s\n' "$(date -u +%FT%TZ)"
} | tee "${EXIT_FILE}" >> "${LOG}"
exit "${rc}"
