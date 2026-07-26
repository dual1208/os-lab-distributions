#!/usr/bin/env bash
set -uo pipefail

readonly FINALIZER=/home/build/oslab/finalize-lfs.sh
readonly LOG=/home/build/oslab/lfs-finalize.log
readonly EXIT_FILE=/home/build/oslab/lfs-finalize.exit

if [[ ${EUID} -ne 0 ]]; then
  echo 'run-lfs-finalize.sh must run as root' >&2
  exit 2
fi

rm -f "${EXIT_FILE}"
printf 'START=%s\n' "$(date -u +%FT%TZ)" > "${LOG}"
"${FINALIZER}" >> "${LOG}" 2>&1
rc=$?
{
  printf 'EXIT=%s\n' "${rc}"
  printf 'END=%s\n' "$(date -u +%FT%TZ)"
} | tee "${EXIT_FILE}" >> "${LOG}"
exit "${rc}"
