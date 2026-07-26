#!/usr/bin/env bash
set -uo pipefail

readonly BUILD_ROOT=/mnt/oslab-lfs
readonly LOG=/home/build/oslab/lfs-build.log
readonly EXIT_FILE=/home/build/oslab/lfs-build.exit

if [[ ${EUID} -eq 0 ]]; then
  echo 'run-lfs-build.sh must run as the unprivileged build user' >&2
  exit 2
fi

if [[ ! -f ${BUILD_ROOT}/jhalfs/Makefile ]]; then
  echo 'jhalfs Makefile is missing; run setup-lfs-builder.sh first' >&2
  exit 2
fi

if ! mountpoint -q "${BUILD_ROOT}"; then
  echo "build root is not mounted: ${BUILD_ROOT}" >&2
  exit 3
fi

rm -f "${EXIT_FILE}"
printf 'START=%s\n' "$(date -u +%FT%TZ)" > "${LOG}"
make -C "${BUILD_ROOT}/jhalfs" >> "${LOG}" 2>&1
rc=$?
{
  printf 'EXIT=%s\n' "${rc}"
  printf 'END=%s\n' "$(date -u +%FT%TZ)"
} | tee "${EXIT_FILE}" >> "${LOG}"
exit "${rc}"

