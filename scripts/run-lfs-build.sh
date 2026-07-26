#!/usr/bin/env bash
set -uo pipefail

readonly BUILD_ROOT=/mnt/oslab-lfs
readonly LOG=/home/build/oslab/lfs-build.log
readonly EXIT_FILE=/home/build/oslab/lfs-build.exit
readonly SOURCE_HASHES=/home/build/oslab/LFS-SOURCE-SHA256SUMS
hash_tmp=

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
# ShellCheck cannot infer that this function is invoked by the EXIT trap.
# shellcheck disable=SC2317
finish() {
  local rc=$?
  [[ -z ${hash_tmp} ]] || rm -f -- "${hash_tmp}"
  if [[ ! -f ${EXIT_FILE} ]]; then
    {
      printf 'EXIT=%s\n' "${rc}"
      printf 'END=%s\n' "$(date -u +%FT%TZ)"
    } | tee "${EXIT_FILE}" >> "${LOG}"
  fi
}
trap finish EXIT

mapfile -t source_names < <(
  grep -RhoE \
    '[[:alnum:]_.+-]+\.(tar\.[[:alnum:]]+|patch(\.[[:alnum:]]+)?)' \
    "${BUILD_ROOT}/jhalfs/lfs-commands" | sort -u
)
if (( ${#source_names[@]} == 0 )); then
  echo 'no LFS source references were discovered' | tee -a "${LOG}" >&2
  exit 3
fi
hash_tmp=$(mktemp /home/build/oslab/.LFS-SOURCE-SHA256SUMS.XXXXXX)
for source_name in "${source_names[@]}"; do
  if [[ ! -f ${BUILD_ROOT}/sources/${source_name} ]]; then
    echo "referenced LFS source is missing: ${source_name}" | \
      tee -a "${LOG}" >&2
    exit 3
  fi
  (cd "${BUILD_ROOT}/sources" && sha256sum "${source_name}") >> "${hash_tmp}"
done
mv "${hash_tmp}" "${SOURCE_HASHES}"
hash_tmp=
printf 'SOURCE_COUNT=%s\n' "${#source_names[@]}" >> "${LOG}"

make -C "${BUILD_ROOT}/jhalfs" >> "${LOG}" 2>&1
rc=$?
{
  printf 'EXIT=%s\n' "${rc}"
  printf 'END=%s\n' "$(date -u +%FT%TZ)"
} | tee "${EXIT_FILE}" >> "${LOG}"
exit "${rc}"
