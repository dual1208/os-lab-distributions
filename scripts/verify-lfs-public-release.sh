#!/usr/bin/env bash
set -euo pipefail

readonly OUTPUT=/srv/oslab-public-verify
readonly PACKAGED=/srv/oslab-release
readonly BASE_URL=https://github.com/dual1208/os-lab-distributions/releases/download/oslab-2026.07
readonly -a EXPECTED=(
  BUILD-MANIFEST.txt
  LFS-SOURCE-SHA256SUMS
  REASSEMBLE.md
  ROOTFS-SHA256SUMS
  SHA256SUMS
  SOURCE-SHA256SUMS
  UPSTREAMS.tsv
  initramfs-7.1.5-oslab.img
  kernel-7.1.5-oslab.config
  oslab-2026.07-skylake-rootfs.tar.zst.part00
  oslab-2026.07-skylake-rootfs.tar.zst.part01
  oslab-2026.07-zen5-rootfs.tar.zst.part00
  oslab-2026.07-zen5-rootfs.tar.zst.part01
  vmlinuz-7.1.5-oslab
)

if [[ ${EUID} -ne 0 ]]; then
  echo 'verify-lfs-public-release.sh must run as root' >&2
  exit 2
fi
grep -qx 'EXIT=0' /home/build/oslab/lfs-packaging.exit
[[ ${OUTPUT} == /srv/oslab-public-verify ]]
install -d -m 0755 "${OUTPUT}"

curl --fail --location --retry 5 --retry-all-errors --connect-timeout 20 \
  --output "${OUTPUT}/SHA256SUMS.new" "${BASE_URL}/SHA256SUMS"
cmp "${PACKAGED}/SHA256SUMS" "${OUTPUT}/SHA256SUMS.new"
mv -f "${OUTPUT}/SHA256SUMS.new" "${OUTPUT}/SHA256SUMS"

for name in "${EXPECTED[@]}"; do
  [[ ${name} == SHA256SUMS ]] && continue
  expected_hash=$(awk -v file="${name}" '$2 == file { print $1 }' \
    "${OUTPUT}/SHA256SUMS")
  [[ ${#expected_hash} -eq 64 ]]
  path="${OUTPUT}/${name}"
  if [[ -f ${path} ]] &&
     [[ $(sha256sum "${path}" | awk '{ print $1 }') == "${expected_hash}" ]]; then
    echo "PUBLIC_SKIP=${name}"
    continue
  fi
  if ! curl --fail --location --retry 5 --retry-all-errors \
      --connect-timeout 20 --continue-at - --output "${path}" \
      "${BASE_URL}/${name}"; then
    echo "public download interrupted: ${name}" >&2
    exit 4
  fi
  actual_hash=$(sha256sum "${path}" | awk '{ print $1 }')
  if [[ ${actual_hash} != "${expected_hash}" ]]; then
    rm -f -- "${path}"
    echo "public asset checksum mismatch: ${name}" >&2
    exit 5
  fi
  echo "PUBLIC_DOWNLOADED=${name}"
done

if (( $(find "${OUTPUT}" -maxdepth 1 -type f | wc -l) != ${#EXPECTED[@]} )); then
  echo 'public verification directory has an unexpected file set' >&2
  exit 6
fi
/home/build/oslab/validate-lfs-release.sh "${OUTPUT}"
echo "LFS_PUBLIC_RELEASE_VERIFIED assets=${#EXPECTED[@]}"
