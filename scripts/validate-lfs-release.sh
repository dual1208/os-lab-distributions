#!/usr/bin/env bash
set -euo pipefail

readonly OUTPUT_ROOT=${1:-/srv/oslab-output}
readonly -a COMMON_EXPECTED=(
  BUILD-MANIFEST.txt
  LFS-SOURCE-SHA256SUMS
  SOURCE-SHA256SUMS
  UPSTREAMS.tsv
  initramfs-7.1.5-oslab.img
  kernel-7.1.5-oslab.config
  vmlinuz-7.1.5-oslab
)
readonly -a BUILDER_EXPECTED=(
  "${COMMON_EXPECTED[@]}"
  SHA256SUMS
  oslab-2026.07-skylake-rootfs.tar.zst
  oslab-2026.07-zen5-rootfs.tar.zst
)
readonly -a PUBLISHED_EXPECTED=(
  "${COMMON_EXPECTED[@]}"
  REASSEMBLE.md
  ROOTFS-SHA256SUMS
  SHA256SUMS
  oslab-2026.07-skylake-rootfs.tar.zst.part00
  oslab-2026.07-skylake-rootfs.tar.zst.part01
  oslab-2026.07-zen5-rootfs.tar.zst.part00
  oslab-2026.07-zen5-rootfs.tar.zst.part01
)

if [[ ! -d ${OUTPUT_ROOT} ]]; then
  echo "release directory is missing: ${OUTPUT_ROOT}" >&2
  exit 2
fi

if [[ -f ${OUTPUT_ROOT}/oslab-2026.07-zen5-rootfs.tar.zst ]]; then
  readonly MODE=builder
  EXPECTED=("${BUILDER_EXPECTED[@]}")
elif [[ -f ${OUTPUT_ROOT}/ROOTFS-SHA256SUMS ]]; then
  readonly MODE=published
  EXPECTED=("${PUBLISHED_EXPECTED[@]}")
else
  echo 'release directory is neither a builder nor published payload' >&2
  exit 3
fi

for name in "${EXPECTED[@]}"; do
  if [[ ! -f ${OUTPUT_ROOT}/${name} ]]; then
    echo "release file is missing: ${name}" >&2
    exit 3
  fi
done
if (( $(find "${OUTPUT_ROOT}" -maxdepth 1 -type f | wc -l) != ${#EXPECTED[@]} )); then
  echo 'release directory contains an unexpected file set' >&2
  exit 3
fi

pushd "${OUTPUT_ROOT}" >/dev/null
if (( $(wc -l < SHA256SUMS) != ${#EXPECTED[@]} - 1 )); then
  echo 'checksum manifest has an unexpected entry count' >&2
  exit 4
fi
for name in "${EXPECTED[@]}"; do
  [[ ${name} == SHA256SUMS ]] && continue
  grep -Eq "^[0-9a-f]{64}  ${name}$" SHA256SUMS
done
sha256sum --check --strict SHA256SUMS

stream_archive() {
  local archive=$1
  if [[ ${MODE} == builder ]]; then
    cat "${archive}"
  else
    cat "${archive}.part00" "${archive}.part01"
  fi
}

for profile in zen5 skylake; do
  archive="oslab-2026.07-${profile}-rootfs.tar.zst"
  if [[ ${MODE} == published ]]; then
    for part in "${archive}.part00" "${archive}.part01"; do
      (( $(stat -c %s "${part}") < 2147483648 ))
    done
    expected_hash=$(awk -v name="${archive}" '$2 == name { print $1 }' \
      ROOTFS-SHA256SUMS)
    actual_hash=$(stream_archive "${archive}" | sha256sum | awk '{ print $1 }')
    [[ ${actual_hash} == "${expected_hash}" ]]
  fi
  stream_archive "${archive}" | zstd --test -
  stream_archive "${archive}" | tar --zstd -tf - \
    ./etc/os-release \
    ./etc/oslab/hardware-profile \
    ./usr/share/doc/oslab/INSTALL.md \
    ./boot/vmlinuz-7.1.5-oslab \
    ./boot/initramfs-7.1.5-oslab.img >/dev/null
done
stream_archive oslab-2026.07-zen5-rootfs.tar.zst | tar --zstd -xOf - \
  ./etc/oslab/hardware-profile | grep -qx 'compiler_tune=znver5'
stream_archive oslab-2026.07-skylake-rootfs.tar.zst | tar --zstd -xOf - \
  ./etc/oslab/hardware-profile | grep -qx 'compiler_tune=skylake'

for option in \
  CONFIG_EFI CONFIG_EFI_STUB CONFIG_BLK_DEV_NVME CONFIG_SATA_AHCI \
  CONFIG_EXT4_FS CONFIG_VFAT_FS CONFIG_VIRTIO_PCI CONFIG_VIRTIO_BLK \
  CONFIG_DRM_AMDGPU CONFIG_DRM_NOUVEAU CONFIG_DRM_I915 CONFIG_E1000E \
  CONFIG_R8169 CONFIG_IWLWIFI CONFIG_SND_HDA_INTEL; do
  grep -Eq "^${option}=(y|m)$" kernel-7.1.5-oslab.config
done
if command -v lsinitrd >/dev/null 2>&1; then
  lsinitrd initramfs-7.1.5-oslab.img >/dev/null
elif [[ ${MODE} == builder ]] && [[ ${OUTPUT_ROOT} == /srv/oslab-output ]] &&
     [[ -x /mnt/oslab-lfs/usr/bin/lsinitrd ]]; then
  chroot /mnt/oslab-lfs /usr/bin/env -i \
    PATH=/usr/bin:/usr/sbin \
    /usr/bin/lsinitrd /boot/initramfs-7.1.5-oslab.img >/dev/null
else
  echo 'INITRAMFS_LISTING_SKIPPED checksum-tied-to-builder-validation'
fi

grep -q '^LINUX_VERSION=7.1.5$' BUILD-MANIFEST.txt
grep -q '^SYSTEMD_VERSION=261.2$' BUILD-MANIFEST.txt
grep -q '^PACMAN_VERSION=7.1.0$' BUILD-MANIFEST.txt
grep -q '^CPIO_VERSION=2.15$' BUILD-MANIFEST.txt
grep -q '^GNU cpio' UPSTREAMS.tsv
grep -q 'cpio-2.15.tar.bz2' SOURCE-SHA256SUMS
if grep -ERn \
  '(ghp_[A-Za-z0-9]|dop_v1_|BEGIN [A-Z ]*PRIVATE KEY|public_ipv4|private_ipv4|([0-9]{1,3}\.){3}[0-9]{1,3})' \
  BUILD-MANIFEST.txt UPSTREAMS.tsv SOURCE-SHA256SUMS \
  LFS-SOURCE-SHA256SUMS; then
  echo 'sensitive-data pattern found in release metadata' >&2
  exit 5
fi
popd >/dev/null

echo "LFS_RELEASE_VALIDATION_OK mode=${MODE} files=${#EXPECTED[@]}"
