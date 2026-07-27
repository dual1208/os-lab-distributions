#!/usr/bin/env bash
set -euo pipefail

readonly BUILD_USER=build
readonly BUILD_ROOT=/mnt/oslab-lfs
readonly BUILD_IMAGE=/srv/oslab-lfs13.img
readonly SOURCE_ARCHIVE=/srv/oslab-lfs-sources
readonly TOOLING_ROOT=/home/build/oslab
readonly JHALFS_ROOT=/home/build/jhalfs-src
readonly JHALFS_COMMIT=476870cd636d37a80629decbcfd8743563261a67
readonly LFS_BOOK_COMMIT=1c2eb20b24b7131dd6f08b6e2eb70f740f3d1054
readonly LINUX_VERSION=7.1.3

if [[ ${EUID} -ne 0 ]]; then
  echo 'setup-lfs-builder.sh must run as root' >&2
  exit 2
fi

case ${BUILD_ROOT} in
  /|/home|/root|/srv) echo "unsafe build root: ${BUILD_ROOT}" >&2; exit 2 ;;
esac

id "${BUILD_USER}" >/dev/null 2>&1 || {
  echo "required user is missing: ${BUILD_USER}" >&2
  exit 2
}

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  bc bison build-essential cpio docbook-xml docbook-xsl flex gawk git \
  libssl-dev libxml2-utils libxslt1-dev meson ninja-build pkg-config \
  python3 qemu-system-x86 rsync sudo texinfo tmux wget xsltproc xz-utils zstd

install -d -m 0755 /srv
install -d -o "${BUILD_USER}" -g "${BUILD_USER}" -m 0755 \
  "${BUILD_ROOT}" "${SOURCE_ARCHIVE}" "${TOOLING_ROOT}"
if [[ ! -f ${BUILD_IMAGE} ]]; then
  truncate -s 64G "${BUILD_IMAGE}"
  mkfs.ext4 -F -L oslab-root "${BUILD_IMAGE}"
fi

if ! mountpoint -q "${BUILD_ROOT}"; then
  mount -o loop "${BUILD_IMAGE}" "${BUILD_ROOT}"
fi

if [[ $(findmnt -rn -o SOURCE -T "${BUILD_ROOT}") != /dev/loop* ]]; then
  echo "refusing unexpected filesystem at ${BUILD_ROOT}" >&2
  exit 3
fi

if ! grep -Fq "${BUILD_IMAGE} ${BUILD_ROOT} ext4 loop,defaults 0 0" /etc/fstab; then
  printf '%s %s ext4 loop,defaults 0 0\n' "${BUILD_IMAGE}" "${BUILD_ROOT}" >> /etc/fstab
fi

install -m 0440 /dev/stdin /etc/sudoers.d/oslab-build <<'EOF'
build ALL=(ALL:ALL) NOPASSWD: ALL
EOF

if [[ ! -d ${JHALFS_ROOT}/.git ]]; then
  sudo -u "${BUILD_USER}" git clone \
    https://git.linuxfromscratch.org/jhalfs.git "${JHALFS_ROOT}"
fi
sudo -u "${BUILD_USER}" git -C "${JHALFS_ROOT}" fetch --tags origin
sudo -u "${BUILD_USER}" git -C "${JHALFS_ROOT}" \
  checkout --detach "${JHALFS_COMMIT}"

readonly LINUX_ARCHIVE="${SOURCE_ARCHIVE}/linux-${LINUX_VERSION}.tar.xz"
if [[ ! -f ${LINUX_ARCHIVE} ]]; then
  wget -O "${LINUX_ARCHIVE}" \
    "https://www.kernel.org/pub/linux/kernel/v7.x/linux-${LINUX_VERSION}.tar.xz"
fi

readonly KERNEL_WORK
KERNEL_WORK=$(mktemp -d /tmp/oslab-kernel-config.XXXXXX)
trap 'rm -rf -- "${KERNEL_WORK}"' EXIT
tar -xf "${LINUX_ARCHIVE}" -C "${KERNEL_WORK}"
cp "/boot/config-$(uname -r)" "${KERNEL_WORK}/linux-${LINUX_VERSION}/.config"
pushd "${KERNEL_WORK}/linux-${LINUX_VERSION}" >/dev/null
scripts/config --set-str LOCALVERSION '-oslab'
scripts/config --set-str SYSTEM_TRUSTED_KEYS ''
scripts/config --set-str SYSTEM_REVOCATION_KEYS ''
scripts/config --disable MODULE_SIG_ALL
scripts/config --disable DEBUG_INFO_BTF
scripts/config --disable GCC_PLUGINS
scripts/config --enable EFI
scripts/config --enable EFI_STUB
scripts/config --enable BLK_DEV_NVME
scripts/config --enable SATA_AHCI
scripts/config --enable EXT4_FS
scripts/config --enable VFAT_FS
scripts/config --enable VIRTIO
scripts/config --enable VIRTIO_PCI
scripts/config --enable VIRTIO_BLK
scripts/config --enable DRM_AMDGPU
scripts/config --enable DRM_NOUVEAU
scripts/config --enable DRM_I915
scripts/config --module DRM_ACCEL_AMDXDNA
scripts/config --module E1000E
scripts/config --module R8169
scripts/config --module IWLWIFI
scripts/config --module IWLMVM
scripts/config --module MT7921E
scripts/config --module RTW88
scripts/config --module RTW89
scripts/config --module ATH10K
scripts/config --module ATH11K
scripts/config --module SND_HDA_INTEL
make olddefconfig </dev/null
cp .config "${TOOLING_ROOT}/kernel-7.1.3-bootstrap.config"
popd >/dev/null

cat > "${TOOLING_ROOT}/fstab" <<'EOF'
# Replace or confirm these labels before installing on physical hardware.
LABEL=oslab-root / ext4 defaults 1 1
proc /proc proc nosuid,noexec,nodev 0 0
sysfs /sys sysfs nosuid,noexec,nodev 0 0
devpts /dev/pts devpts gid=5,mode=620 0 0
tmpfs /run tmpfs defaults 0 0
devtmpfs /dev devtmpfs mode=0755,nosuid 0 0
EOF

cat > "${TOOLING_ROOT}/generate-jhalfs-config.py" <<'PY'
import os
import sys

repo = "/home/build/jhalfs-src"
os.chdir(repo)
os.environ["CONFIG_"] = ""
sys.path.insert(0, os.path.join(repo, "menu"))
from kconfiglib import Kconfig

kconf = Kconfig("Config.in", warn=True)
values = {
    "BOOK_LFS_ANY": "y",
    "BOOK_LFS_SYSD": "y",
    "BRANCH": "y",
    "COMMIT": "1c2eb20b24b7131dd6f08b6e2eb70f740f3d1054",
    "LFS_MULTILIB_NO": "y",
    "BUILD_CHROOT": "y",
    "LUSER": "lfs",
    "LGROUP": "lfs",
    "BUILDDIR": "/mnt/oslab-lfs",
    "GETPKG": "y",
    "SRC_ARCHIVE": "/srv/oslab-lfs-sources",
    "RETRYSRCDOWNLOAD": "y",
    "RETRYDOWNLOADCNT": "5",
    "DOWNLOADTIMEOUT": "90",
    "ALL_CORES": "n",
    "N_PARALLEL": "4",
    "CONFIG_TESTS": "y",
    "TST_1": "y",
    "INSTALL_LOG": "y",
    "NO_PROGRESS_BAR": "y",
    "HAVE_FSTAB": "y",
    "FSTAB": "/home/build/oslab/fstab",
    "CONFIG_BUILD_KERNEL": "y",
    "CONFIG": "/home/build/oslab/kernel-7.1.3-bootstrap.config",
    "TIMEZONE": "America/Los_Angeles",
    "LANG": "en_US.UTF-8",
    "PAGE_LETTER": "y",
    "HOSTNAME": "oslab",
    "INTERFACE": "enp0s3",
    "KEYMAP": "us",
    "FONT": "lat0-16",
    "REPORT": "y",
}

for name, value in values.items():
    symbol = kconf.syms.get(name)
    if symbol is None:
        raise SystemExit(f"unknown jhalfs symbol: {name}")
    if not symbol.set_value(value):
        raise SystemExit(f"rejected jhalfs value: {name}={value}")

kconf.write_config(os.path.join(repo, "configuration"))
PY

chown -R "${BUILD_USER}:${BUILD_USER}" \
  "${BUILD_ROOT}" "${SOURCE_ARCHIVE}" "${TOOLING_ROOT}" "${JHALFS_ROOT}"

sudo -u "${BUILD_USER}" python3 "${TOOLING_ROOT}/generate-jhalfs-config.py"
sudo -u "${BUILD_USER}" bash -lc \
  "cd '${JHALFS_ROOT}' && printf 'yes\\nyes\\n' | ./jhalfs run"

test -f "${BUILD_ROOT}/jhalfs/Makefile"
sudo -u "${BUILD_USER}" git -C "${JHALFS_ROOT}" rev-parse HEAD | \
  install -o "${BUILD_USER}" -g "${BUILD_USER}" -m 0644 /dev/stdin \
    "${TOOLING_ROOT}/jhalfs.commit"
printf '%s\n' "${LFS_BOOK_COMMIT}" > "${TOOLING_ROOT}/lfs-book.commit"
echo "jhalfs build files are ready at ${BUILD_ROOT}/jhalfs"
