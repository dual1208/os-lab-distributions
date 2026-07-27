#!/usr/bin/env bash
set -euo pipefail

readonly BUILD_ROOT=/mnt/oslab-lfs
readonly TOOLING_ROOT=/home/build/oslab
readonly SOURCE_ROOT=/srv/oslab-lfs-sources
readonly OUTPUT_ROOT=/srv/oslab-output
readonly PACMAN_VERSION=7.1.0
readonly PACMAN_COMMIT=5683f8477a0afcc6b331766175a83445b2dcfe89
readonly SYSTEMD_VERSION=261.2
readonly SYSTEMD_COMMIT=4925d9f07fc697efccd98a93046ff535b8832445
readonly LINUX_VERSION=7.1.5
readonly LINUX_COMMIT=dc529fe18aa9479a088c429048d52eaf164d036d
readonly LINUX_SOURCE_SHA256=22a0196b3cbcdf34dc27b77561f4d040585fd3447edc9ab3531a1ac79e3041e7
readonly DRACUT_VERSION=111
readonly DRACUT_COMMIT=b3b4f7ef914b84964a56500cfec83f21dc513e6a
readonly LINUX_FIRMWARE_VERSION=20260622
readonly LINUX_FIRMWARE_SOURCE_SHA256=2b9d8a358e76eb766588609135e53fa548b902c551daae33ee32f26f25e60dbb

if [[ ${EUID} -ne 0 ]]; then
  echo 'finalize-lfs.sh must run as root' >&2
  exit 2
fi

if [[ ! -f ${TOOLING_ROOT}/lfs-build.exit ]] || \
   ! grep -qx 'EXIT=0' "${TOOLING_ROOT}/lfs-build.exit"; then
  echo 'refusing to finalize an incomplete LFS build' >&2
  exit 3
fi

if [[ ! -x ${BUILD_ROOT}/usr/bin/bash ]] || \
   [[ ! -d ${BUILD_ROOT}/usr/lib/systemd ]]; then
  echo 'LFS base is incomplete' >&2
  exit 3
fi

install -d -m 0755 "${OUTPUT_ROOT}" "${BUILD_ROOT}/sources/oslab-extra"
for fs in dev proc sys run; do
  mountpoint -q "${BUILD_ROOT}/${fs}" || mount --bind "/${fs}" "${BUILD_ROOT}/${fs}"
done

cat > "${BUILD_ROOT}/sources/oslab-extra/install.sh" <<'CHROOT'
#!/usr/bin/env bash
set -euo pipefail
cd /sources/oslab-extra

build_autotools() {
  local archive=$1
  local directory=$2
  shift 2
  rm -rf -- "${directory}"
  tar -xf "${archive}"
  pushd "${directory}" >/dev/null
  ./configure --prefix=/usr --disable-static "$@"
  make -j4
  make install
  popd >/dev/null
}

build_autotools libarchive-3.8.5.tar.xz libarchive-3.8.5 \
  --without-xml2 --without-nettle
build_autotools curl-8.18.0.tar.xz curl-8.18.0 \
  --with-openssl --enable-threaded-resolver --without-libpsl

rm -rf systemd-261.2
tar -xf systemd-261.2.tar.gz
sed -e 's/GROUP="render"/GROUP="video"/' \
    -e 's/GROUP="sgx", //' \
    -i systemd-261.2/rules.d/50-udev-default.rules.in
meson setup systemd-261.2/build systemd-261.2 \
  --prefix=/usr --buildtype=release \
  -Ddefault-dnssec=no -Dfirstboot=false -Dinstall-tests=false \
  -Dldconfig=false -Dsysusers=false -Drpmmacrosdir=no \
  -Dhomed=disabled -Dman=disabled -Dmode=release -Dpamconfdir=no \
  -Ddev-kvm-mode=0660 -Dnobody-group=nogroup -Dsysupdate=disabled \
  -Dukify=disabled -Ddocdir=/usr/share/doc/systemd-261.2
ninja -C systemd-261.2/build -j4
ninja -C systemd-261.2/build install

rm -rf linux-7.1.5
tar -xf linux-7.1.5.tar.xz
pushd linux-7.1.5 >/dev/null
cp ../kernel-bootstrap.config .config
scripts/config --set-str LOCALVERSION '-oslab'
scripts/config --set-str SYSTEM_TRUSTED_KEYS ''
scripts/config --set-str SYSTEM_REVOCATION_KEYS ''
scripts/config --disable MODULE_SIG_ALL
scripts/config --disable DEBUG_INFO_BTF
scripts/config --disable GCC_PLUGINS
make olddefconfig </dev/null
make -j4
make modules_install
cp arch/x86/boot/bzImage /boot/vmlinuz-7.1.5-oslab
cp System.map /boot/System.map-7.1.5-oslab
cp .config /boot/config-7.1.5-oslab
popd >/dev/null

rm -rf linux-firmware-20260622
tar -xf linux-firmware-20260622.tar.xz
install -d -m 0755 /usr/lib/firmware
cp -a linux-firmware-20260622/. /usr/lib/firmware/
rm -rf /usr/lib/firmware/.github /usr/lib/firmware/.gitlab-ci.yml
rm -f /usr/lib/firmware/Makefile

rm -rf dracut-111
tar -xf dracut-111.tar.gz
pushd dracut-111 >/dev/null
./configure --prefix=/usr --sysconfdir=/etc --disable-documentation
make -j4
make install
popd >/dev/null
dracut --force --no-hostonly /boot/initramfs-7.1.5-oslab.img 7.1.5-oslab

rm -rf pacman-7.1.0 pacman-pkgroot
tar -xf pacman-7.1.0.tar.xz
meson setup pacman-7.1.0/build pacman-7.1.0 \
  --prefix=/usr --buildtype=release \
  -Dcrypto=openssl -Ddoc=disabled -Ddoxygen=disabled -Dgpgme=disabled
ninja -C pacman-7.1.0/build -j4
DESTDIR=/sources/oslab-extra/pacman-pkgroot \
  ninja -C pacman-7.1.0/build install
ninja -C pacman-7.1.0/build install

install -d -m 0755 /var/lib/pacman/local /var/cache/pacman/pkg /var/log
cat > /etc/pacman.conf <<'EOF'
[options]
RootDir = /
DBPath = /var/lib/pacman/
CacheDir = /var/cache/pacman/pkg/
LogFile = /var/log/pacman.log
Architecture = auto
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional
EOF

cat > pacman-pkgroot/.PKGINFO <<'EOF'
pkgname = pacman
pkgbase = pacman
pkgver = 7.1.0-1
pkgdesc = A library-based package manager with dependency support
url = https://gitlab.archlinux.org/pacman/pacman
builddate = 1785081600
packager = OS Lab reproducible builder
size = 0
arch = x86_64
license = GPL-2.0-or-later
EOF
tar --zstd -C pacman-pkgroot -cf pacman-7.1.0-1-x86_64.pkg.tar.zst .
pacman -U --noconfirm --dbonly pacman-7.1.0-1-x86_64.pkg.tar.zst

rm -rf base-meta
install -d -m 0755 base-meta
cat > base-meta/.PKGINFO <<'EOF'
pkgname = oslab-lfs-base
pkgbase = oslab-lfs-base
pkgver = 2026.07-1
pkgdesc = Current Linux From Scratch development base built by OS Lab
url = https://www.linuxfromscratch.org/lfs/view/systemd/
builddate = 1785081600
packager = OS Lab reproducible builder
size = 0
arch = x86_64
license = custom
depend = pacman
EOF
tar --zstd -C base-meta -cf oslab-lfs-base-2026.07-1-x86_64.pkg.tar.zst .
pacman -U --noconfirm oslab-lfs-base-2026.07-1-x86_64.pkg.tar.zst
pacman -Q pacman oslab-lfs-base
install -d -m 0755 /etc/oslab
pacman -Q > /etc/oslab/pacman-local.txt

cat > /etc/os-release <<'EOF'
NAME="OS Lab Linux"
PRETTY_NAME="OS Lab Linux 2026.07 (LFS-systemd derived)"
ID=oslab
ID_LIKE=lfs
VERSION_ID="2026.07"
VERSION_CODENAME="sourceforge"
HOME_URL="https://github.com/dual1208/os-lab-distributions"
DOCUMENTATION_URL="https://www.linuxfromscratch.org/lfs/view/systemd/"
EOF

: > /etc/machine-id
chmod 0444 /etc/machine-id
ln -snf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
systemctl enable systemd-networkd.service systemd-resolved.service
cat > /etc/systemd/network/20-wired.network <<'EOF'
[Match]
Name=en* eth*

[Network]
DHCP=yes
IPv6AcceptRA=yes
EOF

passwd -l root
install -d -m 0755 /etc/oslab /etc/makepkg.conf.d
cat > /etc/oslab/README-FIRST <<'EOF'
This is an experimental bootstrap root filesystem, not an automatic installer.
Before physical installation: create an administrator and set credentials,
review storage labels and /etc/fstab, regenerate the included initramfs for
the target, install and configure a bootloader, and verify firmware and network
support.
The included generic initramfs is a bootstrap convenience; regenerate it on
the installed target after confirming storage, encryption, and root labels.
EOF
CHROOT

chmod 0755 "${BUILD_ROOT}/sources/oslab-extra/install.sh"
download_source() {
  local url=$1
  local name=$2
  local file="${BUILD_ROOT}/sources/oslab-extra/${name}"
  [[ -f ${file} ]] || wget -O "${file}" "${url}"
}

download_source \
  https://github.com/libarchive/libarchive/releases/download/v3.8.5/libarchive-3.8.5.tar.xz \
  libarchive-3.8.5.tar.xz
download_source https://curl.se/download/curl-8.18.0.tar.xz \
  curl-8.18.0.tar.xz
download_source \
  https://github.com/systemd/systemd/archive/refs/tags/v261.2.tar.gz \
  systemd-261.2.tar.gz
download_source \
  https://www.kernel.org/pub/linux/kernel/v7.x/linux-7.1.5.tar.xz \
  linux-7.1.5.tar.xz
download_source \
  https://github.com/dracut-ng/dracut/archive/refs/tags/111.tar.gz \
  dracut-111.tar.gz
download_source \
  https://www.kernel.org/pub/linux/kernel/firmware/linux-firmware-20260622.tar.xz \
  linux-firmware-20260622.tar.xz

if [[ ! -d ${SOURCE_ROOT}/pacman.git ]]; then
  git clone --mirror https://gitlab.archlinux.org/pacman/pacman.git \
    "${SOURCE_ROOT}/pacman.git"
fi
git -C "${SOURCE_ROOT}/pacman.git" cat-file -e "${PACMAN_COMMIT}^{commit}"
git --git-dir="${SOURCE_ROOT}/pacman.git" archive --format=tar \
  --prefix=pacman-7.1.0/ "${PACMAN_COMMIT}" | xz -T0 \
  > "${BUILD_ROOT}/sources/oslab-extra/pacman-7.1.0.tar.xz"
cp "${TOOLING_ROOT}/kernel-7.1.3-bootstrap.config" \
  "${BUILD_ROOT}/sources/oslab-extra/kernel-bootstrap.config"

printf '%s  %s\n' "${LINUX_SOURCE_SHA256}" linux-7.1.5.tar.xz | \
  (cd "${BUILD_ROOT}/sources/oslab-extra" && sha256sum --check --strict)
printf '%s  %s\n' "${LINUX_FIRMWARE_SOURCE_SHA256}" \
  linux-firmware-20260622.tar.xz | \
  (cd "${BUILD_ROOT}/sources/oslab-extra" && sha256sum --check --strict)
(cd "${BUILD_ROOT}/sources/oslab-extra" && \
  sha256sum libarchive-3.8.5.tar.xz curl-8.18.0.tar.xz \
    systemd-261.2.tar.gz linux-7.1.5.tar.xz dracut-111.tar.gz \
    linux-firmware-20260622.tar.xz pacman-7.1.0.tar.xz \
    > SOURCE-SHA256SUMS)

chroot "${BUILD_ROOT}" /usr/bin/env -i \
  HOME=/root TERM=xterm PATH=/usr/bin:/usr/sbin \
  /bin/bash --login /sources/oslab-extra/install.sh

for option in \
  CONFIG_EFI CONFIG_EFI_STUB CONFIG_BLK_DEV_NVME CONFIG_SATA_AHCI \
  CONFIG_EXT4_FS CONFIG_VFAT_FS CONFIG_VIRTIO_PCI CONFIG_VIRTIO_BLK \
  CONFIG_DRM_AMDGPU CONFIG_DRM_NOUVEAU CONFIG_DRM_I915 CONFIG_E1000E \
  CONFIG_R8169 CONFIG_IWLWIFI CONFIG_SND_HDA_INTEL; do
  if ! grep -Eq "^${option}=(y|m)$" \
    "${BUILD_ROOT}/boot/config-7.1.5-oslab"; then
    echo "required kernel option is missing: ${option}" >&2
    exit 4
  fi
done
install -D -m 0644 "${TOOLING_ROOT}/INSTALL.md" \
  "${BUILD_ROOT}/usr/share/doc/oslab/INSTALL.md"

for profile in zen5 skylake; do
  case ${profile} in
    zen5) tune=znver5 ;;
    skylake) tune=skylake ;;
  esac
  profile_root="${OUTPUT_ROOT}/rootfs-${profile}"
  rm -rf -- "${profile_root}"
  install -d -m 0755 "${profile_root}"
  rsync -aHAX --numeric-ids \
    --exclude='/dev/*' --exclude='/proc/*' --exclude='/run/*' \
    --exclude='/sys/*' --exclude='/sources/*' \
    "${BUILD_ROOT}/" "${profile_root}/"
  install -d -m 0755 "${profile_root}/dev" "${profile_root}/proc" \
    "${profile_root}/run" "${profile_root}/sys"
  cat > "${profile_root}/etc/oslab/hardware-profile" <<EOF
profile=${profile}
baseline=x86-64-v3
compiler_tune=${tune}
kernel=7.1.5-oslab
EOF
  cat > "${profile_root}/etc/makepkg.conf.d/oslab-flags.conf" <<EOF
CFLAGS="-O2 -pipe -march=x86-64-v3 -mtune=${tune} -fno-plt"
CXXFLAGS="\${CFLAGS}"
MAKEFLAGS="-j\$(nproc)"
EOF
  tar --xattrs --acls --numeric-owner --sort=name \
    --mtime='UTC 2026-07-26' -C "${profile_root}" -cf - . | \
    zstd -T0 -19 -o "${OUTPUT_ROOT}/oslab-2026.07-${profile}-rootfs.tar.zst"
done

cp "${BUILD_ROOT}/boot/config-7.1.5-oslab" "${OUTPUT_ROOT}/kernel-7.1.5-oslab.config"
kernel_image=$(find "${BUILD_ROOT}/boot" -maxdepth 1 -type f \
  -name 'vmlinuz-7.1.5*' -print -quit)
if [[ -n ${kernel_image} ]]; then
  cp "${kernel_image}" "${OUTPUT_ROOT}/"
fi
cp "${BUILD_ROOT}/boot/initramfs-7.1.5-oslab.img" "${OUTPUT_ROOT}/"
cp "${BUILD_ROOT}/sources/oslab-extra/SOURCE-SHA256SUMS" "${OUTPUT_ROOT}/"
cp "${TOOLING_ROOT}/LFS-SOURCE-SHA256SUMS" "${OUTPUT_ROOT}/"
cp "${TOOLING_ROOT}/UPSTREAMS.tsv" "${OUTPUT_ROOT}/"

cat > "${OUTPUT_ROOT}/BUILD-MANIFEST.txt" <<EOF
LFS_STABLE_REFERENCE=13.0-systemd
LFS_RECIPE_COMMIT=1c2eb20b24b7131dd6f08b6e2eb70f740f3d1054
JHALFS_COMMIT=476870cd636d37a80629decbcfd8743563261a67
LINUX_VERSION=${LINUX_VERSION}
LINUX_COMMIT=${LINUX_COMMIT}
SYSTEMD_VERSION=${SYSTEMD_VERSION}
SYSTEMD_COMMIT=${SYSTEMD_COMMIT}
PACMAN_VERSION=${PACMAN_VERSION}
PACMAN_COMMIT=${PACMAN_COMMIT}
DRACUT_VERSION=${DRACUT_VERSION}
DRACUT_COMMIT=${DRACUT_COMMIT}
LINUX_FIRMWARE_VERSION=${LINUX_FIRMWARE_VERSION}
COMMON_ISA_BASELINE=x86-64-v3
ZEN5_TUNE=znver5
SKYLAKE_TUNE=skylake
BASH_VERSION=5.3
BINUTILS_VERSION=2.46.1
COREUTILS_VERSION=9.11
GCC_VERSION=16.1.0
GLIBC_VERSION=2.43
SHADOW_VERSION=4.19.4
UTIL_LINUX_VERSION=2.42.2
LIBARCHIVE_SOURCE_SHA256=$(sha256sum "${BUILD_ROOT}/sources/oslab-extra/libarchive-3.8.5.tar.xz" | cut -d' ' -f1)
CURL_SOURCE_SHA256=$(sha256sum "${BUILD_ROOT}/sources/oslab-extra/curl-8.18.0.tar.xz" | cut -d' ' -f1)
PACMAN_SOURCE_SHA256=$(sha256sum "${BUILD_ROOT}/sources/oslab-extra/pacman-7.1.0.tar.xz" | cut -d' ' -f1)
SYSTEMD_SOURCE_SHA256=$(sha256sum "${BUILD_ROOT}/sources/oslab-extra/systemd-261.2.tar.gz" | cut -d' ' -f1)
LINUX_SOURCE_SHA256=$(sha256sum "${BUILD_ROOT}/sources/oslab-extra/linux-7.1.5.tar.xz" | cut -d' ' -f1)
DRACUT_SOURCE_SHA256=$(sha256sum "${BUILD_ROOT}/sources/oslab-extra/dracut-111.tar.gz" | cut -d' ' -f1)
LINUX_FIRMWARE_SOURCE_SHA256=$(sha256sum "${BUILD_ROOT}/sources/oslab-extra/linux-firmware-20260622.tar.xz" | cut -d' ' -f1)
LFS_SOURCE_HASH_MANIFEST_SHA256=$(sha256sum "${TOOLING_ROOT}/LFS-SOURCE-SHA256SUMS" | cut -d' ' -f1)
EOF

pushd "${OUTPUT_ROOT}" >/dev/null
checksum_tmp=$(mktemp "${OUTPUT_ROOT}/.SHA256SUMS.XXXXXX")
trap 'rm -f -- "${checksum_tmp}"' EXIT
find . -maxdepth 1 -type f ! -name SHA256SUMS \
  ! -name '.SHA256SUMS.*' -printf '%P\0' | \
  sort -z | xargs -0 sha256sum > "${checksum_tmp}"
mv "${checksum_tmp}" SHA256SUMS
trap - EXIT
popd >/dev/null
echo "finalized artifacts in ${OUTPUT_ROOT}"
