#!/usr/bin/env bash
set -euo pipefail

readonly OPENWRT_COMMIT=f0a60eee2fe051741c643ea6118718aae1ef17fb
readonly OPENWRT_TAG=v25.12.5
readonly WORK_ROOT=/srv/openwrt-lab/build
readonly REPO_ROOT=/srv/openwrt-lab/repo
readonly SOURCE_ROOT=${WORK_ROOT}/openwrt-x86
readonly ARTIFACT_ROOT=/srv/openwrt-lab/artifacts/x86-lab
readonly LOG=${WORK_ROOT}/x86-lab-build.log
readonly EXIT_FILE=${WORK_ROOT}/x86-lab-build.exit

if [[ ${EUID} -eq 0 ]]; then
  echo 'run this build as the unprivileged builder user' >&2
  exit 2
fi
[[ ${SOURCE_ROOT} == /srv/openwrt-lab/build/* ]]
install -d -m 0755 "${WORK_ROOT}" "${ARTIFACT_ROOT}"
rm -f "${EXIT_FILE}"
printf 'START=%s\n' "$(date -u +%FT%TZ)" > "${LOG}"
finish() {
  local rc=$?
  if [[ ! -f ${EXIT_FILE} ]]; then
    printf 'EXIT=%s\nEND=%s\n' "${rc}" "$(date -u +%FT%TZ)" | tee "${EXIT_FILE}" >> "${LOG}"
  fi
}
trap finish EXIT

if [[ ! -d ${SOURCE_ROOT}/.git ]]; then
  git clone https://github.com/dual1208/openwrt.git "${SOURCE_ROOT}"
fi
git -C "${SOURCE_ROOT}" fetch --tags origin
git -C "${SOURCE_ROOT}" checkout --detach "${OPENWRT_COMMIT}"
test "$(git -C "${SOURCE_ROOT}" rev-parse HEAD)" = "${OPENWRT_COMMIT}"
test "$(git -C "${SOURCE_ROOT}" rev-list -n1 "${OPENWRT_TAG}")" = "${OPENWRT_COMMIT}"

rsync -a --delete "${REPO_ROOT}/openwrt/package/dae/" "${SOURCE_ROOT}/package/dae/"
rsync -a --delete "${REPO_ROOT}/openwrt/lab-files/" "${SOURCE_ROOT}/files/"

cd "${SOURCE_ROOT}"
./scripts/feeds update -a >> "${LOG}" 2>&1
./scripts/feeds install -a >> "${LOG}" 2>&1
cat > .config <<'EOF'
CONFIG_TARGET_x86=y
CONFIG_TARGET_x86_64=y
CONFIG_TARGET_x86_64_DEVICE_generic=y
CONFIG_TARGET_IMAGES_GZIP=y
CONFIG_TARGET_ROOTFS_PARTSIZE=256
CONFIG_PACKAGE_luci-ssl=y
CONFIG_PACKAGE_dae=y
CONFIG_PACKAGE_htop=y
CONFIG_PACKAGE_nano=y
CONFIG_PACKAGE_ip-full=y
CONFIG_PACKAGE_iperf3=y
CONFIG_PACKAGE_tcpdump=y
CONFIG_PACKAGE_curl=y
CONFIG_KERNEL_BPF_EVENTS=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_BTF=y
CONFIG_KERNEL_XDP_SOCKETS=y
EOF
make defconfig >> "${LOG}" 2>&1
grep -qx 'CONFIG_TARGET_x86_64_DEVICE_generic=y' .config
grep -qx 'CONFIG_PACKAGE_dae=y' .config
grep -q '^GO_VERSION_PATCH:=4$' feeds/packages/lang/golang/golang1.26/Makefile
make download -j4 >> "${LOG}" 2>&1
find dl -type f -not -size +0c -delete
make -j4 world >> "${LOG}" 2>&1

rm -rf "${ARTIFACT_ROOT:?}"/*
cp -a bin/targets/x86/64/. "${ARTIFACT_ROOT}/"
cp .config "${ARTIFACT_ROOT}/openwrt.config"
./scripts/diffconfig.sh > "${ARTIFACT_ROOT}/openwrt.diffconfig"
cp "${LOG}" "${ARTIFACT_ROOT}/x86-lab-build.log"
cat > "${ARTIFACT_ROOT}/ARCHITECTURE-DIFFERENCES.txt" <<EOF
Shared OpenWrt commit: ${OPENWRT_COMMIT}
Shared user-space profile: LuCI HTTPS, dae 2.0.0, Go 1.26.4, htop, nano
Physical firmware: mediatek/mt7622/linksys_e8450-ubi, Linux 6.12
Lab image: x86/64/generic, QEMU virtio NIC/storage, Linux 6.12
The lab does not validate E8450 UBI, bootloader, Wi-Fi, switch, NAND, or drivers.
EOF
(
  cd "${ARTIFACT_ROOT}"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' |
    LC_ALL=C sort | xargs sha256sum > SHA256SUMS
)
printf 'EXIT=0\nEND=%s\n' "$(date -u +%FT%TZ)" | tee "${EXIT_FILE}" >> "${LOG}"

