#!/usr/bin/env bash
set -euo pipefail

readonly OPENWRT_COMMIT=f0a60eee2fe051741c643ea6118718aae1ef17fb
readonly OPENWRT_TAG=v25.12.5
readonly DAE_VERSION=2.0.0
readonly DAE_COMMIT=fee4c8661059bfc5a60ca8eaad59a1030cb35128
readonly GO_VERSION=1.26.4
readonly WORK_ROOT=/srv/openwrt-lab/build
readonly REPO_ROOT=/srv/openwrt-lab/repo
readonly SOURCE_ROOT=${WORK_ROOT}/openwrt
readonly ARTIFACT_ROOT=/srv/openwrt-lab/artifacts/e8450-dae
readonly LOG=${WORK_ROOT}/e8450-build.log
readonly EXIT_FILE=${WORK_ROOT}/e8450-build.exit
readonly NINJA_BIN=${SOURCE_ROOT}/staging_dir/host/bin/ninja

if [[ ${EUID} -eq 0 ]]; then
  echo 'run this build as the unprivileged builder user' >&2
  exit 2
fi

for path in "${WORK_ROOT}" "${REPO_ROOT}"; do
  [[ ${path} == /srv/openwrt-lab/* ]] || {
    echo "unsafe workspace path: ${path}" >&2
    exit 2
  }
done

install -d -m 0755 "${WORK_ROOT}" "${ARTIFACT_ROOT}"
rm -f "${EXIT_FILE}"
printf 'START=%s\n' "$(date -u +%FT%TZ)" > "${LOG}"
finish() {
  local rc=$?
  if [[ ! -f ${EXIT_FILE} ]]; then
    # A SIGTERM delivered to the whole systemd cgroup after an OOM can make an
    # EXIT trap observe zero even though the build never reached publication.
    (( rc != 0 )) || rc=1
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

rsync -a --delete \
  "${REPO_ROOT}/openwrt/package/dae/" \
  "${SOURCE_ROOT}/package/dae/"

cd "${SOURCE_ROOT}"
./scripts/feeds update -a >> "${LOG}" 2>&1
./scripts/feeds install -a >> "${LOG}" 2>&1

cat > .config <<'EOF'
CONFIG_TARGET_mediatek=y
CONFIG_TARGET_mediatek_mt7622=y
CONFIG_TARGET_mediatek_mt7622_DEVICE_linksys_e8450-ubi=y
CONFIG_PACKAGE_luci-ssl=y
CONFIG_PACKAGE_block-mount=y
CONFIG_PACKAGE_kmod-usb-storage=y
CONFIG_PACKAGE_kmod-fs-ext4=y
CONFIG_PACKAGE_htop=y
CONFIG_PACKAGE_nano=y
CONFIG_PACKAGE_dae=y
CONFIG_KERNEL_BPF_EVENTS=y
CONFIG_KERNEL_DEBUG_INFO=y
# CONFIG_KERNEL_DEBUG_INFO_REDUCED is not set
CONFIG_KERNEL_DEBUG_INFO_BTF=y
CONFIG_KERNEL_XDP_SOCKETS=y
EOF
make defconfig >> "${LOG}" 2>&1

grep -qx 'CONFIG_TARGET_mediatek_mt7622_DEVICE_linksys_e8450-ubi=y' .config
grep -qx 'CONFIG_PACKAGE_dae=y' .config
grep -qx 'CONFIG_KERNEL_DEBUG_INFO_BTF=y' .config
grep -qx 'CONFIG_KERNEL_XDP_SOCKETS=y' .config
grep -q '^GO_VERSION_PATCH:=4$' feeds/packages/lang/golang/golang1.26/Makefile
grep -q '^PKG_HASH:=4f668a32fbfc1132e6a881fb968c2f1dada631492a339211735fbb255a42602d$' \
  feeds/packages/lang/golang/golang1.26/Makefile

make download -j4 >> "${LOG}" 2>&1
find dl -type f -not -size +0c -delete
make -j2 tools/ninja/compile >> "${LOG}" 2>&1
if ! make -j4 tools/compile NINJA="${NINJA_BIN} -j2" >> "${LOG}" 2>&1; then
  echo 'parallel tools pass failed; isolating the known dwarves gate' >> "${LOG}"
  make tools/dwarves/compile -j1 V=s NINJA="${NINJA_BIN} -j1" >> "${LOG}" 2>&1
fi
make -j4 tools/compile NINJA="${NINJA_BIN} -j2" >> "${LOG}" 2>&1
make -j4 world NINJA="${NINJA_BIN} -j2" >> "${LOG}" 2>&1

rm -rf "${ARTIFACT_ROOT:?}"/*
cp -a bin/targets/mediatek/mt7622/. "${ARTIFACT_ROOT}/"
find bin/packages -type f \( -name 'dae-*.apk' -o -name 'golang1.26-*.apk' \) \
  -exec cp -t "${ARTIFACT_ROOT}" {} +
cp .config "${ARTIFACT_ROOT}/openwrt.config"
./scripts/diffconfig.sh > "${ARTIFACT_ROOT}/openwrt.diffconfig"
cp "${LOG}" "${ARTIFACT_ROOT}/e8450-build.log"

cat > "${ARTIFACT_ROOT}/BUILD-MANIFEST.txt" <<EOF
OpenWrt tag: ${OPENWRT_TAG}
OpenWrt commit: ${OPENWRT_COMMIT}
Kernel line: 6.12
Physical target: mediatek/mt7622/linksys_e8450-ubi
dae version: ${DAE_VERSION}
dae commit: ${DAE_COMMIT}
Go version: ${GO_VERSION}
Go source SHA-256: 4f668a32fbfc1132e6a881fb968c2f1dada631492a339211735fbb255a42602d
dae full-source SHA-256: 51e5fe169a36c03503d74f3cb93a00a4547e41b5a8bd957599bfac0094639061
Note: Go 1.26.5 is available; 1.26.4 is intentionally pinned by contract.
EOF

(
  cd "${ARTIFACT_ROOT}"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' |
    LC_ALL=C sort | xargs sha256sum > SHA256SUMS
)

grep -RIlE 'dop_v1_|gho_|BEGIN (RSA |OPENSSH )?PRIVATE KEY' "${ARTIFACT_ROOT}" && {
  echo 'sensitive-pattern scan failed' >&2
  exit 4
}

printf 'EXIT=0\nEND=%s\n' "$(date -u +%FT%TZ)" | tee "${EXIT_FILE}" >> "${LOG}"
