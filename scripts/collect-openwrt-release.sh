#!/usr/bin/env bash
set -euo pipefail

readonly OPENWRT_ROOT=/home/build/openwrt
readonly BUILD_EXIT=/home/build/openwrt-build.exit
readonly OUTPUT_ROOT=/home/build/openwrt-release
readonly TARGET_ROOT=${OPENWRT_ROOT}/bin/targets/mediatek/mt7622

if [[ ${EUID} -eq 0 ]]; then
  echo 'collect-openwrt-release.sh must run as the unprivileged build user' >&2
  exit 2
fi

if [[ ! -f ${BUILD_EXIT} ]] || ! grep -qx 'EXIT=0' "${BUILD_EXIT}"; then
  echo 'refusing to collect an incomplete OpenWrt build' >&2
  exit 3
fi

if [[ ! -d ${TARGET_ROOT} ]]; then
  echo "OpenWrt target output is missing: ${TARGET_ROOT}" >&2
  exit 3
fi

rm -rf -- "${OUTPUT_ROOT}"
install -d -m 0755 "${OUTPUT_ROOT}"

mapfile -t images < <(find "${TARGET_ROOT}" -maxdepth 1 -type f \
  -name '*linksys_e8450-ubi*' -print | sort)
if (( ${#images[@]} < 2 )); then
  echo 'expected E8450 UBI recovery and sysupgrade images were not produced' >&2
  exit 4
fi

for image in "${images[@]}"; do
  cp "${image}" "${OUTPUT_ROOT}/"
done

for metadata in profiles.json sha256sums version.buildinfo feeds.buildinfo \
  config.buildinfo; do
  [[ -f ${TARGET_ROOT}/${metadata} ]] && \
    cp "${TARGET_ROOT}/${metadata}" "${OUTPUT_ROOT}/"
done

find "${TARGET_ROOT}" -maxdepth 1 -type f -name '*.manifest' -exec \
  cp {} "${OUTPUT_ROOT}/" \;
cp "${OPENWRT_ROOT}/.config" "${OUTPUT_ROOT}/openwrt.config"

{
  printf 'OPENWRT_COMMIT=%s\n' "$(git -C "${OPENWRT_ROOT}" rev-parse HEAD)"
  printf 'OPENWRT_DESCRIBE=%s\n' "$(git -C "${OPENWRT_ROOT}" describe --tags --always)"
  printf 'TARGET=mediatek/mt7622\n'
  printf 'PROFILE=linksys_e8450-ubi\n'
  printf 'CONFIG_SHA256=%s\n' \
    "$(sha256sum "${OPENWRT_ROOT}/.config" | cut -d' ' -f1)"
  printf 'BUILD_STARTED=%s\n' \
    "$(sed -n 's/^START=//p' /home/build/openwrt-build.log | head -1)"
  printf 'BUILD_FINISHED=%s\n' \
    "$(sed -n 's/^END=//p' "${BUILD_EXIT}" | head -1)"
} > "${OUTPUT_ROOT}/BUILD-MANIFEST.txt"

cat > "${OUTPUT_ROOT}/README-FIRST.txt" <<'EOF'
UNOFFICIAL CUSTOM BUILD FOR LINKSYS E8450 UBI / BELKIN RT3200 UBI ONLY.

This release does not convert a stock-layout router to UBI. Do not flash the
plain initramfs recovery image as an installer. For first installation or for
an old layout, follow the current supported owrt-ubi-installer instructions and
back up the vendor bootchain first. Existing current-layout OpenWrt users should
use the UBI sysupgrade image after verifying its SHA-256.

No script in this release flashes the router automatically.
EOF

pushd "${OUTPUT_ROOT}" >/dev/null
find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' | \
  sort -z | xargs -0 sha256sum > SHA256SUMS
sha256sum --check SHA256SUMS
popd >/dev/null
echo "OpenWrt release payload ready at ${OUTPUT_ROOT}"

