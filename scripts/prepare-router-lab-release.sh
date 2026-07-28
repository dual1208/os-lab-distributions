#!/usr/bin/env bash
set -euo pipefail

case ${1:-} in
  e8450)
    source_dir=/srv/openwrt-lab/artifacts/e8450-dae
    archive=/srv/openwrt-lab/release/openwrt-25.12.5-e8450-ubi-dae2-go1.26.4.tar.zst
    marker=/srv/openwrt-lab/build/e8450-build.exit
    ;;
  x86)
    source_dir=/srv/openwrt-lab/artifacts/x86-lab
    archive=/srv/openwrt-lab/release/openwrt-25.12.5-x86-64-router-lab.tar.zst
    marker=/srv/openwrt-lab/build/x86-lab-build.exit
    ;;
  *) echo 'usage: prepare-router-lab-release.sh e8450|x86' >&2; exit 2 ;;
esac

grep -qx 'EXIT=0' "${marker}"
[[ ${source_dir} == /srv/openwrt-lab/artifacts/* ]]
[[ ${archive} == /srv/openwrt-lab/release/*.tar.zst ]]
install -d -m 0755 /srv/openwrt-lab/release
tar --zstd -C "${source_dir}" -cf "${archive}" .
sha256sum "${archive}" > "${archive}.sha256"

