#!/usr/bin/env bash
set -euo pipefail

readonly INPUT=/srv/oslab-output
readonly OUTPUT=/srv/oslab-release
readonly PART_SIZE=1900M
readonly -a PROFILES=(zen5 skylake)
readonly -a COMMON=(
  BUILD-MANIFEST.txt
  LFS-SOURCE-SHA256SUMS
  SOURCE-SHA256SUMS
  UPSTREAMS.tsv
  initramfs-7.1.5-oslab.img
  kernel-7.1.5-oslab.config
  vmlinuz-7.1.5-oslab
)

if [[ ${EUID} -ne 0 ]]; then
  echo 'prepare-lfs-release.sh must run as root' >&2
  exit 2
fi
grep -qx 'EXIT=0' /home/build/oslab/lfs-validation.exit
[[ ${INPUT} == /srv/oslab-output && ${OUTPUT} == /srv/oslab-release ]]

rm -rf -- "${OUTPUT}"
install -d -m 0755 "${OUTPUT}"
for name in "${COMMON[@]}"; do
  install -m 0644 "${INPUT}/${name}" "${OUTPUT}/${name}"
done

(
  cd "${INPUT}"
  sha256sum \
    oslab-2026.07-zen5-rootfs.tar.zst \
    oslab-2026.07-skylake-rootfs.tar.zst
) > "${OUTPUT}/ROOTFS-SHA256SUMS"

for profile in "${PROFILES[@]}"; do
  archive="oslab-2026.07-${profile}-rootfs.tar.zst"
  split -b "${PART_SIZE}" -d -a 2 \
    "${INPUT}/${archive}" "${OUTPUT}/${archive}.part"
done

cat > "${OUTPUT}/REASSEMBLE.md" <<'EOF'
# Reassemble the OS Lab rootfs archives

The rootfs archives are split only to remain below GitHub's per-asset size
limit. Concatenation recreates the original compressed byte stream; it does not
recompress or alter the filesystem.

```bash
cat oslab-2026.07-zen5-rootfs.tar.zst.part* > oslab-2026.07-zen5-rootfs.tar.zst
cat oslab-2026.07-skylake-rootfs.tar.zst.part* > oslab-2026.07-skylake-rootfs.tar.zst
sha256sum --check ROOTFS-SHA256SUMS
```

Then follow `INSTALL.md` inside the selected archive. These are experimental
bootstrap root filesystems, not automatic installers or proven bootable images.
EOF

(
  cd "${OUTPUT}"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' |
    LC_ALL=C sort |
    xargs sha256sum
) > "${OUTPUT}/SHA256SUMS"

/home/build/oslab/validate-lfs-release.sh "${OUTPUT}"
