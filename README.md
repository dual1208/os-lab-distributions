# OS Lab

This workspace builds two kinds of unofficial, reproducible artifacts:

- OpenWrt 25.12.5 firmware for the Linksys E8450 after conversion to the
  supported UBI flash layout.
- Linux From Scratch-derived systemd bootstrap systems, built from a pinned
  current recipe and current stable components, for the user's Zen 5 and Intel
  Skylake-class x86-64 computers.

The controlling contract is [`specs/build-and-release.md`](specs/build-and-release.md).
All paid cloud work is temporary, all release payloads are checksummed, and no
script in this workspace flashes or installs anything on physical hardware.
The manual PC handoff boundary is documented in [`INSTALL.md`](INSTALL.md).
New kernel developers can follow the staged, failure-informed course in
[`LEARNING-JOURNEY.md`](LEARNING-JOURNEY.md).

## Layout

- `scripts/setup-lfs-builder.sh` prepares a clean, file-backed LFS build root,
  pins jhalfs and the LFS book, generates a broad kernel configuration, and
  emits the jhalfs Makefile.
- `scripts/run-lfs-build.sh` runs the generated LFS build with a durable exit
  marker.
- `scripts/finalize-lfs.sh` updates the base to Linux 7.1.5 and systemd 261.2,
  adds linux-firmware, dracut, and pacman, then creates sanitized Zen 5 and
  Skylake-class hardware-profile root filesystem archives.
- `scripts/run-lfs-finalize.sh` runs that final layer as a detached-job-friendly
  logged operation with a durable exit marker.
- `scripts/validate-lfs-release.sh` verifies the exact LFS payload, checksums,
  archive integrity and contents, kernel options, initramfs, profiles, and
  sanitized metadata; `scripts/run-lfs-validation.sh` gives it a durable marker.
- `scripts/prepare-lfs-release.sh` converts validated rootfs archives into
  GitHub-compatible split assets without recompression; its wrapper records a
  durable packaging exit marker and revalidates the complete staged payload.
- `scripts/download-lfs-release.ps1` copies that exact staged payload from the
  named disposable builder and emits a local success marker only after all
  downloaded SHA-256 values match.
- `UPSTREAMS.tsv` maps every preserved fork and build input to its canonical
  upstream, immutable release reference, and source commit.
- `reference/` contains offline documentation kept out of Git; its source and
  checksum manifests are versioned.

## Safety boundaries

The scripts require a disposable Ubuntu builder. They refuse to use `/`,
`/home`, or an unmounted LFS target as the build root. The output is a bootstrap
system, not an automatic disk installer. Review hardware support and customize
partitioning, regenerate the included generic initramfs, configure networking
and accounts, and install a bootloader before using it on a physical computer.
