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
  named disposable builder with two bounded, resume-capable transfers and
  emits a local success marker only after all downloaded SHA-256 values match;
  run it with PowerShell 7 (`pwsh`), not legacy Windows PowerShell.
- `scripts/upload-lfs-release.ps1` resumes the exact draft-release upload at
  asset granularity and accepts an existing asset only when GitHub reports the
  same SHA-256 digest as the locally verified file.
- `scripts/verify-lfs-public-release.sh` performs a resumable unauthenticated
  fresh download of all published assets and reruns the complete validator;
  `scripts/run-lfs-public-verification.sh` records its terminal marker.
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

Release-specific warnings, verification, and reassembly commands are in
[`RELEASE-NOTES-lfs.md`](RELEASE-NOTES-lfs.md).

## Published learning artifacts

- [OpenWrt 25.12.5 for the E8450 UBI layout](https://github.com/dual1208/openwrt/releases/tag/v25.12.5-e8450-ubi-20260726)
- [OS Lab 2026.07 LFS bootstrap root filesystems](https://github.com/dual1208/os-lab-distributions/releases/tag/oslab-2026.07)

Both are prereleases. Their public assets were downloaded into fresh
directories and checksum-verified before the disposable builder was destroyed.

## DigitalOcean router lab

The current extension builds a dae-enabled E8450 UBI bundle with Go 1.26.4 and
runs two OpenWrt x86-64 guests under QEMU/KVM for safe routing experiments. The
cloud and build contract is
[`specs/digitalocean-openwrt-router-lab.md`](specs/digitalocean-openwrt-router-lab.md).
The hands-on course is [`docs/TWO-ROUTER-LABS.md`](docs/TWO-ROUTER-LABS.md).

The virtual guests share the exact OpenWrt source commit and user-space profile
with the physical build. They do not emulate or validate the E8450's MediaTek
SoC, NAND/UBI layout, switch, Wi-Fi, or bootloader. LuCI is loopback-only and is
reached from Windows through `scripts/Start-OpenWrtLabTunnel.ps1`.
