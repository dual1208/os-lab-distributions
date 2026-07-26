# OS Lab build and release contract

Status: in progress  
Date: 2026-07-26

## Objective

Produce reproducible, checksummed build artifacts for the user's Linksys E8450
router and two x86-64 personal computers, retain authoritative offline build
references, publish the artifacts in idiomatic GitHub releases, and remove the
temporary paid builder when publishing and verification are complete.

## Scope

1. Preserve the existing GitHub forks under `dual1208` for OpenWrt, Linux
   mainline and stable, systemd, glibc, binutils/GDB, coreutils, util-linux,
   shadow, Bash, GCC, apt, and dpkg.
   Because pacman's canonical repository is hosted on Arch Linux GitLab rather
   than GitHub, preserve it in a clearly labeled GitHub mirror whose upstream
   URL and immutable source commit are recorded; do not misrepresent it as a
   GitHub-native fork.
2. Build OpenWrt `v25.12.5` for the `mediatek/mt7622`
   `linksys_e8450-ubi` target with LuCI over TLS, block-mount, USB-storage,
   htop, and nano. The deliverable is firmware for the UBI layout; it is not a
   stock-layout installer and it must never be flashed automatically.
3. Build an LFS-systemd-derived x86-64 base using the LFS development recipe at
   immutable commit `1c2eb20b24b7131dd6f08b6e2eb70f740f3d1054`, then produce
   two variants. This pinned recipe supplies the current stable Bash 5.3,
   binutils 2.46.1, coreutils 9.11, GCC 16.1, glibc 2.43, shadow 4.19.4, and
   util-linux 2.42.2 releases; the final layer updates Linux to 7.1.5 and
   systemd to 261.2, installs dracut 111, and includes the official
   linux-firmware 20260622 snapshot.
   Variants:
   - `zen5`: MECHREVO XINGYAO, AMD Ryzen AI 9 H 365, 32 GB RAM.
   - `skylake`: ThinkPad P73, Intel Core i7-9750H, 16 GB RAM, Quadro T2000.
4. Use pacman as the post-bootstrap package manager for the custom GNU/Linux
   system. Package-manager metadata and exact source revisions must be present
   in each artifact. CPU tuning may apply to userland packages, but the kernel,
   bootloader, and recovery path must remain compatible with the named machine.
5. Retain local copies of the stable LFS/BLFS books and relevant GNU, Linux,
   systemd, and package-manager manuals. Record source URLs and SHA-256 hashes.
6. Publish custom OpenWrt firmware as a release on `dual1208/openwrt` and the
   GNU/Linux artifacts in a dedicated `dual1208/os-lab-distributions`
   repository. Release notes must identify custom/unofficial builds and include
   installation boundaries and rollback guidance.

## Invariants

- Never print, commit, upload, or embed access tokens, provider credentials,
  SSH private keys, raw machine inventories, serial numbers, private hostnames,
  public/private IP addresses, or router configuration secrets.
- Pin every upstream input by immutable commit and, where available, signed or
  annotated release tag. Record source archive hashes before building.
- Do not modify or flash the router, repartition either PC, or install an OS on
  physical hardware in this task.
- Do not claim a bootable or installable artifact without an automated boot
  smoke test. A root-filesystem archive that is not boot-tested must be labeled
  as a bootstrap rootfs, not an installer.
- OpenWrt release assets must target only `linksys_e8450-ubi`; the release notes
  must direct stock-layout users to the supported UBI installer workflow.
- Keep the temporary DigitalOcean builder bounded to this work. Powered-off is
  not cleanup: destroy `osforge` after all verified artifacts are downloaded or
  published.
- Preserve unrelated working-tree changes and never stage credential or
  machine-information files.

## Acceptance checks

### OpenWrt

- The expanded `.config` selects `mediatek/mt7622` and
  `linksys_e8450-ubi`, and records the requested packages.
- `make` exits zero and the image builder produces the expected UBI recovery
  and sysupgrade artifacts.
- `sha256sums`, the expanded `.config`, package manifest, source commit, build
  log summary, and reproducibility/provenance manifest accompany the firmware.
- Each published asset downloads successfully and matches its recorded SHA-256.

### GNU/Linux

- The build manifest identifies the stable LFS 13.0 reference baseline, the
  pinned LFS development recipe commit, all source versions and hashes,
  compiler flags, kernel configuration, package database, and the two hardware
  profiles.
- Each variant contains Linux, glibc, systemd, Bash, coreutils, util-linux,
  shadow, GCC runtime support, networking essentials, initramfs tooling, and
  pacman with a valid local package database.
- The kernel.org Linux and linux-firmware archives are rejected unless their
  SHA-256 hashes match the values published in kernel.org's signed checksum
  manifests. All other final-layer source hashes and immutable tag commits are
  recorded before compilation begins.
- Filesystem ownership, `/etc/os-release`, machine-id handling, DNS resolver
  setup, fstab template, bootloader instructions, and first-boot account setup
  are explicit and contain no builder identity or secrets.
- Each released artifact passes archive integrity checks. Any artifact labeled
  bootable additionally reaches systemd multi-user target in a bounded QEMU
  smoke test; otherwise it is labeled bootstrap-only.
- Published assets re-download and match the release checksums.

### References and cleanup

- The local reference manifest covers every retained file with URL, retrieval
  date, size, and SHA-256, and corrupt/HTML-error downloads are rejected.
- GitHub releases and repository metadata contain no sensitive local data.
- The `osforge` droplet is destroyed and absence is confirmed through normalized
  cloud inventory after artifact verification.

## Failure behavior

- Stop the affected build on a source-integrity, compilation, packaging,
  signing, boot-test, or checksum failure. Preserve a bounded sanitized log and
  do not publish the failed artifact as successful.
- A failed GitHub upload must not trigger a rebuild. Retain the verified local
  artifact and retry only the upload.
- If the cloud builder approaches the independent budget/deadline boundary,
  preserve source/config/log manifests and destroy it rather than allowing
  unbounded billing.
- If a physical-hardware-specific image cannot be safely boot-tested, publish
  it only as an experimental bootstrap artifact with the limitation stated.

## Apply plan

1. Verify forks, source tags, cloud billing/inventory, and the interrupted
   builder state.
2. Correct and lock the OpenWrt configuration, build in a detached logged job,
   validate outputs, and publish the custom release.
3. Add versioned GNU/Linux build scripts and manifests, build the common base
   and two hardware variants in detached logged jobs, validate, and publish.
4. Finish and hash the offline reference library.
5. Re-download representative release assets, verify checksums, then destroy
   `osforge` and confirm removal.

## Rollback

- GitHub releases: `gh release delete <tag> --repo <owner/repo> --cleanup-tag`
- Dedicated distribution repository, if the entire published result is invalid:
  `gh repo delete dual1208/os-lab-distributions --yes`
- Individual forks created for this task:
  `gh repo delete dual1208/<name> --yes` (only after explicit evidence that the
  fork has no independent work).
- DigitalOcean builder:
  `one-console exec --provider digitalocean -- compute droplet delete <id> --force`
- Local generated artifacts: remove only the exact generated `out/` directory
  after resolving and verifying that it is inside this OS Lab workspace.
