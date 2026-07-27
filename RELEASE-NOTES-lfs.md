# OS Lab 2026.07 — experimental LFS bootstrap root filesystems

This unofficial learning release contains two Linux From Scratch 13.0-systemd
derived x86-64-v3 root filesystems: a Zen 5 future-package tuning profile and an
Intel Skylake future-package tuning profile. Both use the same broad Linux 7.1.5
kernel and generic dracut initramfs. The payload also records systemd 261.2,
pacman 7.1.0, source provenance, pinned checksums, and the complete kernel
configuration.

These are bootstrap rootfs archives, not disk images, automatic installers, or
proven bootable images. They do not partition disks, create credentials, or
install an EFI bootloader. The root account is locked. Read `INSTALL.md` inside
the chosen archive, keep a tested recovery path, configure `/etc/fstab`, create
an administrator, regenerate the initramfs for the real storage layout, and
install a bootloader before attempting a test boot.

## Verify and reassemble

Download all 14 assets into a fresh directory, then run:

```bash
sha256sum --check SHA256SUMS
cat oslab-2026.07-zen5-rootfs.tar.zst.part* > oslab-2026.07-zen5-rootfs.tar.zst
cat oslab-2026.07-skylake-rootfs.tar.zst.part* > oslab-2026.07-skylake-rootfs.tar.zst
sha256sum --check ROOTFS-SHA256SUMS
zstd --test oslab-2026.07-zen5-rootfs.tar.zst oslab-2026.07-skylake-rootfs.tar.zst
```

The split is transport framing only: concatenation restores the exact original
compressed bytes. `SHA256SUMS` covers every transported asset except itself;
`ROOTFS-SHA256SUMS` covers the two reconstructed archives.

For the repository's full portable check, run:

```bash
scripts/validate-lfs-release.sh /path/to/fresh-download
```

Pacman initially contains only local bootstrap metadata and was built without
GPGME. Rebuild it with GPGME, establish a trusted keyring, and define a signature
policy before adding any remote package repository.
