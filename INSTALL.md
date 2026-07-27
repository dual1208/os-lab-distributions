# Bootstrap installation boundary

The OS Lab PC artifacts are root-filesystem archives, not disk images or
automatic installers. They deliberately do not choose a partition table,
overwrite an EFI System Partition, create credentials, or install a bootloader.
The root account is locked and the generic initramfs is supplied only as a
bootstrap convenience.

Before using an archive on either named PC:

1. Keep a tested recovery medium and a complete backup of the existing system.
2. Verify the release `SHA256SUMS`, then extract the matching archive from a
   trusted live Linux environment while preserving numeric owners, ACLs, and
   extended attributes.
3. Confirm the installed root filesystem label and edit `/etc/fstab`; the
   included template assumes `LABEL=oslab-root`.
4. Chroot into the target, create an administrator, set credentials, and leave
   the root account locked unless there is a documented recovery need.
   Pacman initially contains only local bootstrap metadata and was built without
   GPGME; rebuild it with GPGME and establish a trusted keyring before adding
   any remote package repository.
5. Review the selected hardware profile under `/etc/oslab/`, regenerate the
   initramfs with dracut for the actual storage and encryption layout, and
   install an EFI bootloader of your choice.
6. Verify storage, keyboard, wired networking, Wi-Fi, display, audio, suspend,
   and recovery boot before treating the installation as primary.

The `zen5` and `skylake` archives share the same x86-64-v3 base and broad
kernel. Their hardware-profile and makepkg flag files select `-mtune=znver5`
or `-mtune=skylake` for future locally rebuilt packages. The ThinkPad profile
includes Nouveau support for the Quadro T2000; proprietary NVIDIA users must
install a kernel-matched driver separately and regenerate the initramfs.

Rollback is the existing operating system or the previously tested boot entry.
Do not delete either until the new root filesystem has passed the checks above.
