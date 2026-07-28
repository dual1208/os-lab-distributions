# Unofficial OpenWrt 25.12.5 dae and router-lab bundle

This prerelease is built from OpenWrt commit
`f0a60eee2fe051741c643ea6118718aae1ef17fb` with Linux 6.12, dae 2.0.0, and
Go 1.26.4.

## Physical firmware boundary

The physical firmware targets **only**
`mediatek/mt7622/linksys_e8450-ubi`. It is not a stock-layout-to-UBI installer.
OpenWrt's E8450 instructions warn that writing a plain UBI recovery image to an
unconverted device can brick it. Back up the vendor boot chain and use the
currently supported UBI conversion procedure before considering these images.
Nothing in this repository flashes a router.

dae is included but disabled. The build contains no proxy nodes, subscriptions,
or credentials. Enabling it requires a private configuration and review of the
firewall/DNS effects. The exact Go 1.26.4 pin is intentional even though Go
1.26.5 is available with later security fixes.

## QEMU learning image

The x86-64 image shares the OpenWrt commit and user-space profile but exists
only for QEMU/KVM labs. It does not emulate or validate the Linksys MediaTek
SoC, Wi-Fi, switch, NAND/UBI layout, bootloader, or physical installation.

The archive also contains the expanded configuration, package manifest,
architecture-difference statement, source/build manifest, build log, and
SHA-256 manifest. Follow `docs/TWO-ROUTER-LABS.md` in the source repository for
the loopback-only LuCI and two-router exercises.

## Verification

Verify the top-level release assets with the published `SHA256SUMS`. After
extracting either bundle, verify its internal `SHA256SUMS` before using an image
or package. These are custom experimental artifacts, not official OpenWrt or
dae releases.

