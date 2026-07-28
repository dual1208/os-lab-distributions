# Router-lab supply chain

This record explains what was discovered, adopted, rejected, and how to remove
it. It contains no provider identifiers, addresses, or credentials.

## OpenWrt

- Canonical source: `https://github.com/openwrt/openwrt`
- User-owned fork: `https://github.com/dual1208/openwrt`
- Tag and commit: `v25.12.5`,
  `f0a60eee2fe051741c643ea6118718aae1ef17fb`
- Feed pins: packages `5caa62e0bc9f7fb9b0c12a23267bceb7724214dd`,
  LuCI `128a7812f4be233c5dd7f7466f534fd888785caf`, routing
  `3d7d0dc7fa43d3eb09498417407e95a6552e5312`, telephony
  `2618106d5846a4a542fdf5809f0d3ed228ce439b`, and video
  `094bf58da6682f895255a35a84349a79dab4bf95`.
- Verification: annotated release tag resolves to the requested commit; the
  MediaTek target selects Linux 6.12.
- Removal: delete only `/srv/openwrt-lab/build/openwrt*` on the disposable
  hosts after verified artifacts are published.

## dae

- Canonical source: `https://github.com/daeuniverse/dae`
- User-owned backup fork: `https://github.com/dual1208/dae`
- Release and commit: `v2.0.0`,
  `fee4c8661059bfc5a60ca8eaad59a1030cb35128`
- Full-source archive SHA-256:
  `51e5fe169a36c03503d74f3cb93a00a4547e41b5a8bd957599bfac0094639061`
- License: AGPL-3.0-only.
- Network behavior: when enabled and privately configured, dae loads eBPF
  programs and makes outbound proxy/DNS connections. This build ships no nodes,
  subscriptions, or credentials and leaves the service disabled.
- Kernel permissions: BPF events, XDP sockets, scheduler BPF, veth, and full
  BTF debug type information.
- Removal from a running router: `apk del dae`; removal from this build source:
  delete the exact `openwrt/package/dae` directory and deselect
  `CONFIG_PACKAGE_dae`.

The repository search found several community packages. The implementation
uses a narrow packaging structure derived from the verified commit
`abec9549accaf4363a0db00d0d271ee354aa175a` of
`douglarek/dae-openwrt` (GPL-2.0-only packaging, AGPL dae payload). Its
unpinned `stable` version and skipped source hash were rejected. The OS Lab
package replaces both with exact v2.0.0 and SHA-256 pins. The more expansive
`kenzok8/openwrt-daede` feed was inspected but not adopted because it tracks a
newer assembled development core and includes dashboard/update behavior beyond
this task.

## Go

- Canonical GitHub mirror: `https://github.com/golang/go`
- User-owned backup fork: `https://github.com/dual1208/go`
- Version: `go1.26.4`.
- Official source SHA-256:
  `4f668a32fbfc1132e6a881fb968c2f1dada631492a339211735fbb255a42602d`.
- License: BSD-3-Clause.
- Provider: the exact OpenWrt packages feed commit above already pins 1.26.4;
  no host compiler substitution or toolchain patch is used.
- Known version boundary: Go 1.26.5 is available and contains security fixes.
  Version 1.26.4 remains intentional because it is part of the requested build
  contract.
- Removal: deselect dae/Go packages and delete only the matching OpenWrt build
  directories and downloads on the disposable host.

## QEMU and lab networking

- Provider: Ubuntu 24.04 packages `qemu-system-x86`, `qemu-utils`, `iproute2`,
  `nftables`, `socat`, and `dnsmasq-base`.
- Permissions: the `builder` account belongs to `kvm`; topology creation and
  network namespaces run as root, while QEMU drops to `builder`.
- Exposure: only SSH is permitted by UFW. QEMU forwards LuCI to host loopback,
  and Windows reaches that port through a second SSH loopback forward.
- Removal: disable `openwrt-lab.service`, run its exact topology teardown, then
  remove the named service/helper files. Destroying the recorded disposable
  Droplet is the final cloud uninstall.

GitHub repository and code searches also covered OpenWrt/QEMU labs, vrnetlab,
and LobeHub catalogs. No third-party virtual appliance framework was installed:
the required topology is smaller and auditable with supported QEMU and Linux
network namespaces.
