# DigitalOcean OpenWrt build and two-router lab contract

Status: approved by user request; implementation in progress  
Date: 2026-07-28

## Objective

Use the user's expiring DigitalOcean promotional credit for three bounded,
high-capability builder/lab hosts that:

1. builds a complete, reproducible Linksys E8450 UBI firmware bundle from
   OpenWrt `v25.12.5` commit
   `f0a60eee2fe051741c643ea6118718aae1ef17fb`, Linux 6.12, dae `v2.0.0`,
   and Go `1.26.4`;
2. runs an educational OpenWrt router simulation with LuCI reachable only
   through local SSH port forwarding; and
3. provides executable two-router labs derived from `2routers.md`.

All non-secret source, infrastructure definitions, tutorials, test code,
configuration templates, provenance, and sanitized verification evidence must
be backed by the public `dual1208/os-lab-distributions` GitHub repository.

## Verified inputs and constraints

- OpenWrt `v25.12.5` was released on 2026-06-29 and its annotated tag resolves
  to the requested commit.
- `target/linux/mediatek/Makefile` at that commit selects
  `KERNEL_PATCHVER:=6.12`.
- dae `v2.0.0` resolves to commit
  `fee4c8661059bfc5a60ca8eaad59a1030cb35128` and was published on
  2026-07-08. Its full-source archive digest is
  `51e5fe169a36c03503d74f3cb93a00a4547e41b5a8bd957599bfac0094639061`.
- Go `1.26.4` was released on 2026-06-02. It is intentionally pinned despite
  the availability of Go 1.26.5; the release notes and manifest must disclose
  that a newer security release exists.
- The DigitalOcean account currently exposes only Basic Droplet sizes. The
  largest available premium plan is `s-4vcpu-8gb-intel`: 4 vCPU, 8 GiB RAM,
  160 GiB SSD, $0.08333/hour, capped at $56/month. The account limit is three
  droplets. The user explicitly authorized retirement of the six-month-old
  1-vCPU legacy Droplet to free the third slot. Before deletion it was verified
  as created 2026-01-01, 1 GiB RAM, 25 GiB disk, with no attached volumes or
  tags. The account API later reported status `warning`; creation must still
  use only an actually available supported size and must not bypass provider
  controls.
- DigitalOcean's current Ubuntu 24.04 image does not provide the historical
  `qemu-kvm` package name. Install `qemu-system-x86` and `qemu-utils`, then add
  the unprivileged lab account to the `kvm` group after package installation.
- OpenWrt defaults `KERNEL_DEBUG_INFO_REDUCED=y`; its BTF option depends on
  full debug information. The dae builds must explicitly disable reduced debug
  info before selecting `KERNEL_DEBUG_INFO_BTF`, then verify BTF survived
  `make defconfig`.
- On these four-vCPU builders, both clean parallel tools passes stopped at the
  pinned `tools/dwarves` host tool without a retained sub-error; an isolated
  `make tools/dwarves/compile -j1 V=s` succeeded. First allow the bounded
  parallel tools pass to populate prerequisites. If that pass fails, serialize
  only dwarves, rerun the complete parallel tools gate, and only then enter
  `make -j4 world`. Retain the diagnostic log.
- An independent clean retry proved that the LLVM/BPF host-tool portion can
  expand to six simultaneous `cc1plus` processes and exhaust an 8 GiB Basic
  Droplet with no swap. The kernel OOM record showed individual compiler
  processes using up to about 1.7 GiB resident memory. A `make -j2` retry did
  not propagate the bound through OpenWrt's nested wrapper: the process tree
  still showed six live compiler children. Bootstrap the host Ninja tool, then
  explicitly override `NINJA` with `-j2` for tools and world (`-j1` for the
  dwarves fallback), while retaining four outer make jobs. Resume the preserved
  incremental tree after an OOM rather than rebuilding.
  A missing success marker must fail closed: an abnormal shell termination may
  never be reported as `EXIT=0`, even if Bash presents zero to an EXIT trap.
- QEMU does not model the Linksys E8450's MediaTek MT7622 SoC, switch, NAND/UBI
  layout, radios, or boot chain. The E8450 firmware therefore cannot be
  honestly booted as a virtual E8450. The interactive lab will run a separate
  x86-64 OpenWrt image built from the same source commit and aligned user-space
  package profile. It teaches routing, firewall, NAT, DNS, LuCI, and tunnel
  concepts, but is not a hardware or flashing test for the E8450 artifact.

## Scope

### Cloud hosts

- Create exactly three Ubuntu 24.04 LTS Droplets named `openwrt-lab`,
  `openwrt-lab-2`, and `openwrt-lab-3` in `sfo3`, each using
  `s-4vcpu-8gb-intel` and an existing account SSH public key. The first builds
  E8450 firmware; the second builds and hosts the x86-64 interactive and
  two-router labs; the third performs an independent clean E8450 build for
  reproducibility and then serves as relay/verification capacity.
- Tag it `os-lab`, `openwrt-build`, and `temporary`.
- Install only the build, QEMU/KVM, container/network-namespace, verification,
  and Git tooling required by this contract.
- Keep build work under `/srv/openwrt-lab`; use a non-root `builder` account for
  compilation and root only for host networking/KVM/service setup.
- Record the Droplet IDs and public addresses only in ignored local state, never
  in Git, release notes, logs, or tutorials.

### Linksys firmware bundle

- Build only `mediatek/mt7622/linksys_e8450-ubi` as physical firmware.
- Include LuCI HTTPS, block-mount, USB storage support, htop, nano, dae 2.0.0,
  a disabled-by-default dae service/config example, and the kernel/eBPF
  facilities required by dae where the target supports them.
- Build dae from its pinned full-source release input with the exact Go 1.26.4
  bootstrap toolchain; do not silently use the host Go or a different OpenWrt
  Go package.
- Produce the UBI recovery and sysupgrade artifacts plus all package files,
  manifests, expanded configuration, source hashes, logs, SBOM/provenance, and
  verification reports needed to reproduce and audit the build.
- Never flash a router. Clearly distinguish the existing plain 25.12.5 release
  from this new dae-enabled bundle.

### Router simulation and LuCI access

- Build an x86-64 OpenWrt lab image from the same OpenWrt commit and compatible
  package profile. Differences required by architecture or virtual hardware
  must be machine-readable and documented.
- Run the virtual router under QEMU/KVM. It must have at least one WAN and two
  LAN-facing interfaces so forwarding, firewall zones, and NAT are observable.
- Do not expose LuCI to the public Internet. Bind the host forward to loopback,
  then document a local SSH command such as
  `ssh -L 8443:127.0.0.1:<host-port> <host>`.
- Generate a unique lab administrator password on the host, store it in a
  root-readable file outside Git, and provide a command for the user to retrieve
  or rotate it. Never commit or echo it into public logs.
- The lab must survive an SSH disconnect and host reboot through a systemd
  service or an equivalently durable supervisor.

### Two-router labs

- Convert the networking claims in `2routers.md` into a repeatable topology
  with router A, router B, a blind relay/Internet segment, and one endpoint LAN
  behind each router.
- Prefer Linux network namespaces and QEMU/OpenWrt nodes over an unreviewed
  third-party appliance image. If a third-party framework is adopted, pin its
  commit, inspect its license/manifest/network behavior, and document uninstall.
- Provide staged lessons for addressing and routes, NAT, stateful firewalling,
  DNS, MTU, failure/fallback observation, and the distinction between control
  and data planes. Each lesson needs setup, observation commands, expected
  output shape, a reversible experiment, and reset.
- The lab may model the proposed campus-link design before that protocol is
  implemented, but must label simulated/stub behavior honestly.

### GitHub durability

- Connect this existing workspace safely to
  `git@github.com:dual1208/os-lab-distributions.git` without overwriting local
  files or unrelated parent-repository changes.
- Preserve the credentials and machine inventories already excluded by
  `.gitignore`; add ignored runtime-state patterns before generating state.
- Commit and push specs before remote execution, then push implementation and
  sanitized verification updates at meaningful recovery points.
- Track every Linux installer, build entrypoint, and lab helper with its Git
  executable bit so a clone made from the Windows authoring workspace can run
  the documented commands directly; service data files remain non-executable.
- Publish large binaries as a new GitHub prerelease rather than Git blobs.
  Release assets must have SHA-256 digests and provenance.
- Preserve GitHub forks of the official dae and Go repositories under the
  user's account, while continuing to build only the immutable release inputs
  and hashes named by this contract.

## Invariants

- Never print, commit, upload, or embed DigitalOcean/GitHub tokens, private SSH
  keys, lab passwords, public IP addresses, raw machine inventories, provider
  account identifiers, or router secrets.
- Preserve every DigitalOcean resource except the exact legacy Droplet whose
  retirement is explicitly authorized and verified above, and preserve all
  unrelated Git working-tree changes.
- No LuCI, SSH password authentication, QEMU monitor, or lab management socket
  may listen on a public interface. Public SSH remains key-only.
- Do not claim that an x86-64 QEMU image validates the E8450 kernel, drivers,
  UBI layout, Wi-Fi, switch offload, bootloader, or physical installation.
- dae remains disabled until the user supplies a valid, private configuration.
  The example configuration contains no subscription URLs or credentials.
- Every cloud mutation has a corresponding inventory check and rollback
  command. A powered-off Droplet remains billable and is not cleanup.
- Build parallelism is bounded to the four available vCPUs; retain enough disk
  space for source, downloads, build trees, lab images, and release staging.
- Memory-heavy Ninja sub-builds are explicitly bounded to two concurrent jobs
  on the 8 GiB plans, rather than assuming the recursive make jobserver bound
  is inherited; successful completion, not nominal CPU occupancy, is the
  optimization target.

## Acceptance checks

### Provisioning and cost

- The exact new Droplets are `openwrt-lab`, `openwrt-lab-2`, and
  `openwrt-lab-3`, each size
  `s-4vcpu-8gb-intel`, region `sfo3`, Ubuntu 24.04 LTS, tagged as specified,
  and accessible by SSH key.
- A sanitized cost record states the hourly rate, creation time, and estimated
  maximum cost through 2026-07-31 without exposing account data.
- The explicitly authorized legacy Droplet is absent after a converged exact-ID
  deletion, and no volume was targeted or removed.

### Firmware

- The checked-out OpenWrt commit equals the pin and the tag verification is
  recorded.
- The expanded E8450 configuration selects only the requested physical device,
  Linux 6.12, LuCI HTTPS, and dae dependencies.
- `go version` used for dae reports exactly `go1.26.4`; the produced dae reports
  version 2.0.0 or embeds equivalent build metadata.
- The full build exits zero. Recovery/sysupgrade images, packages, manifest,
  hashes, source pins, license notices, and sanitized build report validate.
- A source/binary scan finds no credentials, host IPs, or local account data.

### Interactive lab

- QEMU uses KVM when available and reaches a stable OpenWrt boot.
- LuCI returns an HTTP(S) success response through the host-loopback port and
  through the documented SSH local-forwarding path, while the same service is
  unreachable directly on the Droplet's public address.
- Rebooting the host restores the lab without manual intervention.
- The architecture-difference manifest proves the lab and firmware use the
  same OpenWrt source pin while clearly listing target-specific differences.

### Two-router course

- An automated smoke test proves endpoint A can reach the authorized endpoint
  B path through both routers and that an intentionally forbidden flow is
  blocked.
- Tests visibly distinguish route lookup, forwarding, firewall state, NAT, DNS,
  and MTU behavior.
- A reset command restores a known topology without deleting unrelated host or
  cloud resources.
- Every tutorial command is tested on the provisioned host and is stored in
  GitHub with expected-output patterns rather than private raw output.

### Backup and handoff

- The remote default branch contains the final spec, scripts, topology,
  tutorials, provenance, and sanitized verification report.
- A new prerelease contains only verified firmware/lab artifacts with SHA-256
  manifests and prominent experimental/not-for-stock-layout warnings.
- The handoff gives the SSH forwarding command using a local alias or
  placeholder, service status commands, lab reset, password rotation, release
  URL, current hourly burn, and exact destroy command.

## Failure behavior

- On any source-integrity, toolchain-version, compile, package, boot, or
  verification failure, preserve a bounded sanitized log and do not publish the
  failed output as successful.
- If dae cannot be integrated without unsupported kernel changes or exceeds the
  E8450 image constraints, stop publication, record the exact failure, and
  keep the last validated non-dae firmware release unchanged.
- If the requested premium size cannot be created because of quota/capacity,
  do not silently substitute a smaller Droplet. Record the provider error and
  request direction.
- If the cloud host approaches 85% disk usage, preserve manifests/logs and stop
  before corrupting the build; do not attach billable storage without new
  authorization.
- If the GitHub push or release upload fails, retain verified cloud artifacts
  and retry publication without rebuilding.

## Apply plan

1. Connect the workspace to the existing GitHub repository, preserve ignored
   secrets, commit/push this contract, and add versioned build/lab scripts.
2. Create the first two exact premium Basic Droplets. After explicit user
   authorization, verify and retire the exact volume-free legacy Droplet, wait
   for inventory convergence, then create the third premium Basic Droplet.
   Verify all SSH/bootstrap states and record sanitized cost evidence.
3. Build and verify the E8450 dae bundle with Go 1.26.4.
4. Build and boot the x86-64 lab image; configure loopback-only LuCI forwarding
   and durable supervision.
5. Instantiate and test the two-router exercises; write the beginner-safe
   tutorial from observed results.
6. Publish the verified prerelease and push sanitized verification/provenance.
7. Leave all three hosts running for the user's month-end study window unless the
   user asks for immediate cleanup; report the exact live hourly burn and
   destroy commands.

## Rollback

- Stop lab services: `sudo systemctl disable --now openwrt-lab.service` and the
  two-router topology unit(s).
- Remove only `/srv/openwrt-lab` after resolving the path and preserving any
  unpublished verified artifacts.
- Delete the new prerelease with
  `gh release delete <tag> --repo dual1208/os-lab-distributions --cleanup-tag`.
- Destroy only the three recorded lab Droplet IDs with one exact-ID command per
  host, then poll inventory until all three are absent.
