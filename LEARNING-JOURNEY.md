# From source tree to trusted kernel: a first Linux kernel course

This course turns the OS Lab build into a path a newcomer can repeat and
understand. It does not begin with editing a random kernel file. It begins with
the more important question:

> How do I know which source I built, what configuration I gave it, what system
> can boot it, and whether the artifact I downloaded is still the artifact I
> tested?

By the end, you should be able to read a kernel build pipeline, make and explain
a small kernel-module change in a disposable virtual machine, diagnose common
configuration and dependency failures, and produce a checksummed experimental
artifact without risking a daily-use computer.

The versions in examples match this repository's 2026.07 build. They are
historical pins, not instructions to replace newer stable releases blindly.

The course has a deliberate order:

1. **Ideas and mental models** build intuition about the system.
2. **Precise formulations** turn that intuition into testable invariants.
3. **Runbook and labs** apply those invariants with observable commands.

Do not skip directly to the commands. A command is useful only when you know
which claim it is intended to prove.

# Part I: ideas and mental models

## The map before the journey

A useful mental model is a chain of evidence:

```text
contract -> exact sources -> isolated build root -> configuration
         -> compiler/toolchain -> kernel + modules -> userspace + initramfs
         -> archive -> checksums -> published release -> re-download check
```

Each link answers a different question:

| Link | Question it answers |
| --- | --- |
| Contract | What are we building, and what are we explicitly not doing? |
| Source pin | Which exact revision produced this result? |
| Build root | What host state was allowed to influence the build? |
| `.config` | Which kernel capabilities exist as built-ins, modules, or not at all? |
| Toolchain | Which compiler, linker, C library, and headers formed the system? |
| Initramfs | Can early userspace find and mount the real root filesystem? |
| Manifest | Can another person reconstruct the inputs and decisions? |
| Re-download | Did publication preserve the bytes we verified locally? |

The OS Lab contract is [`specs/build-and-release.md`](specs/build-and-release.md),
the source ledger is [`UPSTREAMS.tsv`](UPSTREAMS.tsv), and the physical-machine
handoff boundary is [`INSTALL.md`](INSTALL.md). Read those three files before
running a build.

## Safety laboratory

Use a disposable x86-64 virtual machine for every exercise that changes a
kernel, initramfs, module set, partition, or bootloader. Take a snapshot first.
Keep the VM's known-good kernel in its boot menu and keep its console available.

Do not begin on the Linksys router or either daily-use PC. OpenWrt, an LFS
rootfs, a kernel image, and a disk installer are four different artifacts. None
is interchangeable with another. This repository deliberately produces PC
bootstrap root filesystems rather than automatic disk installers, and its
OpenWrt image targets only the E8450 UBI layout.

For the full LFS build, a practical disposable builder has at least four CPU
threads, 16 GiB of memory, and substantially more than the script's 50 GiB
filesystem image available for sources, logs, and release archives. A first
kernel-only lab needs much less.

## Chapter 1: learn to trust a source tree

Start by cloning the distribution repository and inspecting, not executing:

```bash
git clone https://github.com/dual1208/os-lab-distributions.git
cd os-lab-distributions
git status --short
git log --oneline --decorate -12
column -t -s $'\t' UPSTREAMS.tsv | less -S
```

Notice the distinction between a release name, an annotated tag, and a commit
object. Human-readable tags are convenient; an immutable commit identifies the
source. This build records both where possible. For example, the final PC
kernel is Linux 7.1.5 at the commit listed in `UPSTREAMS.tsv`.

Exercise:

1. Pick Linux, systemd, and pacman from `UPSTREAMS.tsv`.
2. Write down the canonical upstream, the preserved fork or mirror, the tag,
   the commit, and why it is included.
3. Explain why the unpinned `master` entry for mainline Linux is preserved but
   is not a release build input.

The lesson is that “latest” is a discovery result, while a reproducible build
needs a recorded decision.

## Chapter 2: hashes are receipts, not signatures

The reference library is intentionally kept outside Git because it is large,
but its source ledger and manifest are versioned. After populating it from
`reference/SOURCES.tsv`, verify it from the repository root:

```bash
(cd reference && sha256sum --check MANIFEST.sha256)
```

A SHA-256 match proves that the bytes match the manifest. It does not, by
itself, prove who authored the manifest. Strong provenance combines a trusted
source location, a signed upstream release or checksum manifest when available,
an immutable revision, and a local content hash.

Exercise: corrupt a copy, never the original, and observe the failure.

```bash
cp reference/README.md /tmp/reference-readme.test
printf '\nchanged\n' >> /tmp/reference-readme.test
sha256sum /tmp/reference-readme.test
rm -f /tmp/reference-readme.test
```

This tiny experiment is the same principle used later for multi-gigabyte
rootfs archives.

## Chapter 3: understand the LFS bootstrap story

Linux From Scratch is a toolchain story before it is a kernel story. The build
roughly progresses through these worlds:

1. The host provides enough tools to begin.
2. A temporary cross-toolchain is built under the LFS prefix.
3. Temporary userspace tools are built against that controlled toolchain.
4. The process enters a chroot, where `/` is the new system rather than the
   Ubuntu host.
5. The final compiler, C library, shell, core utilities, systemd, and other
   packages are built inside that world.
6. The kernel, modules, firmware, and initramfs complete the bootstrap.

Read [`scripts/setup-lfs-builder.sh`](scripts/setup-lfs-builder.sh) and find:

- the file-backed ext4 image and its validated mount point;
- the unprivileged `build` user;
- the pinned jhalfs and LFS-book commits;
- the generated kernel configuration;
- the refusal to operate on dangerous broad paths.

Then read [`scripts/run-lfs-build.sh`](scripts/run-lfs-build.sh). Its durable
`EXIT=` marker is more important than a lively-looking log. A log says what was
happening; an exit marker says whether the stage finished successfully.

# Part II: precise formulations of the theory

The notation in this part is intentionally small. Its purpose is not to make
the work look academic; it is to make vague words such as “same,” “finished,”
and “bootable” precise enough to test.

## 1. A build is a directed acyclic graph

Model the pipeline as a directed acyclic graph $G=(V,E)$. Each vertex is a
stage—source acquisition, base build, finalization, packaging, publication,
verification, or cleanup. An edge $(u,v)$ means stage $v$ depends on stage $u$.

Each stage has a state

$$
s(v) \in \{\text{pending},\text{running},\text{succeeded},\text{failed}\}.
$$

A stage is eligible to start exactly when every direct predecessor succeeded:

$$
\operatorname{eligible}(v) \iff
\forall u\,((u,v)\in E \Rightarrow s(u)=\text{succeeded}).
$$

In this repository, a durable file containing `EXIT=0` is the evidence for
`succeeded`. A missing marker is not success, even if a process exists or an
output file has appeared. A nonzero marker is `failed`, not “mostly finished.”

This gives the core gate used throughout the runbook:

```text
LFS base EXIT=0 -> finalizer may start
finalizer EXIT=0 -> artifact validation may start
validation true -> release may publish
fresh download verification true -> cloud builder may be destroyed
```

## 2. An artifact is a function of declared inputs

Represent an artifact as

$$
A = F(S,C,T,E,P),
$$

where $S$ is source content, $C$ is configuration, $T$ is the toolchain, $E$
is the controlled build environment, and $P$ is the packaging procedure.

“Rebuild the same source” is therefore insufficient. Reproducibility requires
the relevant components of the tuple $(S,C,T,E,P)$ to be fixed or recorded.
For two builds $i$ and $j$, bit-for-bit reproducibility is the strong claim

$$
(S_i,C_i,T_i,E_i,P_i)=(S_j,C_j,T_j,E_j,P_j)
\Rightarrow H(A_i)=H(A_j),
$$

where $H$ is SHA-256. When the environments are not fully normalized, the
weaker but still useful goal is *explainable variance*: every changed artifact
hash must be attributable to a recorded input or packaging change.

## 3. A provenance record is a tuple, not a URL

For source input $k$, define

$$
p_k=(u_k,r_k,c_k,h_k,\sigma_k),
$$

where $u$ is the canonical upstream, $r$ is a human-readable release ref, $c$
is an immutable commit when applicable, $h$ is the downloaded content hash, and
$\sigma$ is available signature evidence.

The source is acceptable only when every required field for its source type is
present and verified. A Git URL alone leaves the revision unknown. A hash alone
identifies bytes but not their author. A tag name alone can be moved. The tuple
combines identity, integrity, and provenance.

`UPSTREAMS.tsv`, the source checksum manifests, and signed kernel.org checksum
manifests are concrete encodings of these tuples.

## 4. Kconfig is a toolchain-dependent fixed-point problem

For each configuration symbol $i$, let

$$
x_i \in \{0,1,2\}=\{n,m,y\}.
$$

Kconfig constraints map a proposed configuration $x$ and observed toolchain
capabilities $\tau$ to a normalized configuration:

$$
K(x,\tau)=x'.
$$

A configuration is converged in the build environment only when

$$
K(x,\tau_{\text{build}})=x.
$$

The toolchain matters because a symbol may be invisible on one host and visible
inside another chroot. `make olddefconfig` computes defaults for newly visible
symbols; `make listnewconfig` checks for unresolved additions; noninteractive
`make oldconfig </dev/null` verifies that no question remains.

For early boot, let $Y$ be features built into the kernel, $M$ be features built
as modules, and $I$ be modules included in the initramfs. The capabilities
available before mounting the real root filesystem are

$$
B = Y \cup (M \cap I).
$$

If $R$ is the set of capabilities required to locate and mount root, the boot
configuration must satisfy

$$
R \subseteq B.
$$

This is the precise reason that storage-controller and root-filesystem drivers
must be built in or deliberately included in the initramfs.

## 5. Release verification is set equality plus hash equality

Let the local release be a mapping from filenames to hashes,
$L=\{n\mapsto H(f_n)\}$, and let a fresh download be $D$. Verification requires

$$
\operatorname{names}(L)=\operatorname{names}(D)
$$

and

$$
\forall n\in\operatorname{names}(L),\quad L(n)=D(n).
$$

For cross-platform releases, filenames must also be unique under the target
filesystem's normalization function $N$:

$$
N(n_i)=N(n_j) \Rightarrow i=j.
$$

On a case-insensitive Windows filesystem, `sha256sums` and `SHA256SUMS` violate
that condition. Renaming one asset repairs the name set before hashes are even
considered.

## 6. Claims form an evidence ladder

Treat artifact claims as an ordered ladder:

$$
\text{bytes verified}
< \text{archive valid}
< \text{bootstrap rootfs complete}
< \text{VM boot observed}
< \text{target hardware validated}.
$$

Evidence for a lower rung does not imply a higher rung. A valid rootfs archive
is not automatically a disk image, installer, or boot-tested system. Release
language must name only the highest rung actually demonstrated.

## 7. Recovery should invalidate the smallest downstream set

If stage $v$ fails, repair $v$ and invalidate only $v$ plus descendants whose
outputs could depend on its failed or changed result. Formally, the minimum
rerun set is

$$
R_v=\{v\}\cup\operatorname{descendants}(v).
$$

Completed ancestors remain valid when their inputs and outputs are unchanged.
This is why a kernel-configuration failure did not justify rebuilding OpenWrt,
and a GitHub upload failure would not justify recompiling either operating
system.

## 8. The terminal cleanup predicate

Let $V_o$ and $V_l$ mean the OpenWrt and Linux releases passed fresh-download
verification, and let $D$ mean the exact temporary builder is absent from
normalized inventory. The task is complete only when

$$
V_o \land V_l \land D.
$$

Destruction is authorized after $V_o\land V_l$ is true, never merely because a
build process ended. Cleanup is part of correctness because a forgotten paid
builder is an unbounded side effect of the experiment.

# Part III: runbook and observable labs

Every command below is paired with a claim to observe. Keep a lab notebook with
the command, its exit status, the relevant bounded output, and your conclusion.

## Chapter 4: Kconfig is a dependency graph

Kernel configuration symbols have three common states:

- `y`: built into the kernel image;
- `m`: built as a loadable module;
- unset: not built.

Boot-critical storage and filesystem support is often safest as `y`, because a
module stored on the root filesystem cannot help the kernel find that same root
filesystem unless the module is already inside the initramfs. Hardware that is
not needed until later can usually be `m`.

In a disposable VM, install the normal build prerequisites for its distribution,
then use a pinned kernel tree and a separate output directory:

```bash
git clone --depth 1 --branch v7.1.5 \
  https://github.com/dual1208/linux-stable.git linux-study
mkdir linux-study-build
cd linux-study
make O=../linux-study-build x86_64_defconfig
scripts/config --file ../linux-study-build/.config --enable EFI
scripts/config --file ../linux-study-build/.config --enable EFI_STUB
scripts/config --file ../linux-study-build/.config --enable BLK_DEV_NVME
scripts/config --file ../linux-study-build/.config --enable EXT4_FS
scripts/config --file ../linux-study-build/.config --disable GCC_PLUGINS
make O=../linux-study-build olddefconfig </dev/null
```

Inspect the result:

```bash
grep -E '^(CONFIG_EFI|CONFIG_BLK_DEV_NVME|CONFIG_EXT4_FS)=' \
  ../linux-study-build/.config
make O=../linux-study-build listnewconfig
```

The `olddefconfig` step accepts defaults for newly visible symbols. The final
`listnewconfig` should be empty. For automation, also prove that an interactive
prompt cannot block the pipeline:

```bash
timeout 60 make O=../linux-study-build oldconfig </dev/null
```

### Failure story: the invisible option that became visible

The real OS Lab build generated a kernel configuration on the Ubuntu host.
There, GCC-plugin support was not visible to Kconfig. Inside the completed LFS
toolchain it became visible, so jhalfs' `make oldconfig` asked a new question.
No human was attached; the 60-second guard terminated the stage.

The repair was not to remove the guard or feed endless `yes` input. We made the
decision explicit with `scripts/config --disable GCC_PLUGINS`, converged with
`olddefconfig`, proved `oldconfig` was noninteractive, and reran only the failed
predecessor. The reusable lesson is:

> Kconfig visibility can depend on the toolchain. A generated `.config` is not
> finished until it converges in the environment that will compile it.

## Chapter 5: compile, then inspect before installing

Build the image and modules without touching the VM's boot files:

```bash
cd linux-study
make O=../linux-study-build -j"$(nproc)" bzImage modules
file ../linux-study-build/arch/x86/boot/bzImage
du -h ../linux-study-build/arch/x86/boot/bzImage
```

Useful inspection commands include:

```bash
grep '^CONFIG_LOCALVERSION=' ../linux-study-build/.config
find ../linux-study-build -name '*.ko' | head
modinfo ../linux-study-build/drivers/virtio/virtio.ko 2>/dev/null || true
```

Do not run `make install` on your daily-use machine as a first exercise. In the
VM, install into a staging directory first:

```bash
rm -rf /tmp/kernel-stage
make O=../linux-study-build modules_install \
  INSTALL_MOD_PATH=/tmp/kernel-stage
find /tmp/kernel-stage/lib/modules -maxdepth 2 -type f | head
```

Staging reveals exactly what installation would add while keeping the boot
configuration untouched.

## Chapter 6: make your first kernel-adjacent change

An out-of-tree module is a good first coding lab because it exercises the
kernel build interface without requiring a full source patch. Do this only in
a disposable VM whose running kernel has matching headers.

Create `hello.c`:

```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int __init hello_init(void)
{
    pr_info("oslab_hello: module loaded\n");
    return 0;
}

static void __exit hello_exit(void)
{
    pr_info("oslab_hello: module unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OS Lab first module");
```

Create `Makefile` (the command under `all` and `clean` must begin with a tab):

```make
obj-m += hello.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
```

Build, inspect, load, observe, and unload:

```bash
make
modinfo ./hello.ko
sudo insmod ./hello.ko
sudo dmesg | tail -n 10
sudo rmmod hello
sudo dmesg | tail -n 10
```

If `insmod` reports an invalid module format, compare `uname -r` with
`modinfo -F vermagic ./hello.ko`. That mismatch is evidence that modules are
coupled to the configured and built kernel, not generic plugin files.

Change the message, rebuild, and use `git diff` to review the smallest possible
change. That edit-build-observe loop is the seed of kernel development.

## Chapter 7: kernel, firmware, initramfs, and rootfs are partners

The kernel image contains executable kernel code. Modules extend it. Firmware
is data uploaded to devices. The initramfs is early userspace that finds storage,
assembles encryption or RAID if needed, and mounts the real root filesystem.
The rootfs supplies the long-lived userspace, including systemd.

Use a running Linux VM to see the relationships:

```bash
uname -a
cat /proc/cmdline
findmnt /
lsinitrd 2>/dev/null | less || unmkinitramfs /boot/initrd.img-"$(uname -r)" /tmp/initrd-view
lspci -nnk
lsmod | head
journalctl -k -b | less
```

The OS Lab finalizer builds a broad shared kernel, installs linux-firmware,
generates a generic dracut initramfs, and packages two rootfs variants. It does
not know the final disk labels, encryption topology, administrator account, or
EFI boot entry. Those remain manual installation decisions in `INSTALL.md`.

## Chapter 8: distinguish portability from optimization

Both PC archives use an `x86-64-v3` userspace baseline. Future locally rebuilt
packages receive either `-mtune=znver5` or `-mtune=skylake`. The important
distinction is:

- `-march` can enable instructions and changes where a binary can run;
- `-mtune` changes scheduling choices while retaining the selected instruction
  baseline.

The shared kernel stays broad rather than being stripped to one laptop. A
recovery-capable kernel that boots both target machines is more valuable than
a tiny kernel optimized so narrowly that storage, display, or networking
vanishes during troubleshooting.

Exercise: inspect the released hardware profile and makepkg fragment after the
release is available, then explain why tuning belongs to future userland package
rebuilds rather than the boot and recovery boundary.

## Chapter 9: dependencies should be deliberate

Autoconf options often default to “auto”: enable a feature when its dependency
appears to be wanted. Auto-detection is convenient interactively but can make a
minimal bootstrap unpredictable.

### Failure story: curl and optional libpsl

The finalizer's curl configuration detected that public-suffix support was
wanted but the LFS base did not include libpsl. Configuration stopped before
packaging. We documented the bootstrap boundary and passed
`--without-libpsl`, keeping HTTPS through OpenSSL and the threaded resolver
while declining one optional feature.

The lesson is not “disable every dependency.” It is:

1. Decide whether the feature is required by the contract.
2. If required, add and pin the dependency.
3. If optional, disable it explicitly.
4. Record the tradeoff and rerun only the affected stage.

### Failure story: initramfs is its own userspace

After the kernel and modules succeeded, dracut still could not create an
initramfs. GNU cpio was absent, and dracut's automatically selected systemd
modules depended on `systemd-sysusers`, which this minimal rootfs intentionally
did not install. The repair added pinned GNU cpio and explicitly selected
dracut's traditional non-systemd initramfs path. A further compiler boundary
appeared because cpio 2.15 predates GCC 16's newer default C dialect: the source
was tested and then built explicitly as GNU C17 instead of being patched
speculatively.

This does not change PID 1 in the installed rootfs: the final system still uses
systemd after the real root is mounted. Early userspace and the long-lived
rootfs are separate dependency environments. Formally, adding a userspace
component to the rootfs does not imply that it belongs to the early-boot set
$B=Y\cup(M\cap I)$ or that all of its companion tools exist in the initramfs.

The reusable test is twofold: the initramfs file must be nonempty, and
`lsinitrd` must be able to enumerate it before packaging continues.

There is a subtle validation boundary here: `lsinitrd` belongs to dracut and is
not guaranteed to exist on a later download workstation. The builder therefore
enumerates the image with the tool from the rootfs that produced it. A fresh
download then proves byte identity with SHA-256 and repeats every portable
check. If $I_b$ is the builder-tested image and $I_d$ is the download, the
handoff argument is

$$
\operatorname{listable}(I_b)\land
H_{\mathrm{SHA256}}(I_b)=H_{\mathrm{SHA256}}(I_d)
\Longrightarrow I_d=I_b
$$

under the standard collision-resistance assumption. This is stronger than
silently skipping a tool: the skip is explicit, and it is allowed only after
the checksum manifest has passed.

### Failure story: configuration cannot promise a missing capability

Pacman 7.1.0 was deliberately built without GPGME to keep the bootstrap's
dependency closure small. Its first configuration nevertheless set `SigLevel`,
which asks libalpm to use signature support that was not compiled in. Pacman
correctly rejected the contradiction before initializing its local database.

The repair removed signature directives and retained an empty repository set.
This is suitable only for the two locally created bootstrap metadata packages;
it is not permission to consume unsigned network repositories. Before adding a
repository, rebuild pacman with GPGME, create or import a trusted keyring, and
define an actual signature policy. A second package-boundary check ensures
`.PKGINFO` is stored at the archive root rather than under a leading `./`, then
uses `pacman -Qp` to prove libalpm recognizes the package before installation.
The general invariant is:

$$
\text{configured capabilities}\subseteq\text{compiled capabilities}.
$$

## Chapter 10: make failure resumable

Long builds should run as named, logged jobs and emit a durable terminal record.
This repository's wrappers write:

```text
START=<UTC time>
...
EXIT=<numeric status>
END=<UTC time>
```

The controlling rule is simple:

```bash
grep -qx 'EXIT=0' /home/build/oslab/lfs-build.exit
```

Only that result authorizes the finalizer. A missing marker means running or
interrupted; a nonzero marker means diagnose and repair the same stage. Never
publish a partial output directory merely because it contains large files.

When diagnosing, preserve a bounded tail and locate the package-specific log:

```bash
tail -n 80 /home/build/oslab/lfs-build.log
find /mnt/oslab-lfs/jhalfs/logs -type f -mmin -30 -print
```

Read errors as evidence, not as commands. Determine the failed layer before
changing anything.

## Chapter 11: package reproducibly

The finalizer uses deterministic archive ordering and timestamps, preserves
numeric owners, ACLs, and extended attributes, and records profiles separately.
Study the `tar` and `rsync` invocations in
[`scripts/finalize-lfs.sh`](scripts/finalize-lfs.sh).

After an artifact exists, test structure before release:

```bash
zstd --test oslab-2026.07-zen5-rootfs.tar.zst
tar --zstd -tf oslab-2026.07-zen5-rootfs.tar.zst | head
sha256sum --check SHA256SUMS
```

A rootfs archive may be internally valid without being boot-tested. Labeling is
part of engineering: say “experimental bootstrap rootfs,” not “installer” or
“bootable image,” until a bounded boot test proves the stronger claim.

## Chapter 12: publication is another build stage

The OpenWrt release exposed a Windows-specific lesson. Upstream provided a file
named `sha256sums`; the release collector also created `SHA256SUMS`. Linux treats
those as distinct names, while the Windows download filesystem does not. The
repair renamed the upstream copy to `OPENWRT-UPSTREAM-SHA256SUMS` and retained
`SHA256SUMS` for the release manifest.

Before publishing, check for case-folded collisions:

```bash
find . -maxdepth 1 -type f -printf '%f\n' |
  awk '{ key=tolower($0); if (seen[key]++) print "collision: " $0 }'
```

After publication, download into a fresh directory and verify again:

```bash
mkdir release-verification
gh release download <tag> --repo <owner/repository> \
  --dir release-verification
cd release-verification
sha256sum --check SHA256SUMS
```

This is not redundant. It tests the release boundary, asset selection, naming,
and bytes served to future users.

### Failure story: the transport has a smaller unit than the artifact

The two LFS rootfs archives are each larger than GitHub's 2 GiB per-asset
limit. That is a publication constraint, not a reason to rebuild or weaken
compression. The packaging gate splits each already-validated byte stream into
1,900 MiB parts and records two layers of checksums. If archive $A$ becomes
ordered parts $P_0,\ldots,P_n$, the required invariants are

$$
A=P_0\Vert\cdots\Vert P_n,\qquad |P_i|<2^{31},\qquad
H(A)=H(P_0\Vert\cdots\Vert P_n).
$$

`SHA256SUMS` authenticates each transported part; `ROOTFS-SHA256SUMS`
authenticates the reconstructed archive. The release validator streams the
parts directly through SHA-256, zstd, and tar, so verification does not require
another multi-gigabyte temporary copy. This is the general mental model:
packaging may change transport framing, but must not change artifact semantics.

## Chapter 13: reproduce the full OS Lab build

Do this only after the smaller labs, on a disposable Ubuntu builder. Review all
scripts before using root. The intended layout places this repository at
`/home/build/oslab` and provides a dedicated unprivileged `build` account.

The high-level sequence is:

```bash
cd /home/build/oslab
sudo ./scripts/setup-lfs-builder.sh
sudo -u build ./scripts/run-lfs-build.sh
grep -qx 'EXIT=0' ./lfs-build.exit
sudo ./scripts/run-lfs-finalize.sh
grep -qx 'EXIT=0' ./lfs-finalize.exit
cd /srv/oslab-output
sha256sum --check SHA256SUMS
```

In practice, run the two long wrappers in a detached terminal multiplexer and
inspect one bounded status snapshot at a time. Do not launch the finalizer when
the predecessor marker is missing or nonzero.

Before treating a reproduction as equivalent, compare:

- `BUILD-MANIFEST.txt`;
- `UPSTREAMS.tsv`;
- `SOURCE-SHA256SUMS` and `LFS-SOURCE-SHA256SUMS`;
- the expanded kernel configuration;
- archive SHA-256 values;
- the package database and hardware profile inside each rootfs.

Exact artifact hashes can legitimately change after a documented source,
toolchain, configuration, or packaging change. The goal is explainable change,
not a magical hash divorced from its inputs.

## Chapter 14: your first upstream-style patch

Once the module lab is comfortable, practice a source-tree change without
submitting it anywhere:

```bash
cd linux-study
git switch -c study/describe-change
# Make one small, reviewable documentation or self-test change.
git diff --check
git diff
git add <path>
git commit -s
git format-patch -1 --stdout > ../first-kernel-patch.patch
```

A useful kernel patch explains the observed problem, the responsible layer,
why the change is correct, and how it was tested. Prefer a tiny change you can
prove over a dramatic change you cannot explain.

Read `Documentation/process/submitting-patches.rst` and the relevant subsystem
documentation in the kernel tree before considering upstream submission. Do
not send a practice patch to a mailing list.

## Graduation checklist

You are ready for a second course when you can do all of the following without
guessing:

- identify an exact kernel source revision and verify its archive;
- explain `y`, `m`, and unset Kconfig states;
- converge a configuration noninteractively and identify newly visible symbols;
- build a kernel and modules into a separate output/staging directory;
- build, load, observe, and unload a tiny module in a disposable VM;
- explain the roles of firmware, initramfs, rootfs, and bootloader;
- diagnose a failure from its first relevant error rather than its last noisy
  line;
- resume only after correcting the failed stage;
- generate and verify a release checksum manifest;
- state honestly whether an artifact is a kernel, rootfs, disk image, installer,
  or tested boot image.

The most transferable lesson from this journey is that kernel development is
not merely compilation. It is controlled experimentation: make one explicit
decision, preserve the evidence, test at the correct boundary, and keep a known
way back.
