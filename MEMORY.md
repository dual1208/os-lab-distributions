# Durable engineering memory

## 2026-07-27 — Large local transfers need supervision and resumability

- Symptom: a serial SCP transfer was extremely slow, and a detached local
  PowerShell worker later vanished during a task-host refresh without a terminal
  marker.
- Root cause: one transport stream underused the available path; `Start-Process`
  detached from the command but did not provide a durable supervisor boundary.
- Decisive evidence: partial-file size and I/O counters proved forward progress;
  the worker and SFTP processes later disappeared while partial files remained
  and no success marker existed.
- Reusable lesson: resume exact files with SFTP `reget`, bound concurrency,
  schedule large parts first, and run slow work in a named PSMUX session. PSMUX
  survives an agent turn but not a Windows sign-out or server recreation, so
  durable data plus a checksum-backed `EXIT=0` marker—not the supervisor—define
  completion.
- Verification: two SFTP workers resumed existing parts inside the named
  `oslab-transfer` session; the final gate still hashes every manifest entry.

## 2026-07-27 — Cloud deletion needs an observed postcondition

- Symptom: the exact droplet delete command succeeded, but the first immediate
  normalized inventory read still contained the target.
- Root cause: control-plane deletion and inventory convergence are separate
  events.
- Decisive evidence: the following bounded normalized read showed the exact ID
  and name absent while the unrelated machine set was unchanged.
- Reusable lesson: never equate an accepted destructive request with completed
  cleanup; verify target absence and preservation of out-of-scope resources.
- Verification: `osforge` was absent and one unrelated machine remained.

## 2026-07-28 — BTF host tooling needs a narrow serial gate

- Symptom: two independent clean `make -j4 world` builds stopped at
  `tools/dwarves` with only the OpenWrt top-level failure retained.
- Root cause: the pinned dwarves host-tool stage was not reliable under the
  clean parallel schedule on these four-vCPU builders; the surrounding
  OpenWrt configuration and source pins were identical across both failures.
- Decisive evidence: `make tools/dwarves/compile -j1 V=s` configured, compiled,
  linked, and installed all 59 Ninja steps successfully from the same tree.
- Reusable lesson: prebuild only `tools/dwarves` with `-j1` when full kernel BTF
  is selected, retain the verbose diagnostic, then return to bounded parallel
  world compilation. Do not serialize the entire firmware build.
- Verification: both incremental jobs passed the former dwarves failure point
  and entered the LLVM BPF host-tool build.

## 2026-07-28 — Bound LLVM host-tool memory, and distrust trap-only success

- Symptom: an 8 GiB builder's LLVM/BPF tools build ended with systemd
  `Result=oom-kill`, but the Bash EXIT trap wrote `EXIT=0` and no artifacts
  existed.
- Root cause: the OpenWrt jobserver admitted six large `cc1plus` processes whose
  combined resident memory exhausted the swapless host; cgroup termination also
  let the trap observe a misleading zero status.
- Decisive evidence: the kernel OOM record showed one compiler at roughly
  1.7 GiB RSS, systemd recorded `oom-kill`, and the artifact directory was
  empty.
- Reusable lesson: constrain memory-heavy host tools separately from the main
  build and define success as an explicit end-of-pipeline marker plus artifact
  checks, never as a trap's status alone.
- Verification: an initial `make -j2` retry still spawned six compiler children,
  proving the recursive jobserver assumption false. The scripts now bootstrap
  Ninja and pass an explicit `NINJA=... -j2` override while retaining four
  outer make jobs; an intentional stop also proved the corrected trap writes
  `EXIT=1`.
