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
