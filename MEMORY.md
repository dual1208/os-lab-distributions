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
  schedule large parts first, run slow work in a named PSMUX session, and treat
  only a checksum-backed `EXIT=0` marker as completion.
- Verification: two SFTP workers resumed existing parts inside the named
  `oslab-transfer` session; the final gate still hashes every manifest entry.
