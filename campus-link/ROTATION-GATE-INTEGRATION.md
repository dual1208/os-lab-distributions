# Certificate-rotation gate integration contract

The rotation gate in this tree is source-only and fail-closed. It does not make
the production candidate production-ready, and it must not be inserted into the
live qualification chain until the fixed privileged driver and the stable
candidate-state integration below are implemented and tested.

## Stable candidate binding

`campus_link_candidate_fingerprint` currently hashes the active leaf, key, and
authorization files directly. A legitimate rotation therefore changes the
candidate fingerprint. The central helper must replace only those mutable
identity entries with this bounded construction:

1. Hash every executable, unit, structural configuration field, topology rule,
   and non-identity security-policy file exactly as today.
2. Hash one root-owned, non-symlink, mode-`0444`, size-bounded rotation manifest
   as an immutable candidate input.
3. The manifest has one fixed schema and thirteen logical artifacts:
   `relay.config`, `relay.control-cert`, `relay.control-key`, and, for each of
   `edge-a` and `edge-b`, `config`, `control-cert`, `control-key`, `data-cert`,
   and `data-key`. It contains complete SHA-256 rows for `pre`, `overlap`,
   `relay-next`, `edge-a-next`, `edge-b-next`, `retiring`, and `post`. It also
   contains the five exact public current/next identity assignments. It contains
   no private-key bytes.
4. Before returning a fingerprint, recompute all thirteen artifact hashes and
   match the entire row selected by the atomic stage marker. Reject a missing or
   extra artifact, a symlink, wrong ownership/mode, a row assembled from two
   states, an unknown state, an unsealed manifest, or any run/candidate/
   rotation/manifest binding mismatch. Never accept a caller-supplied path or a
   leaf-derived authorization.
5. The initial fingerprint bootstrap is allowed only with no active transaction
   and an exact `pre` row. The qualification coordinator then atomically writes
   the run manifest and a stage marker bound to the resulting candidate digest.
   Every later fingerprint check requires that bound marker. A transition may
   temporarily make the selected row fail validation; the gate lock prevents a
   concurrent qualification, and a crash leaves the candidate invalid until
   bounded recovery restores one complete row.
6. The driver writes `STATE=retiring` before removing any old authorization.
   That state chooses the forward-safe `next-only` rollback floor. `post` is
   written only after all artifacts match the complete post row.

The stage marker is root-owned, mode `0600`, atomic, and ordered exactly as:

```text
FORMAT=1
RUN_ID=<32 lowercase hex>
CANDIDATE_SHA256=<64 lowercase hex>
ROTATION_ID=<32 lowercase hex>
ROTATION_MANIFEST_SHA256=<64 lowercase hex>
STATE=<bounded state name>
```

The marker is validation state, not candidate input; its bindings and selected
artifact row are checked on every candidate re-evaluation. This avoids a digest
cycle while preventing an unconstrained credential exclusion.

## Fixed driver boundary

The systemd gate accepts only
`/usr/local/libexec/campus-link-certificate-rotation-driver`, which must be part
of the installed release manifest. Production environment overrides are
rejected. The driver implements three bounded verbs:

- `prepare` validates the sealed manifest, snapshots exact service and artifact
  state, and atomically writes the run-bound `pre` stage before mutation;
- `execute` owns atomic credential/config replacement, authenticated relay
  participant coordination, supervised reloads, the continuously reused
  bidirectional stream, old/next handshake fixtures, expiry fixtures, and the
  sanitized transcript consumed by `certificate_rotation_gate.py`;
- `rollback` restores the complete current-plus-next row before retirement or
  the complete next-only row from `retiring` onward, then proves credential,
  authorization, service, and direct-path state in its exact JSON marker. Its
  selected state is exactly `overlap` for the pre-retirement floor and `post`
  for the next-only floor; the coordinator revalidates the bound stage marker
  after accepting that JSON.

The driver must not use a general shell hook, an unpinned executable, a
caller-controlled path, a password, or a private key copied into evidence. A
relay participant needs a separately authenticated least-privilege control
channel; root SSH and shared site keys are not an acceptable production
substitute.

## Central patches required before activation

- Install and candidate-bind the gate script, validator, fixed driver, sealed
  manifest, and `campus-link-certificate-rotation.service`.
- Add the new service after `fault-in-stream` and before `24h-soak`; make the
  24-hour unit assert `certificate-rotation.result` rather than
  `fault-in-stream.result` directly.
- Clear only the bounded rotation pass/failure markers when starting a fresh
  chain. Never clear a leftover active or closed-transaction marker; recover it
  first. A pass marker coexisting with either transaction marker is invalid.
- Extend `campus_link_validate_chain` with the exact ordered pass-marker schema
  exported by `PASS_MARKER_KEYS`, require its prerequisite hash to equal the
  fault-in-stream marker hash, and require the 24-hour prerequisite hash to
  equal the rotation marker hash.
- Include the rotation unit in every installer/rollback active-unit guard and
  snapshot. Preserve an unverified active marker across rollback failure.
- Extend the release installer allowlists for
  `campus-link-certificate-rotation`,
  `campus-link-certificate-rotation-validate.py`, the fixed driver, and the new
  unit. The driver and sealed manifest are mandatory; the unit must remain
  unstartable while either is absent.

## Required adversarial tests

The focused validator tests already reject early/out-of-window next slots,
missing observers, mixed slot matrices, stale invocations/sessions, missing
direct-instance transitions, stream loss/duplication, excessive outage,
partial old-pin retirement, cutoff overrun, unsafe rollback, schema expansion,
and secret-bearing evidence. Central integration must additionally mutate each
of the thirteen artifact hashes in every state, splice every pair of state rows,
swap stage order, alter each stage binding, replace manifest/stage/artifacts
with symlinks, change ownership/mode, kill the driver between every atomic
replacement, and kill it immediately before and after `retiring`. Every case
must either retain one exact committed row or fail candidate validation and
complete the correct bounded rollback; none may emit a pass marker.
