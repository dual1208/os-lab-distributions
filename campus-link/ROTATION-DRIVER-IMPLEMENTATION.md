# Certificate-rotation driver implementation status

This note records the source-only implementation behind
`ROTATION-GATE-INTEGRATION.md`. It is not production evidence and does not make
the campus-link candidate production-ready.

## Implemented source boundary

The fixed driver is `scripts/certificate_rotation_driver.py`. It accepts only
the ordered `prepare`, `execute`, and `rollback` argument sets used by
`scripts/certificate-rotation-gate.sh`. Production paths are constants; only
`isolated-test` may relocate the same path tree beneath
`CAMPUS_LINK_ROTATION_TEST_ROOT`. There is no process-launch, remote-command,
password, or caller-supplied executable interface.

`scripts/campus_link_rotation_state.py` provides the shared strict parser and
atomic filesystem primitives. It validates:

- the exact seven states, thirteen logical artifacts, and transition change
  sets;
- canonical, duplicate-free JSON and ordered, duplicate-free marker schemas;
- regular non-symlink inputs, exact Linux modes and ownership, bounded stable
  reads, and durable atomic replacements;
- all 91 state/artifact hashes, all ten unique public SPKI assignments, exact
  SPIFFE endpoint/plane profiles, and one common circuit;
- certificate SPKI values by parsing the certificate DER rather than trusting
  a caller-provided leaf pin; and
- complete live rows, rejecting missing, extra, mixed, or altered artifacts.

`scripts/certificate_rotation_manifest.py` seals or verifies the manifest using
only fixed paths. In isolated mode it hashes complete fixture rows and checks
their configuration/certificate semantics before publication. It never writes
private material into the manifest.

The isolated driver snapshots the complete pre-state before mutation, advances
only through sealed rows, writes `retiring` before removing old authorization,
and restores exactly `overlap` or `post` during rollback. Its transcript and
rollback JSON are accepted by `tests/certificate_rotation_gate.py`. Evidence
contains only bindings, counters, slot labels, and booleans.

## Production fail-closed boundary

Production sealing and mutation intentionally return failure. A safe production
implementation needs an authenticated participant on each of the two edges and
the relay. The coordinator must never collect the relay private key or either
edge private key to construct a row.

The missing participant protocol must provide all of the following before the
production guard can be removed:

1. TLS 1.3 mutual authentication with separately provisioned, role-constrained
   participant keypairs; no shared site key and no bearer secret fallback.
2. A release-pinned fixed RPC vocabulary for hash attestation, bounded artifact
   installation, supervised reload, observation, and rollback. It must have no
   arbitrary path, command, or payload destination.
3. Canonical responses signed over the run, candidate, manifest, transaction,
   stage, participant role, request nonce, monotonic sequence, requested row,
   artifact hashes, and service instance identifiers.
4. Exact three-participant quorum and replay protection. A missing, duplicated,
   stale, wrong-role, or mixed-row response fails the transaction.
5. Local keypair/certificate validation and atomic replacement on the owning
   host. Private-key bytes never cross the participant boundary.
6. Participant-measured handshake, continuously reused stream, expiry cutoff,
   service invocation, control-session, and direct-instance observations. The
   isolated simulator cannot be promoted as a substitute for these facts.

## Required release integration

These source-to-install mappings must be added to both the release manifest and
the edge installer/rollback snapshot allowlists:

| Release source | Fixed installed path | Mode |
| --- | --- | --- |
| `scripts/certificate_rotation_driver.py` | `/usr/local/libexec/campus-link-certificate-rotation-driver` | `0755` |
| `scripts/certificate_rotation_manifest.py` | `/usr/local/libexec/campus-link-certificate-rotation-manifest` | `0755` |
| `scripts/campus_link_rotation_state.py` | `/usr/local/libexec/campus_link_rotation_state.py` | `0644` |
| `scripts/certificate-rotation-gate.sh` | `/usr/local/libexec/campus-link-certificate-rotation` | `0755` |
| `tests/certificate_rotation_gate.py` | `/usr/local/libexec/campus-link-certificate-rotation-validate.py` | `0755` |
| `systemd/campus-link-certificate-rotation.service` | `/etc/systemd/system/campus-link-certificate-rotation.service` | `0644` |

The installer and rollback active-unit guards must include the rotation unit.
The installed release manifest and candidate fingerprint must bind all five
installed code files and the unit. The candidate fingerprint must additionally
bind the sealed `/var/lib/campus-link/rotation/manifest.json`, then validate the
stage-selected distributed artifact attestations on every recheck. The unit
must remain unstartable while the manifest, participant identities, or any
participant are absent.

## Coordinator crash edge requiring a central patch

The current coordinator sets `rollback_required=1` only after `prepare` returns.
A kill after the driver's final atomic `STATE=pre` write but before process exit
therefore leaves a bound stage marker while cleanup believes rollback is not
required. No live credential has changed, but the stale marker correctly blocks
the next run. Cleanup must detect this exact bound `pre` marker and either prove
the complete pre row before removing it or run bounded pre-retirement recovery.
It must reject every other marker or mixed row. This change belongs in the
central coordinator specification and tests before behavior changes.

## Verification

`tests/test_certificate_rotation_driver.py` covers full validator-compatible
rotation, both rollback floors, strict paths and verbs, every stage binding,
marker order, mode and symlink replacement, all 91 state/artifact mutations,
all distinct cross-state splices, semantic pin/certificate misassignment, every
prepare replacement kill point, every execute replacement kill point, and kills
immediately before and after `retiring`.
