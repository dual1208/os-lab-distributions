# NAT-rebinding stream gate integration contract

This source-only contract defines a dedicated production qualification gate for
the two lab WANs. It does not alter, install, or start the live candidate and it
does not by itself make that candidate production-ready.

## Transaction

The gate starts exactly one TCP connection from the A-side LAN process to the
B-side LAN process. The server performs one `accept` and closes its listening
socket; the client performs one `connect` and has no reconnect path. That
connection continuously exchanges authenticated, sequence-contiguous 1 MiB
records in both directions. Every completed record contributes its two
streaming SHA-256 values and reciprocal acknowledgements to one
domain-separated transcript.

After at least one record, the gate pins both edge service invocation IDs,
restart counts, direct epochs, direct connection instances, authenticated
identities, relay application counters, and the continuous-stream identity. It
then tests edge A and edge B, one at a time. No two temporary NAT rules may be
active together.

For one edge, the gate identifies the sole UDP socket owned by the pinned edge
process. It records the current relay-facing translated UDP port without
serializing it, inserts one exact source/interface/protocol/socket-scoped
temporary `MASQUERADE` rule with a disjoint port range, and deletes only that
socket's UDP conntrack entries. Immediately before each scoped deletion it pins
a fresh completed-record checkpoint; post-change evidence must advance beyond
that checkpoint, so progress from an earlier quiet interval cannot satisfy the
fault. The gate must observe exactly one new translated
port in the forced range and different from the prior port. After direct stream
progress resumes, every conntrack entry for the exact edge UDP socket—including
the peer-facing direct entry—must use the forced range, and that range must have
been disjoint from every pre-fault translated port. It retains the rule
until the original TCP stream completes a later full-duplex record.

The temporary rule is then removed and those same bounded conntrack entries are
deleted once more. The gate must observe another translated port different from
the forced port, complete another record on the original TCP connection, and
prove that the complete NAT ruleset is byte-for-byte equal to its pre-gate
snapshot. Failure and signal cleanup remove only either exact gate-owned rule
and also require that ruleset restoration; they never flush a table or delete
another source's conntrack state.

Every post-change boundary must again show both edges on authenticated healthy
direct paths with the same nonzero epoch. A boundary is valid in exactly one of
two forms:

* migration: both per-edge direct instances and the shared epoch are unchanged;
* withdrawal and re-establishment: both per-edge direct instances strictly
  increase and the shared epoch does not regress.

A mixed boundary, one-sided instance replacement, an epoch regression, or a
direct-data identity mismatch fails closed. Each mapping transition must resume
a later complete record within 25 seconds. Both edge invocations and restart
counts remain exact throughout. Edge relay application sent/received counters,
fallback, queue-drop, invalid, duplicate, and dropped counters remain unchanged.
Authenticated relay drop packet/byte counters also remain unchanged. Raw relay
forwarding may advance only within the existing bounded warm-association
allowance; it is not application-path evidence.

The stop marker is accepted only at a completed record boundary. Final evidence
must retain the pinned stream start, report one connection and zero reconnects,
account for exactly `records * 1048576` bytes in each direction, retain
contiguous sequence endpoints, and have independent maximum send/receive
progress gaps no greater than 25,000 ms.

## Sanitized result marker

The result is `/run/campus-link/nat-rebinding.result`, an atomic root-owned mode
0600 file. Its exact format-1 key order is:

```text
FORMAT=1
STATUS=pass
GATE=nat-rebinding
MODE=production
RUN_ID=<32 lowercase hex>
CANDIDATE_SHA256=<64 lowercase hex>
RUN_MANIFEST_SHA256=<64 lowercase hex>
PREREQUISITE_MARKER_SHA256=<64 lowercase hex>
START_MONOTONIC_MS=<uint>
COMPLETE_MONOTONIC_MS=<uint>
FAULT_SITES=2
FORCED_MAPPING_CHANGES=2
RESTORATION_MAPPING_CHANGES=2
MAPPING_CHANGE_OBSERVATIONS=4
SOCKET_MAPPING_PROFILE_CHECKS=4
UNTOUCHED_WAN_MAPPING_CHECKS=4
CONNTRACK_SCOPED_DELETIONS=4
NAT_RULESET_RESTORATIONS=2
FAULT_RECOVERY_TIMEOUT_MS=25000
MATCHED_DIRECT_EPOCH_CHECKS=4
MIGRATED_PATHS=<uint>
REESTABLISHED_PATHS=<uint>
HIGHER_DIRECT_INSTANCE_EDGE_CHECKS=<uint>
PROCESS_CONTINUITY_CHECKS=12
TCP_CONNECTIONS=1
TCP_RECONNECTS=0
STREAM_RECORD_BYTES=1048576
FULL_DUPLEX_RECORDS=<uint>
STREAM_BYTES_A_TO_B=<uint>
STREAM_BYTES_B_TO_A=<uint>
FIRST_A_TO_B_SEQUENCE=<uint>
LAST_A_TO_B_SEQUENCE=<uint>
FIRST_B_TO_A_SEQUENCE=<uint>
LAST_B_TO_A_SEQUENCE=<uint>
STREAM_TRANSCRIPT_SHA256=<64 lowercase hex>
MAX_PROGRESS_GAP_A_TO_B_MS=<uint>
MAX_PROGRESS_GAP_B_TO_A_MS=<uint>
EDGE_A_DIRECT_SENT_DELTA=<uint>
EDGE_A_DIRECT_RECEIVED_DELTA=<uint>
EDGE_A_DIRECT_PROGRESS_DELTA=<uint>
EDGE_A_RELAY_SENT_DELTA=0
EDGE_A_RELAY_RECEIVED_DELTA=0
EDGE_B_DIRECT_SENT_DELTA=<uint>
EDGE_B_DIRECT_RECEIVED_DELTA=<uint>
EDGE_B_DIRECT_PROGRESS_DELTA=<uint>
EDGE_B_RELAY_SENT_DELTA=0
EDGE_B_RELAY_RECEIVED_DELTA=0
RAW_RELAY_PACKET_LIMIT_PER_SITE=<uint>
RAW_RELAY_BYTE_LIMIT_PER_SITE=<uint>
RAW_RELAY_SITE_A_DELTA=<uint>
RAW_RELAY_SITE_A_BYTES_DELTA=<uint>
RAW_RELAY_SITE_B_DELTA=<uint>
RAW_RELAY_SITE_B_BYTES_DELTA=<uint>
```

`MIGRATED_PATHS + REESTABLISHED_PATHS` equals four. Each forced and
restoration transition also proves that the other WAN's relay-facing mapping
remained exactly unchanged, yielding four untouched-WAN checks.
Each transition also checks at least two exact-socket conntrack entries and the
forced/restored translated-port profile, yielding four socket-profile checks.
`HIGHER_DIRECT_INSTANCE_EDGE_CHECKS` equals twice
`REESTABLISHED_PATHS`. Every direct counter delta is positive; every raw relay
delta is nonnegative and no greater than its corresponding duration-derived
limit. The marker contains no address, translated port, interface, namespace,
PID, invocation ID, socket inode, credential, token, or key material.

## Central integration required before deployment

The installer must atomically install `scripts/nat-rebinding-gate.sh` as
`/usr/local/libexec/campus-link-nat-rebinding-gate`,
`tests/nat_rebind_gate.py` as
`/usr/local/libexec/campus-link-nat-rebind-gate.py`, and the new unit. All three
installed files must be included in the immutable candidate fingerprint.

The central chain must place `campus-link-nat-rebinding.service` immediately
after `campus-link-fault-in-stream.service`. Its prerequisite hash is the exact
`fault-in-stream.result` hash. The next gate must use the exact
`nat-rebinding.result` hash as its prerequisite. `campus_link_validate_chain`
must validate the displayed schema and all relations above, enforce monotonic
ordering after the fault-in-stream completion, and accept the through-name
`nat-rebinding`. The coordinator must remove this bounded marker before a new
run, and the next unit must both order after this service and assert this marker.

Existing markers are incompatible with this new chain member. Integration
therefore requires a fresh offline qualification run; an old marker must never
be reinterpreted or grandfathered.
