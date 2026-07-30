# Accelerated edge-kill stream gate integration contract

This source-only contract closes the fresh-connection loophole in the
accelerated one-sided edge-recovery gate. It does not change a live candidate
and does not make the candidate production-ready.

## Per-trial transport transaction

Every target-edge kill owns one new, root-private evidence directory and one
dedicated TCP port. Before the signal, the runner starts `serve-once` at the
remote LAN process and `continuous-client` at the local LAN process. The
server closes its listening socket immediately after its sole `accept`; the
client performs exactly one `connect` and has no reconnect path.

The runner must observe at least one complete, sequence-contiguous full-duplex
record before taking either edge's supervised-state snapshot and sending
`KILL`. The pre-kill checkpoint pins the stream start timestamp, both byte
counters, completed-record count, sequence endpoints, transcript SHA-256, and
the client/server process instances. Each process instance includes its
nonzero kernel start tick, executable identity, and exactly one TCP socket
inode confirmed as `ESTABLISHED` in that process's network namespace. The
transcript is domain-separated and
commits both directions' sequence, length, streaming SHA-256, and reciprocal
acknowledgement for every complete record.

Every restart poll and every post-health guard poll must prove that both pinned
stream processes remain alive, the immutable connection fields remain exactly
`tcp_connections=1` and `tcp_reconnects=0`, the stream start timestamp is
unchanged, both pinned kernel socket instances remain `ESTABLISHED`, and no
counter, sequence, or update timestamp regresses. No fresh
health connection, replacement process, replacement progress file, or newly
accepted socket may satisfy this proof.

After the target has exactly one replacement invocation, the survivor remains
unchanged, the runner pins a distinct replacement-active stream checkpoint.
This checkpoint prevents progress buffered before or during the kill from being
misclassified as recovery. Only after that checkpoint, with the route and kill
switch intact and ordinary health returned, the same stream must complete a
later record in both directions. Both byte
counters and the record count must strictly advance beyond their pre-kill
values, the contiguous sequence endpoints must advance by the record delta,
and the transcript digest must change. The runner then creates a fixed,
root-private stop marker. The client stops only at a full-duplex record boundary
and both client and `serve-once` must exit successfully. Final evidence must be
`state=pass`, retain the pinned start timestamp and one/no-reconnect tuple, and
account for exactly `records * record_bytes` in each direction.

The target recovery deadline and both independent last-byte-to-next-byte
progress gaps are at most 30,000 ms. Existing exact invocation/restart-count,
survivor, route, kill-switch, no-plaintext-WAN, and two-second post-health guard
checks remain mandatory.

## Sanitized accelerated marker

The accelerated gate aggregates every per-trial transcript in cycle/trial
order. Each hashed row commits the pre-kill, replacement-active, first
post-restart, and clean-final record counts and transcript digests, so later
evidence cannot substitute buffered or final-only progress for the required
transition. The gate emits the following additional exact keys after
`EDGE_KILL_TRIALS`:

```text
MAX_RECOVERY_MS=<uint>
STREAM_RECORD_BYTES=1048576
STREAM_PROGRESS_TIMEOUT_MS=30000
TCP_CONNECTIONS=<uint>
TCP_RECONNECTS=0
FULL_DUPLEX_RECORDS=<uint>
STREAM_BYTES_A_TO_B=<uint>
STREAM_BYTES_B_TO_A=<uint>
PRE_RESTART_PROGRESS_CHECKS=<uint>
REPLACEMENT_ACTIVE_CHECKPOINTS=<uint>
POST_RESTART_PROGRESS_CHECKS=<uint>
STREAM_SURVIVAL_CHECKS=<uint>
MAX_PROGRESS_GAP_A_TO_B_MS=<uint>
MAX_PROGRESS_GAP_B_TO_A_MS=<uint>
STREAM_DIGEST_DIRECTIONS=<uint>
STREAM_TRANSCRIPT_SHA256=<64 lowercase hex>
```

For a valid marker, `TCP_CONNECTIONS`, both progress-check counts, the
replacement-active checkpoint count, and half the digest-direction count equal
`EDGE_KILL_TRIALS`; reconnects are zero;
full-duplex records are at least twice the trial count; both byte totals equal
`FULL_DUPLEX_RECORDS * STREAM_RECORD_BYTES`; recovery and progress gaps are no
larger than `STREAM_PROGRESS_TIMEOUT_MS`; and the transcript is canonical.
The marker contains no address, port, PID, invocation ID, socket identity,
credential, key, token, or private topology identifier.

## Central integration

`campus_link_validate_chain` must add the keys above to the accelerated marker
schema in exactly the displayed order and enforce all stated relations with
overflow-safe arithmetic before allowing `fault-in-stream` to start. Candidate
fingerprinting already binds the recovery runner and stream transport; the
central validator implements that schema and revalidates it before advancing.
No existing
live marker is compatible with the expanded schema, so activation requires a
fresh offline qualification run rather than reinterpretation of old evidence.
