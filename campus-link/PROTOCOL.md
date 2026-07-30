# campus-link protocol and production contract

This document is normative for `campus-link`. Code, installers, tests, and
qualification evidence must fail closed when they cannot satisfy it. The
current deployed build remains a **production candidate**, not a
production-ready release.

## Fixed circuit and trust boundaries

The circuit contains exactly `site-a` (`10.81.0.0/24`) and `site-b`
(`10.82.0.0/24`). Only those prefixes may cross the TUN. `gz` brokers control
and rendezvous and may blindly splice encrypted packets, but it must never
possess a site data-plane private key or a data CA signing key.

Production key custody is per endpoint. A router may read only its own control
and data leaf keys plus public roots and peer authorizations. It must not store
the other router's key, the relay key, or any CA signing key. The relay may
read only its relay control leaf key, public control root, and the two public
site authorizations. The all-in-one generator is a learning-lab facility and
must require `CAMPUS_LINK_LAB_ONLY=1`; evidence from that shared-key layout
cannot satisfy the production key-isolation gate.
Reuse of an existing lab PKI is still fail closed: its complete symlink
inventory is captured from a checked traversal before any certificate or key
is trusted. A failed traversal is not evidence that the tree contains no
symlink.

## Asymmetric identity

All control and data sessions use TLS 1.3 mutual authentication with Ed25519
leaf certificates. Native X.509 chain and DNS verification is followed by an
exact authorization check:

- exactly one canonical `spiffe://campus-link/<circuit>/<endpoint>/<plane>`
  URI SAN;
- the exact DNS SAN profile for that URI: only `gz.campus-link` for
  `relay/control`, no DNS SAN for either site `control` identity, and only the
  endpoint's `<site>.campus-link` name for a site `data` identity;
- no IP-address, email-address, or unsupported GeneralName SAN identities;
- the exact required EKU set and only digital-signature key usage;
- an explicit non-CA basic constraint and a leaf lifetime no longer than 90
  days;
- a canonical SHA-256 SPKI pin matching either the `current` or `next` slot.

Every current and next SPKI is globally unique across relay-control, both
site-control, and both site-data identities. Each component's runtime config
carries explicit public current/next authorization slots for every local and
remote identity visible to it. Local preflight matches the loaded leaf against
its configured local slots and applies the same URI, DNS, EKU, key, chain,
lifetime, and file-custody rules before any dial, listener, or TUN mutation.
Deriving a one-element authorization from the loaded certificate itself is
forbidden because it would falsely label any local key as `current`.
Certificate and key files contain only the expected PEM blocks with no trailing
or embedded private material.

An accepted session is bounded by the authenticated leaf's `NotAfter` time.
Each process exposes only the expiry time and `current`/`next` slot in sanitized
status, begins a controlled reconnect before expiry, and closes the session no
later than expiry. A next-slot connection is observable so rotation can be
proved before current-slot removal.

An edge tracks peer data identities separately for its exact relay and direct
path instances. Every mux path receives a nonzero, non-reusable instance ID;
the verified peer identity is bound to that ID and the owning mux lifetime, not
merely to a direct epoch. Sanitized `data_identity` names the currently selected
path and its direct epoch (zero for relay), but publishes a peer identity only
when its internal instance binding exactly matches the selected mux snapshot.
Direct preparation registers that future binding before selection while holding
serialized activation authority. Relay replacement inserts its binding in the
same Runner-to-mux critical section that installs the path. Status takes the mux
snapshot and resolves this bounded binding map while holding Runner authority,
so a selected healthy path is never paired with a retired identity or exposed
without its exact verified identity. A dialed, accepted, redundant, failed, or
otherwise rejected candidate cannot change identity status; neither can
replacement of an unselected warm relay falsely describe an already-selected
direct connection.

Credential material is immutable for one process invocation. An edge therefore
ends its invocation at the earliest reconnect cutoff of its local control and
data leaves, and the relay ends its invocation at the reconnect cutoff of its
local control leaf. The supervised restart reloads the complete preflighted
credential set. An earlier control-leaf expiry may never be masked by a later
data-leaf expiry, and a listener may never keep serving a leaf past its cutoff.
Every process and connection cutoff is guarded both by an elapsed-duration
timer and by a wall-clock recheck at most every 250 milliseconds. A forward
clock correction therefore closes authority within 250 milliseconds of the
new wall-clock cutoff; the rotation gate rejects a larger measured overrun.
A newly authenticated relay candidate carries its exact cutoff, guard state,
and connection liveness through installation. Immediately before replacement,
the edge revalidates all three under the same Runner-to-mux commit authority
that publishes its exact peer binding. A candidate that closed or crossed its
cutoff after authentication is rejected without selecting a path or resetting
the existing contiguous no-path recovery deadline.

### Certificate-rotation transaction and gate

Certificate rotation is a separate, crash-safe qualification transaction; an
ordinary throughput interval may not be relabeled as rotation evidence. The
transaction is bound to the qualification run ID, immutable candidate digest,
its prerequisite marker hash, and a fresh 128-bit rotation ID. Its public
manifest assigns every relay-control, site-control, and site-data SPKI to one
exact `current` or `next` slot without containing a private key. Reusing a pin,
skipping a plane, changing the candidate, or changing the manifest after the
transaction begins fails closed.

Before any verifier admits a `next` pin, the coordinator atomically publishes
a root-owned, mode-`0600` active-transaction marker containing only those
bindings and a monotonic start time. Every next-slot observation is bound to
the hash of that marker and must fall between its start and the transaction's
completion time. Baseline and post-retirement observations are all `current`;
there are exactly eleven in-transaction next observations: the relay local
control leaf, both edges' relay-control peers, each edge's local control and
data leaves, both relay observations of site-control peers, and both edges'
direct-data peer observations. A `next` observation without this marker, after
its removal, or in any other qualification gate invalidates the candidate.
The complete transaction is bounded to 30 minutes.

The immutable candidate digest includes the digest of a sealed, root-owned
public rotation manifest. That manifest contains complete, exact artifact-hash
rows for every permitted `pre`, `overlap`, endpoint-activation, `retiring`, and
`post` credential/authorization state. The candidate fingerprint may omit an
active leaf, key, authorization config, or slot-selection file only after it
has recomputed all of those artifact hashes and matched the entire row selected
by an atomic stage marker bound to the run ID, candidate digest, rotation ID,
and rotation-manifest digest. The stage marker moves to `retiring` before any
old authorization is removed. A missing artifact, an extra mutable artifact,
a row assembled from two states, an out-of-order stage, or a manifest/stage
binding mismatch fails closed. Structural config, executables, units, topology,
and every non-identity security policy remain directly candidate-hashed.

The gate executes these ordered stages:

1. **Stage authorization.** While every current leaf remains active, each
   verifier atomically installs and preflights the exact current-plus-next
   public authorization. All current control and selected direct-data
   connections must remain healthy and a sequence-unique bidirectional stream
   starts before any leaf replacement.
2. **Activate next leaves.** One endpoint and plane is changed at a time by an
   atomic credential replacement followed by a supervised reload. The old pin
   remains authorized during this stage. Both edge control sessions must
   witness the relay's next control leaf; the relay must witness each edge's
   next control leaf; and each edge must witness the other edge's next data leaf
   on the exact selected direct connection instance. A local slot label is
   valid only when the loaded public key is matched against the immutable
   rotation manifest; self-pinning a local leaf always as `current` is not
   evidence.
3. **Prove recovery and transport.** The stream started in stage 1 remains
   sequence-unique and checksum-correct across every required reload. Each
   outage is measured with the kernel monotonic clock, may not exceed 30
   seconds, and must recover without application-record loss, duplication, or
   reordering. After recovery, both edges must again select a healthy direct
   path, authenticated progress must advance in both directions, and relay
   forwarding must remain within the raw keepalive bound.
4. **Retire current pins.** Only after every next-slot observation and stream
   recovery passes may all old public pins be atomically removed. Every
   verifier is reloaded, and an isolated handshake using each retained old test
   leaf must be rejected for its former exact identity and plane. The same
   identity presented with the next leaf must succeed. The next pins are then
   promoted to `current`, so no post-transaction status can retain a `next`
   label. Rollback before retirement restores the snapshotted current-plus-next
   authorization and service state. Rollback at or after retirement is a
   forward-safe recovery to the verified next-only state and may not silently
   restore an old authorization. The isolated fixture fault-injects and proves
   both rollback floors, including exact credential/authorization state,
   supervised service state, direct-path health, and stream resumption.
5. **Prove expiry enforcement.** An isolated, candidate-identical fixture uses
   short-lived leaves that remain outside the five-minute reconnect margin at
   admission. Without changing host time, it proves established control,
   relay-data, direct-data, and relay-listener authority ends no later than the
   computed cutoff, that an expired/inside-margin leaf cannot reconnect, and
   that the staged next leaf restores the circuit within the same 30-second
   outage budget.

The pass marker is root-owned, mode `0600`, atomic, hash-chained, and has one
fixed ordered schema. It records only the run/candidate/prerequisite/rotation
and active-marker bindings, stage start and completion monotonic times, the
fixed overlap/next-observation/reload/reconnect counts, maximum measured outage,
stream record totals and digest direction count, old-pin rejection and
next-pin acceptance counts, expiry/reconnect/cutoff counts, maximum cutoff
overrun, and the two rollback-drill results. It contains no certificate, SPKI
pin, key, address, tuple, token, raw service/session identifier, or host
identifier. A failed transaction instead writes a separate fixed-schema
failure marker stating only its bindings, safe rollback floor, and whether the
bounded rollback was verified; it can never satisfy the chain. Missing
observations, a service start-limit lockout, a status identity not bound to the
exact selected connection instance, a transaction longer than 30 minutes, an
application outage over 30 seconds, or a cutoff overrun over 250 milliseconds
invalidates the whole transaction. The 24-hour soak may start only from this
exact pass marker.

## Control ownership

Each edge opens outbound TCP/443, completes mTLS, and registers its exact site,
circuit, prefix, source version, generation, and deployment transaction. The
relay authorizes the site from URI and SPKI, never from a common name or a
claimed site string. Edge and relay source versions and deployment transaction
must match. Every bounded control frame is one canonical JSON object: duplicate
keys at any nesting level, escaped object-key spellings, unknown fields,
multiple values, and non-finite numbers are rejected before a message can
change authority or telemetry. The current profile advertises exactly one transport,
`quic-datagram`; missing, duplicate, additional, or unsupported transport
values reject registration rather than silently negotiating different
capabilities.

Replacement is a two-phase operation. The relay prepares a fresh random
32-byte binding token and prospective owner, delivers `Registered`, and only
then atomically replaces the prior owner. Failed token delivery cannot evict a
healthy circuit. Once committed, stale owners cannot clear, bind, publish a
candidate for, or forward through the replacement.

Pre-authentication work has its own small bounded admission pool and deadline;
the two authenticated site sessions do not consume it. Invalid, replayed, or
faster-than-one-per-second heartbeats close only the offending session.

## Authenticated UDP binding v2

Every binding flight is an exact 82-byte HMAC-SHA-256 packet scoped to one
control-issued token. `REQUEST`, `CHALLENGE`, `RESPONSE`, and `READY` carry the
site, a strictly increasing 64-bit sequence, a 16-byte request nonce, and a
16-byte challenge. All fields and the type are authenticated.

Binding and rendezvous-probe packets use a fixed non-QUIC discriminator whose
two most-significant bits are zero. The one socket-owning QUIC transport is the
only reader of the UDP socket and delivers those bounded packets through its
non-QUIC queue. One long-lived dispatcher is the sole consumer of that queue
and routes exact binding and rendezvous discriminators into separate bounded
mailboxes. Binding, rebind, and punch attempts never compete as socket readers;
unknown or overflowing packets are counted and dropped. Callers must not read
the underlying socket directly. Each mailbox is protected by one exclusive,
context-bounded lease for the complete binding or punch transaction. A second
consumer fails closed rather than stealing packets, and closing the dispatcher
invalidates outstanding leases before any queued packet can be returned or any
new packet can be written.

The relay retains constant state for one transaction per current owner. A
higher authenticated sequence begins a make-before-break rebind. The last
proven tuple remains authorized until a response from the pending tuple proves
return routability; duplicate and stale flights cannot move it. A lost READY
may be replayed only for the same token, transaction, and proven source.
Binding retransmissions follow an independent bounded timer; malformed,
wrong-source, or unauthenticated mailbox arrivals are counted and dropped and
cannot trigger an immediate transmission, suppress sequence advancement, or
amplify a flood toward the relay.

## Packet paths and reliability

The production profile is **direct-required**. `gz` carries authenticated
control/rendezvous and a bounded warm QUIC liveness association, but it never
carries an authorized inner TUN packet. Before first direct activation and
during direct recovery, TUN reading is backpressured. A lab-only configuration
that selects the blind relay for application packets cannot satisfy production
qualification. Inner IPv4 packets are checked against the fixed source and
destination prefixes and MTU before crossing the direct QUIC path. QUIC
DATAGRAM itself remains best-effort; reliable applications rely on their own
transport. The current
profile accepts only a canonical 20-byte IPv4 header (`IHL=5`), so
source-routing and other IPv4 options cannot reinterpret an already-authorized
destination after tunnel delivery. Both OpenWrt edges must also keep IPv4
`accept_source_route=0` on every interface as defense in depth.
Every inner packet or fragment is independently protected by the authenticated
QUIC association and checked for canonical IPv4 header, checksum, and exact
source/destination prefixes. Kernel-produced IPv4 fragmentation is permitted so
DF-clear UDP and other non-TCP traffic can cross the 1200-byte inner path without
userspace reassembly. The reserved flag and any DF+fragment combination are
rejected. A non-final fragment must have a nonempty payload whose size is a
multiple of eight, and offset plus payload must remain within the maximum IPv4
payload extent. Campus-link never reassembles or retains fragment sets.
Policy validation is non-mutating: campus-link does not decrement the inner
TTL or rewrite its checksum. The kernel routing a packet into the local TUN and
the peer kernel routing it out of the TUN own normal IPv4 hop/ICMP semantics;
an additional userspace decrement would create hidden hops and break low-TTL
traffic and traceroute.

The warm broker association is self-healing without becoming a data fallback.
Loss of one exact association emits one coalesced recovery need; the edge
retries with bounded cryptographic jitter until its data context ends or a
replacement succeeds. During a direct no-path gap,
the edge retains exclusive ownership of the TUN, holds at most the one already
policy-checked packet, and stops reading to apply kernel backpressure instead
of sending to any unauthenticated or default route. The gap has one
non-extendable 30-second monotonic deadline: only activation of an exact
authenticated direct path cancels it; expiry is fatal, closes the TUN,
and lets systemd start a fresh fully preflighted invocation. Repeated failure
notifications cannot reset that deadline. A replacement is
eligible only after exact peer
data mTLS/SPKI verification, authenticated relay-tuple classification,
certificate-cutoff calculation, and full configured DATAGRAM-capacity proof.
The server edge has one QUIC accept-and-classify owner for both baseline and
direct connections; competing `Accept` loops are forbidden. The mux assigns a
fresh nonzero, non-reusable local instance ID and installs the validated
association atomically. `SelectDirect` is only a provisional activation step:
the new connection is not externally healthy, cannot carry a TUN packet, and
cannot cancel or replace the existing no-path deadline until `CommitDirect`
succeeds. During replacement, the prior committed direct connection remains
authoritative through that barrier. A failed or expired provisional activation
restores that exact prior connection, or `none` when none existed, without
resetting the outage deadline. The retired association closes only after the
committed swap. Delayed receive, send, timer, or close errors from a retired
instance cannot demote its replacement. Instance-ID exhaustion permanently
fails closed.

An exact selected-but-uncommitted direct instance may retain authenticated,
envelope-valid, replay-accepted application datagrams only in its private FIFO
activation buffer. The buffer is bounded to 256 datagrams, 524,288 payload bytes,
and five seconds from `SelectDirect`. A prepared-but-unselected instance, a
different instance or epoch, and every relay association are ineligible. Hitting
either capacity bound or the time bound aborts the candidate and discards the
entire buffer; packets are never evicted or delivered early. `CommitDirect`
atomically makes the exact candidate current, detaches and zeroes its buffer
accounting, then releases the retained datagrams in order without holding the
mux authority lock. Before exposing the candidate, commit reserves capacity for
the entire retained FIFO in the fixed inbound queue; inadequate capacity aborts
the candidate without a partial release or a successful commit. Datagrams
arriving on that now-current instance wait behind the release barrier, so they
cannot overtake retained datagrams. Provisional replay decisions use a private
copy of the epoch window. Replay acceptance occurs once, when a datagram enters
the activation buffer; commit atomically publishes that private window only if
its global base is unchanged, and does not re-accept packets during release.
Abort, replacement, receive failure, timeout, authority retirement, and
shutdown discard all retained payloads, private replay state, and accounting
while leaving the previously committed path authoritative until a successful
commit.

Every QUIC DATAGRAM carries a fixed authenticated-inside-QUIC campus-link
envelope containing the wire version, selected path (`relay` or `direct`),
path epoch, and a strictly increasing per-direction packet sequence. Reserved
bits and stale epochs are rejected. A bounded replay window suppresses packets
duplicated across a make-before-break transition without turning DATAGRAM into
a reliable or retransmitted transport. Replay state is scoped to direct path
epoch: a same-epoch exact-instance retry shares its window to suppress
ambiguous-send duplicates, while a strictly newer authenticated epoch receives
a fresh window so a one-sided process restart may safely restart its sequence.
Only the current and bounded receive-draining epochs are retained; stale
old-epoch traffic remains rejected. The configured inner MTU must be no
greater than the current negotiated QUIC DATAGRAM payload capacity minus the
campus-link envelope and frame overhead. Startup fails closed unless the first
packet of that full effective size is supported; a later capacity shrink makes
that path unhealthy and enters bounded direct-required backpressure. A
non-production lab profile may instead select an explicitly configured healthy
fallback. The implementation must
not assume that later path-MTU discovery will make an initially oversized
packet fit. The current profile fixes the inner MTU and exact remote route MTU
at 1200 bytes; advertising or configuring 1280 is a release-blocking error.
Each edge installs an exact TCP SYN `TCPMSS --clamp-mss-to-pmtu` rule toward
`cl0`, so a forwarded TCP flow remains usable even when ICMP packet-too-big is
filtered. DF traffic still receives normal kernel packet-too-big behavior,
while DF-clear traffic may be fragmented by the sending edge kernel and each
fragment is validated and transported independently as specified above.

The required high-throughput path is direct edge-to-edge QUIC established from
authenticated rendezvous plans. One socket-owning demultiplexer must coordinate
binding, punching, and QUIC; concurrent independent readers on the UDP socket
are forbidden. Direct activation requires nonce-correlated authenticated
probes, replay protection, exact peer mTLS, and a bidirectional stability
probe. The broker association stays warm, but direct failure enters bounded
TUN backpressure; it never authorizes relay delivery. Large-transfer
qualification must prove that relay forwarding counters for campus-link data
envelopes remain zero before, during, and after the transfer, including every
injected direct failure. The blind relay's raw packet counter may grow only
within a recorded time-based baseline for warm QUIC keepalives; growth
proportional to transfer bytes is a failure. QUIC DATAGRAM enqueue success is
not proof of peer delivery:
authenticated keepalive plus a bounded peer-delivery/no-progress watchdog must
withdraw an unresponsive direct path.
The exporter-bound activation stream remains open for the direct connection's
lifetime. It carries HMAC-authenticated, epoch/nonces/context-scoped progress
frames acknowledging the highest direct packet sequence accepted into the peer
receive queue, plus correlated idle ping/pong frames. Progress writes are
coalesced through a queue of one and emitted within 50 milliseconds. Once a
direct sender has unacknowledged traffic, failure to advance its authenticated
peer acknowledgement for five seconds closes that exact connection instance
and enters the bounded direct-recovery interval. Unrelated inbound packets
cannot reset the outbound watchdog. While idle, a ping is sent every three
seconds and the exact instance
is withdrawn after twelve seconds without its correlated pong. These signals
use a two-second write deadline so a peer that stops reading cannot suspend the
watchdog. They measure path progress only; they do not retransmit DATAGRAMs or
claim UDP reliability.
An authenticated rendezvous plan remains eligible for bounded, jittered direct
establishment retries until it expires or a higher path epoch supersedes it.
Punch, handshake, activation, and later direct-path failures all trigger that
retry while the authenticated broker sessions remain available. A retry may replace a failed
direct connection at the same path epoch, but never a healthy one; connection
instance identity, not the epoch alone, owns failure and close events so a
delayed event from the replaced connection cannot demote its replacement.

Each direct QUIC connection is additionally bound to its authenticated plan's
circuit, session, generation pair, role, and path epoch by a keyed handshake on
a reliable 1-RTT stream. Its handshake key combines the control-delivered plan
secret with a TLS exporter from that exact end-to-end QUIC connection, so the
broker cannot authenticate a direct path despite knowing the plan. Both
directions must complete a bounded stability exchange before either edge
selects it. The raw broker-visible plan is never accepted by the direct
handshake or activation API; successful peer identity verification and TLS
exporter derivation produce an opaque, connection-bound plan capability. A
four-flight authenticated activation barrier (`activate`, `ack`, `activated`,
`committed`) prepares both receive loops before either sender selects the path.
The initiator commits only after authentic confirmation that the receiver has
selected; the receiver commits only after sending that confirmation. A lost
final confirmation therefore rolls the initiator back and closes the new
connection. Each side returns to its prior committed direct connection when
one exists, or to bounded `none`/TUN backpressure otherwise; the warm broker
association is never an application-data fallback.

A broker process restart or authenticated control-session loss must not
withdraw `cl0`, demote an already committed direct path, or interrupt the
A11-to-B22 application stream. The broker association and control session
recover in the background, with direct epoch/instance and relay-data counters
unchanged. A recovery gate that rewards private-route withdrawal is invalid.

The exact direct connection's certificate-cutoff guard is armed and validates
the initial wall-clock cutoff before the first mux preparation step. Prepare,
select, and commit each recheck that guard and the wall-clock cutoff while
holding the same serialized activation authority used for plan revocation; the
commit check is the final activation recheck. A cutoff that wins this authority
closes the candidate, and a phase that observes expiry aborts activation, so an
unguarded or already-expired connection can never become an exposed mux path.

During a make-before-break transition, a receiver accepts the old and new
authenticated paths for at most two seconds while the sender emits each packet
on exactly one selected path. At most two retired receive paths may drain; an
evicted or expired path is closed immediately. Sequence replay suppression is
shared across the transition. Stale epochs can never replace or clear a newer
path, and a delayed failure from an older connection cannot demote a newer one.
Selection remains rollback-capable until the activation barrier commits: if a
final activation flight fails, the new path closes and the prior authenticated
sender is restored from the drain set, including when the relay is unavailable.

Path epochs live in an authenticated deployment-scoped namespace. Every
registration and rendezvous plan carries the exact source version, deployment
transaction, and relay generation. The relay persists the next epoch across a
process restart within that deployment, rejects zero or reused session/key
material, and changes generation only when authority is intentionally reset.
An edge may reset its remembered epoch only after authenticating a new matching
deployment namespace; a relay restart alone cannot make new plans permanently
stale or authorize rollback.
Every received rendezvous plan, including one whose path epoch equals the
remembered epoch, must pass the complete structural, namespace, generation,
fixed-role, candidate, authenticated-clock, and lifetime validation before any
duplicate decision. Within one plan-session lease, only an exact duplicate of
the complete last accepted plan is idempotent and it is not delivered to the
direct worker twice; a malformed or conflicting same-epoch plan fails closed.
After a fresh authenticated control lease in the same namespace, that exact
fully validated duplicate may be delivered once, rebound to the fresh lease,
so failure of the independently surviving direct connection can still retry
the plan within the existing non-extendable recovery bound. This authority
rebind neither replaces nor interrupts the established direct instance and
cannot extend plan or certificate lifetimes. A namespace change erases the
remembered plan, so no equal-epoch value can cross namespaces.
Every cryptographic namespace input uses a length-prefixed canonical encoding;
delimiter concatenation of variable-length circuit, version, deployment, or
generation strings is forbidden.

The broker control session and an established end-to-end data session have
separate lifetimes. Losing `gz` control immediately clears the authority to
accept rendezvous plans and starts a bounded, jittered reconnect loop, but it
does not close an already-authenticated direct connection. Reconnection must
repeat exact peer-certificate, version, deployment, relay-generation, and bind
validation before restoring plan admission. No plan received before that
validation, between control sessions, or from a prior namespace is actionable.
The direct path remains bounded by its edge certificates and direct peer
certificate; a control reconnect cannot extend those lifetimes.

Plan authority is also bound to an authenticated cross-host clock sample. Each
`Heartbeat` carries the edge's wall-clock Unix nanoseconds and a nonzero,
process-local monotonic send sample; neither value contains a host identifier.
The `HeartbeatAck` echoes the exact monotonic sample and carries relay wall-clock
Unix nanoseconds captured immediately after receipt and immediately before
send. All four timestamps are canonical dates in `[2000-01-01, 2100-01-01)`,
the edge sample is at most `MaxInt64`, a sample RTT is at most five seconds, and
relay processing is nonnegative and at most one second. The edge records its
own wall and monotonic clocks immediately before send and immediately after
receipt, rejects a local wall rollback or more than 50 milliseconds of
wall/monotonic divergence, and rejects a mismatched sequence or echoed sample.
The relay applies the same 50-millisecond wall/monotonic divergence bound to
its receive-to-send processing interval before emitting an acknowledgement.
Old control peers omit required nonzero fields and therefore fail closed.

For a valid exchange, let `t0` and `t3` be edge wall time at send and receive,
with `t3` correlated from the local monotonic RTT, and let `t1` and `t2` be
relay receive and send wall time. The authenticated relay-minus-edge offset is
conservatively bounded by `[t2-t3, t1-t0]`. The interval must be ordered and
must lie wholly within `[-1 second, +1 second]`; it is not sufficient for a
point estimate alone to meet the limit. A plan on an acknowledgement whose
sample is missing, malformed, stale, or outside that bound is never admitted.
A valid sample remains current for at most 15 seconds. Three consecutive
invalid samples revoke the current plan-session lease and force control
reauthentication, while an already established end-to-end direct path retains
its independent lifetime. Any valid intervening sample resets the consecutive
failure count.

Edge status exposes only `synchronized`, the absolute midpoint offset rounded
up to milliseconds, and the half-width uncertainty rounded up to milliseconds.
Raw timestamps, monotonic samples, clock-source identifiers, and host
identifiers are forbidden in status and logs. A missing or rejected current
sample reports `synchronized=false`; the numeric fields are zero until another
sample is accepted. Qualification requires `synchronized=true` and verifies
that absolute offset plus uncertainty is no greater than 1000 milliseconds.

Every `HeartbeatAck` binds a relay telemetry snapshot to the exact echoed
heartbeat sequence. The authenticated mTLS response carries six fixed
`uint64` counters: datagrams forwarded from site A and their outer UDP payload
bytes, datagrams forwarded from site B and their outer UDP payload bytes, and
datagrams dropped and their classified payload bytes. A forwarded datagram and
all of its bytes are recorded only after one complete UDP write; a rejected or
failed datagram and all of its bytes are recorded as dropped instead. Valid
binding-protocol datagrams consumed or emitted successfully by rendezvous are
not relay-data forwarding, while a binding response that cannot be emitted is
classified as a dropped datagram of the attempted response length. Oversized
input is read without truncating its length before it is classified as dropped.
The packet and byte increments for one classification and all six-counter
snapshots occur under the relay authority lock. Any increment that would wrap
a `uint64` terminates relay forwarding and fails closed. All six JSON fields
are mandatory even when zero; an omitted field, including an older
packet-only schema, and any additional field are rejected. Maps, addresses,
site identifiers, credentials, and other variable telemetry are forbidden on
this wire message. An edge accepts a snapshot only for the
exact current plan-session lease, rejects a missing snapshot or any sequence or
counter regression within that session, and clears it when control authority is
revoked. Sanitized edge status binds the latest snapshot only to the nonzero,
process-local plan-session serial. That serial cannot wrap or be reused; serial
exhaustion permanently withholds new plan authority. Status never exposes TLS
exporter material or a digest derived from it, certificate material, addresses,
tokens, or private routing identifiers.

Source versions are 1--64 ASCII characters and match
`[0-9A-Za-z][0-9A-Za-z._+-]{0,63}`. Deployment transactions and relay
generations are canonical 32-character lowercase hexadecimal values. The relay returns its exact source version,
deployment transaction, and generation in `Registered`; an edge accepts plans
only in that authenticated namespace. Relay epoch state is a mode-0600 regular
file owned by the dedicated relay identity inside a non-writable-by-others,
root-controlled service-state directory. It is replaced atomically after file
and directory synchronization.
The relay service identity is provisioned by a separately manifest-bound,
idempotent bootstrap before the deployment transaction. It is a locked system
account with a distinct primary group, `/nonexistent` home, nologin shell, and
no supplementary groups; the transactional relay installer validates that
exact boundary and never creates or modifies the account.
It retains prior deployment namespaces so a controlled software rollback
resumes the prior generation and next unused epoch. An epoch is durably consumed
before its plan is published; a crash may skip an epoch but can never reuse one.
That guarantee assumes monotonic state: restoring an older snapshot of the
epoch-state file or its containing volume is prohibited. A host/volume restore
must be detected by a non-snapshotted boot or external monotonic anchor and
must rotate the relay generation and material before control admission. The
snapshot-restore detection and rotation test is a release gate; ordinary file
durability alone is not accepted as rollback protection.
The Linux profile uses only the SHA-256 digest of the canonical kernel
`boot_id`; the raw host identifier is never persisted, logged, or reported.
The digest must remain equal across relay process restarts in one boot. A
change rotates the relay generation and material seed for every retained
deployment in one durable state replacement before the relay can admit control
sessions. An unavailable, malformed, zero, or non-canonical production boot
anchor fails closed. Restoring epoch state in place without changing the boot
anchor cannot be distinguished by this mechanism and remains prohibited; host
and volume recovery procedures must boot a fresh kernel before relay startup.
After an edge process restart, the first plan in the authenticated namespace
may begin at any nonzero persisted epoch; bounded forward-jump checks apply
after that first epoch has been remembered.

Roles are fixed rather than negotiated: `site-a` is the QUIC client/sender and
`site-b` is the QUIC server/receiver on relay and direct connections. Any other
site/role combination fails configuration preflight. The server accepts the
baseline connection only from the already authenticated relay UDP tuple and a
direct connection only from the tuple proven by its current rendezvous plan;
an authenticated but misclassified or stale connection is closed and cannot
occupy the other path's slot.

TCP/441 with inner edge-to-edge TLS 1.3 is the required UDP-blocked fallback.
Relay redundancy, direct QUIC, and TCP/441 are release gates; foundations or
dead code do not count as implemented paths.

## Observable failure semantics

Status writes are coalesced through one writer outside forwarding/authority
locks. Packet I/O never performs filesystem work. Counters distinguish policy
drops, malformed binding traffic, wrong-source/replay traffic, socket write
failures, control admission failures, invalid plans, and status-write failures.
Status paths are volatile and contain no addresses, tokens, keys, candidate
tuples, payloads, or certificate bytes.

Qualification opens status and evidence snapshots without following the final
path component and accepts only a single-link regular file whose owner and
group are the exact service identity for the expected site, whose mode is
`0640`, and whose parent directory is owned by that same identity without
group/other write permission. The pre-open and opened device/inode identities must
match, sizes are bounded, duplicate JSON keys and non-finite values are
rejected, and evidence snapshots are created exclusively with mode `0600`.
The edge-A input must contain exact site `site-a`, the edge-B input exact site
`site-b`, and the two opened inputs must have different device/inode identities.
The data identity observation names the exact selected path; a direct
observation also names the same nonzero direct epoch published by that path,
while a relay observation has epoch zero. A different site, duplicated source,
unselected-path identity, or mismatched epoch fails closed. Whenever both edges
report a healthy direct selection, they must report the same nonzero
authenticated plan epoch; two individually self-consistent but different
epochs are a split-brain observation and cannot satisfy a wait or evidence
boundary.

The edge bounds registration, heartbeats, queues, and no-progress intervals.
Short TUN writes and partial datagram writes are failures. During the bounded
no-path recovery interval, the private-prefix route remains pinned exclusively
to the retained TUN so it cannot fall through to WAN; TUN reading is
backpressured and no unauthenticated output occurs. When the terminal recovery
deadline wins, mux forwarding is canceled immediately and the TUN is closed.
An independently installed exact-prefix kill switch then becomes the winning
route: a persistent high-metric `unreachable` route plus exact OUTPUT/FORWARD
WAN rejection survives edge absence, crash, failed preflight, restart, install,
and rollback. A healthy `cl0` route has lower metric and may override only that
exact kill switch. Removing `cl0` must therefore reveal `unreachable`, never a
default route; qualification proves zero matching plaintext packets on the WAN
veth during bounded recovery and terminal restart gaps. That proof includes a
packet originated by the simulated LAN process and traversing FORWARD, not only
a packet originated inside the edge namespace.

Topology construction is fail closed. Each edge namespace begins disconnected
with forwarding disabled and no default route. Router mode is enabled before
any link is attached (because that kernel transition resets IPv4 interface
policy), then `accept_source_route=0` is installed for `all` and `default` and
verified again for loopback, transit, WAN, and TUN after each exists. The exact
unreachable route plus OUTPUT/FORWARD rejection rules are installed and
verified before the WAN default. A failed `up` transaction tears down every
partially created namespace/link/rule.

The privileged topology service never writes the shared host's global
`net.ipv4.ip_forward` setting or changes its `FORWARD` policy. Before changing
campus-link state it requires a host baseline that already has IPv4 forwarding
enabled and an exact default `FORWARD DROP` policy. It adds only four narrow
filter exceptions: one outbound rule per edge matching the exact campus WAN
veth, source address, physical egress interface, and tracked state, plus one
return rule per edge matching that physical ingress interface, exact campus WAN
destination address, assigned veth, and `ESTABLISHED,RELATED` state. NAT is
similarly limited to the two exact edge source addresses and physical egress
interface. A missing or changed host baseline fails before teardown or link
creation; campus-link never broadens forwarding for another host interface or
workload.

The router baseline has a persistent campus mode that
never creates the legacy plaintext `oslab-relay` namespace or either relay
bridge port; deleting it after boot is not an acceptable safety control.
Qualification repeatedly proves those objects are absent. Returning to the
offline learning topology revokes every production-candidate marker.

Network-facing edge parsers do not run as host root and retain no Linux
capability. A privileged, bounded topology oneshot owns TUN creation,
configuration, exact-prefix routes, and firewall rules before either edge can
start. Site A and site B run under distinct fixed service identities with empty
capability and ambient sets, join only their assigned pre-created network
namespace, and can read only their own leaf private keys/configuration plus
public trust material. Neither identity can read the peer's private keys or
mutate the independent kill switch. Installed edge credentials and configuration
are root-owned, mode `0640`, and grouped to exactly that site's service identity;
their root-owned parent is mode `0750`. Runtime credential validation accepts a
group-readable private key only when its group is the process's effective group,
so the edge can read but cannot replace or chmod its key, and the peer service
cannot read it. Because this is a software key readable by its own edge process,
the contract does not claim hardware-backed non-exportability. A clean
install runs the final preflight under each exact service identity after atomic
installation, rather than relying on a root-only staging preflight.
Each edge's systemd mount namespace makes the peer credential/status directory,
central PKI, deployment state, and `/srv/openwrt-lab` inaccessible even if a
future DAC error would otherwise make one readable.
Unmanifested persistent, runtime, transient, or control unit-specific systemd
drop-ins are forbidden. The installer checks the known unit-specific drop-in
search paths before snapshot and again after installation. Distribution-wide
defaults are tolerated only when every security-relevant effective property
still matches the contract and their effective serialization is candidate-bound;
qualification reports no private runtime identifiers.
Candidate fingerprinting and every immutable-run recheck require both edge
units to be active with a stable nonzero main process whose real/effective/saved
UID and GID, sole group, zero capability sets, no-new-privileges state, network
namespace, executable bytes, and exact argument vector match that effective
unit contract. An inactive unit or a process transition during inspection fails
closed and cannot produce a candidate fingerprint.
Qualification accepts status files only
from the exact configured site service identity and binds that owner to the
expected site.

The two service accounts and groups are reproducibly provisioned by the tracked
host bootstrap and are immutable platform prerequisites, not
deployment-transaction side effects. The transactional installer never creates,
deletes, or modifies accounts. Before snapshot or mutation it requires distinct
UIDs and primary GIDs, nologin/nonexistent-home accounts, and proves neither
account has any supplementary group. A missing or over-privileged identity
fails closed without changing deployment state.

## Deployment and qualification evidence

Every deployed artifact comes from one clean, verified source tree. A signed or
SHA-256-bound manifest covers source revision/tree digest, VERSION, binaries,
configs, scripts, units, host bootstrap, deployment orchestrator, and public
authorization material. Manifest lookup requires one exact logical-path field;
a prefix, suffix, duplicate, missing entry, malformed digest, or lookup failure
cannot bind an artifact. Staged PKI directory allowlisting also captures and
validates the enumerator's exit status; a traversal failure is never an empty
allowlist. Each transfer,
preflight, installation, and rollback verifies the same manifest. Edge and
relay installers share a transaction ID and use fresh transaction snapshots.
The relay installer opens and pins the exact staging-directory inode before it
trusts any artifact. That directory must be an exact root-owned, mode-`0700`,
non-symlink directory. Every allowlisted staged artifact must be a root-owned,
single-link regular file with no group/world write or special permission bit.
Inventory, hashing, preflight copies, rollback helpers, and final installation
must resolve through the pinned directory rather than re-resolving the caller's
path. Complete custody and manifest bindings are revalidated immediately
before the first installed artifact is replaced; a rename, replacement, link,
permission change, or revalidation failure leaves deployment unchanged.
Every source-list, artifact-list, account-record, and status-snapshot producer
that feeds a build, install, rollback, or qualification decision has its exit
status captured and checked. Valid-looking partial output followed by producer
failure is never accepted as a complete enumeration or identity record.
Every such bounded inventory or status proof also has checked complete
consumption: the consumer distinguishes a successful end of input from a read
error, rejects a valid-looking prefix with an omitted tail, and validates the
entire captured input against its exact count, framing, or schema before using
any item in a build, deployment, or qualification decision. Producer success
alone is insufficient, and consumer EOF alone is not proof of completeness.
After both sides install, coordinated activation always stops the external
target and confirms the target, topology, and both edges are inactive before
starting the target. This reapplies the newly installed topology and creates
fresh edge processes. Both edges must have nonempty InvocationIDs different
from their pre-activation values, be active under the expected runtime boundary,
and pass direct-only smoke before the candidate may enter qualification.
Rollback must stop the target and both edge services successfully and verify
that none remains active before changing any file. After atomic restore and
daemon reload it restores the exact recorded active/inactive state of the target
and each edge, verifies every state (and the topology dependency whenever an
edge or target is active), and only then writes the rollback-complete marker.
A prior online snapshot is eligible only when its complete security tuple—not
just kill-switch substrings—contains the immutable host-forward baseline,
narrow source/interface/state firewall rules, 1200 route MTU and MSS clamp,
unprivileged hardened edge units, exact site credential trees, and no symlinks.
An unsafe or partial prior tuple is rejected before any service stop or file
mutation; migration from such a version requires an explicit offline recovery
transaction rather than silently restoring the vulnerability.
A stop, start, or verification failure leaves the snapshot active and unmarked
for operator recovery; it never falsely certifies a partial rollback.

Deployment holds an exclusive lock; a qualification chain holds the shared
lock for its entire run. A coordinator generates one random run ID and exact
candidate fingerprint before clearing bounded result markers. Full,
accelerated-fault, fault-in-stream, NAT-rebinding,
certificate-rotation/expiry, 24-hour, and seven-day gates are ordered and
accept only markers from that run and candidate. Markers are
atomic, root-only, and chained by hash. Durations and outage budgets use the
kernel monotonic clock only.

The gates include simultaneous sequence-unique full-duplex transfers, both
directions and both edge failures, relay failure, NAT rebinding, long-lived
stream recovery, UDP source/digest validation, direct-path counter evidence,
certificate rotation/expiry, installer rollback, and key-isolation checks. A
cached systemd result, stale filename, or unscoped `STATUS=pass` is never
evidence. Production-ready labeling is forbidden until every contract gate
and the seven-day burn-in pass for the same immutable candidate.

Before every accelerated edge-recovery kill, the gate snapshots canonical,
nonempty systemd `InvocationID` and `NRestarts` values for both the target edge
and the surviving edge while both units are active. Every recovery poll and
every sample in the two-second post-health guard must prove that the survivor's
two values remain exactly unchanged. Every target restart-count sample must be
either the captured value or exactly that value plus one; a malformed value,
counter reset or decrement, overflow, or larger jump fails closed. The first
active target sample at the incremented count must have one distinct canonical
`InvocationID`; those incremented count and replacement identity are then
pinned through the remainder of recovery and the complete guard. A second
target identity change, any further restart, or health before that single
replacement has been proven fails the trial.

Each accelerated kill trial also opens exactly one TCP connection before the
kill and gives the server exactly one `accept`. Both directions complete and
acknowledge a sequence-contiguous, SHA-256-checked 1 MiB record before the
signal. The gate pins both endpoint processes' kernel start ticks and their
sole established socket inodes, then rechecks those same process/socket
instances during every recovery and guard poll. When the single replacement
edge invocation first becomes active, the gate captures a distinct stream
checkpoint; only a later complete bidirectional record and changed transcript
may count as recovered progress. The client has no reconnect path and stops
only at a fully acknowledged record boundary. A fresh health connection,
buffered pre-checkpoint bytes, a new progress file, a second accept, or a
replacement stream process fails closed.

The accelerated marker records, after `EDGE_KILL_TRIALS`, the exact ordered
fields `MAX_RECOVERY_MS`, `STREAM_RECORD_BYTES=1048576`,
`STREAM_PROGRESS_TIMEOUT_MS=30000`, `TCP_CONNECTIONS`, `TCP_RECONNECTS=0`,
`FULL_DUPLEX_RECORDS`, both directional stream-byte totals, pre-restart,
replacement-active, and post-restart checkpoint counts, survival-check count,
both maximum progress gaps, digest-direction count, and one aggregate
lowercase SHA-256 transcript. Connections and each checkpoint count equal the
trial count; records are at least twice the trial count; both byte totals equal
records times 1 MiB; survival checks are at least three per trial; recovery and
both gaps are at most 30 seconds; and digest directions equal twice the trials.
All multiplication is range-checked before shell arithmetic. The marker
contains no address, port, PID, invocation ID, socket inode, key, or token.

### Fault-in-stream transaction and gate

The accelerated fault gate is followed by a separately supervised
`fault-in-stream` transaction before any long soak can begin. Its production
mode starts one TCP connection carrying at least 2 GiB of deterministic,
sequence-unique data in each direction. The receiver checks every bounded
chunk, both sides exchange the streaming SHA-256 acknowledgements, and the
same connection must survive every fault below. Creating a replacement TCP
connection, buffering an entire payload, or completing the transfer before a
fault is injected fails the gate. Smaller byte counts and shorter waits are
permitted only in an explicitly labelled isolated-test mode whose marker can
never satisfy the production qualification chain.

The fault-stream listener accepts exactly one application TCP session carried
by the authenticated campus-link data path and closes its listening socket
before serving that session, so neither the client nor the server has a
reconnect path. The server exits successfully only after
the sole full-duplex record, both streaming digests, both reciprocal
acknowledgements, and the peer's clean terminal close have been verified. Its
entire successful output is the one canonical record
`PASS connections=1 reconnects=0 records=1` followed by exactly one LF byte;
the shell requires that exact byte sequence and a zero server exit status
before it can publish gate evidence. It constructs the expected bytes in a
root-owned, mode-0600, single-link regular file, proves identical custody for
`server.log`, and compares the two files byte for byte. Newline counting and
line-search acceptance are not terminal-evidence validation.
A failed or partial session, a second accept, an extra output line, or a server
that remains listening after terminal success fails the gate.

Each full-duplex writer is subordinate to the caller's absolute phase
deadline. Once an operation fails or that deadline expires, the caller shuts
down the socket and permits only a bounded worker-join interval. A worker that
does not stop within that interval is failed evidence and must not retain the
Python process lifetime. Progress observation and evidence publication execute
behind a subordinate daemon execution boundary governed by the same absolute
phase deadline. The caller accepts their work only after observing bounded
successful completion; timeout, callback failure, or publication failure fails
the transport before any `PASS` record. In
particular, a blocked progress observer, file publication, or socket operation
cannot extend a client or one-session server past its process-lifetime bound;
the outer gate then performs its independently bounded cleanup.

Both WANs carry the bounded impairment profile throughout the transaction:
100 ms delay with 20 ms jitter, one-percent loss, and 0.1-percent reordering
per WAN. While the stream is making verified receive progress, both edges'
TCP/443 broker associations are rejected long enough for each edge to publish
an unauthenticated/reconnecting control state. The already selected direct
path must retain the same plan epoch and exact peer-data identity, the stream
must continue to advance, and neither edge invocation may change. After the
outage is observed, the gate takes another receive-progress observation in the
final one-second guard window before removing the rule. Independent A-to-B and
B-to-A receiver files each provide the three observations (before rejection,
during authenticated outage, and near unblock); both series must be strictly
increasing and production mode must receive at least 1 MiB per direction
between the first and third observations. A repeated status check in that guard
window must still show the same direct epoch, direct-instance generation,
identity, zero relay-data/fallback/drop deltas, and the original edge
invocations. After the rules are removed, each edge must authenticate a fresh
broker control session with the same authorized control identities before the
direct-path fault is started.

Production fault injection first performs one real relay-process stop/start
on the same application socket, then performs the independent firewall-
rejection interval above. The gate host authenticates the restart
single-purpose action with a dedicated Ed25519 key pair; passwords, bearer
tokens, agent forwarding, port forwarding, PTYs, and a general remote shell
are forbidden. The private key and pinned relay host key are root-readable
gate inputs and are never readable by either edge service. The dedicated SSH
client uses that one-line pin as its sole host-key trust store, disables global
known-hosts lookup and host-key updates, and fails closed if host-key
verification cannot use exactly that pin. On the relay, the public key is
restricted to one root-owned forced command that accepts only the literal
actions `permit` and `restart`; both root helpers take zero command-line
arguments. Authorization material travels only as bounded canonical stdin and
never in `SSH_ORIGINAL_COMMAND`, sudo argv, process listings, or logs.
Current-run authority is not derived from the SSH credential: the gate host
has a second, independently generated Ed25519 permit-signing pair, keeps its
private key root-only, and pins only its public key on the relay. Immediately
before the fault, the gate generates a fresh 256-bit canonical-hex session
secret and signs a canonical permit containing the run ID, candidate
fingerprint, run-manifest digest, deployment-attestation digest,
permit-public-key digest, session-secret digest, issue time, and a fixed
ten-minute expiry. Only the digest enters the signed permit and relay state;
the secret is sent once in the restart channel's initial exact frame.
A separate root-owned permit authorizer reads the EOF-terminated bounded
envelope, verifies its Ed25519 signature, exact byte schema, local deployment
and permit-key bindings, and expiry before crash-durably installing one
expected-run record. An identical re-upload is idempotent; a different
replacement must be a newly signed strictly newer permit, and the superseded
record becomes permanently non-replayable. The restricted SSH key cannot
create or alter a valid permit or guess the session secret. The restart
actuator verifies the secret digest before it atomically and crash-durably
consumes the expected record, and consumption completes before service state
can change or a stopped proof can be emitted. Once consumed, the transaction
has explicit no-resume semantics. The persistent
revoked/consumed ledger is bounded to 4,096 exact lower-hex run-ID files; an
unexpected entry type, name, owner, mode, link count, or exhausted ledger
fails closed without evicting replay history. Ledger enumeration is itself a
checked operation: a traversal or read error is never interpreted as an empty
valid ledger.
The 64-byte Ed25519 signature has one required unpadded-bit-clean Base64
encoding: the authorizer decodes it, re-encodes it, and requires byte-for-byte
text equality before verification, so alternate pad-bit spellings are not
canonical permits.

The restart action takes a nonblocking exclusive lock, rejects reuse and
invocations inside the cooldown, and arms an independent, bounded, delayed
systemd recovery action before requesting the exact relay unit to stop. Before
that stop it installs one root-owned, non-symlink runtime inhibit marker. The
manifest-bound relay unit has an exact negated `ConditionPathExists` for that
marker, so every ordinary dependency, automatic, and manual activation remains
ineligible throughout the stopped interval. Before consuming the permit, the
actuator requires the signed run-manifest digest to equal the installed
root-owned manifest, the manifest entry to equal the exact loaded relay-unit
fragment digest, `NeedDaemonReload=no`, and no unit-specific drop-in. A
nonempty effective `DropInPaths` set, including a distribution-wide
`service.d` default, is rejected until every such input and the resulting
security-relevant effective serialization are explicitly candidate-bound. The
recovery timer and service use one fixed discoverable identity. The actuator
marks that identity as possibly present before requesting transient-unit
creation; cancellation treats proven `not-found` as success but never treats an
inspection failure as absence. Install and rollback hold the same actuator lock
and reject either recovery unit while it remains loaded. The recovery action
removes only the marker in `ExecStartPre` and starts only the exact relay unit as
its main command. Relay-unit start and stop jobs have explicit 15-second service
bounds.
While stopped, the actuator continuously proves the inhibit marker, inactive
state, and absence of TCP/UDP listeners on the relay port; failure to execute
any proof query is a failed transaction. Only after the signed release and
fixed hold may the actuator end the stopped interval by removing the marker and
requesting the exact start.
The restart clock has a fixed 120-second ceiling. Its declared worst-case
blocking budget counts every fixed mutation, state query, listener query,
anti-prequeue probe, monitor-cancellation grace, challenge generation, release
wait, and release-signature verification; each external operation uses the
same absolute deadline when it can wait on service state, sockets, channel
input, randomness, or signature verification. Small validations of already
bounded root-owned regular files consume the declared residual slack; an
uninterruptible kernel or storage failure is a host failure, not a successful
restart. The declared subtotal must retain explicit slack below that ceiling.
The complete transaction, local transport, driver, and
outer fault deadlines form a strictly increasing hierarchy. The fixed delayed
recovery plus its own service timeout must also finish inside the local
transport bound.
Every ordinary exit path removes the marker, requests and verifies restart,
then disarms the recovery action; SIGKILL, a severed SSH process tree, or an
actuator crash leaves that independent action armed, so the qualification
fault cannot strand the relay indefinitely. A process with unrestricted relay
root authority remains outside this exclusion boundary, as it can replace the
unit, marker, or actuator itself.

After entering the stopped state, and only after proving that no future-phase
input was buffered, the actuator creates a fresh 256-bit server challenge and
emits it in the stopped proof. The gate may release the stop only after both
directional application-progress observations. It signs a domain-separated
release transcript binding the protocol version, run, session, deployment and
all three helper digests, pre-stop invocation digest, stopped challenge, and
fixed hold. The actuator consumes exactly one fixed-length,
newline-terminated release frame, byte-compares its canonical form, and
verifies that signature. It then holds the relay down for at least the fixed
fault interval and starts only `campus-link-relay.service`.

After the manual start, systemd's restart counter must have reset to zero;
that post-manual-start value, rather than the pre-stop counter, is pinned. The
actuator rejects buffered future input, creates a second fresh server
challenge, and publishes the started proof. The gate observes both edges
reconnect to that exact invocation, then signs a domain-separated commit
transcript chaining both challenges, both invocation digests, the session and
deployment/helper bindings, restart duration, and active state. Only an exact
signed commit frame on the same channel starts the fixed five-second stability
interval. Throughout that interval the actuator requires the same invocation
to remain active and `NRestarts` to remain zero. Only afterward may it publish
the final pass and close the channel. A prequeued, fragmented, NUL-decorated,
oversized, duplicated, stale, cross-phase, cross-session, or unsigned frame;
a crash; an automatic restart; an invocation change; a missing commit; or an
early channel close fails the action.

The command returns over the host-key-pinned
SSH channel an exact three-phase bounded schema containing the echoed run ID,
candidate-manifest-bound actuator, permit-authorizer, and forced-command
digests, two fresh server challenges, a stopped proof,
distinct SHA-256 digests of the pre- and post-restart systemd invocation IDs,
the fixed hold, measured restart duration, and `ACTIVE=1`; it exposes neither invocation
ID, address, username, key, nor host identifier. A missing, duplicated,
case-variant, replayed, stale, or expanded acknowledgement fails closed. Each
line has a fixed maximum length, stderr is file-size bounded, and successful
completion requires EOF immediately after the final canonical line. The raw
SSH stdout is retained byte-for-byte and must equal the independently rebuilt
canonical acknowledgement, so NUL bytes cannot be discarded by a shell
parser. The bounded line parser is not authoritative by itself. Before any
stopped, release, started, or commit phase transition, the driver waits for its
root-only raw capture to reach the canonical phase length, requires exact
byte-for-byte equality, and requires the capture to remain exactly unchanged
through a 150-millisecond anti-prequeue interval. NUL, CR, premature EOF, an
overlong line, a missing newline, and any prequeued later-phase byte therefore
fail before the transition; raw-capture comparison at the end is defense in
depth, not permission to act on a lossy intermediate parse. Buffered or delayed
trailing bytes are an expanded acknowledgement and fail the gate.
Crossing the anti-prequeue deadline while starting its final bounded sleep is
not itself a failure: the driver re-reads the monotonic clock, revalidates the
child and raw-file identity/length, and performs the final exact comparison.
Only a clock at or beyond the stability deadline can complete that wait.
Inbound
frames are retained byte-for-byte in root-only bounded
files under a single absolute monotonic deadline; the parser never retries
after a partial read, so Bash's NUL stripping and polling-read prefix loss are
outside the trust boundary. The SSH/timeout/raw-capture pipeline runs in a
dedicated local process group. Cleanup owns one absolute deadline and targets
the pinned group rather than only its Bash coordinator. A negative-PGID signal
is permitted only while the pinned session leader still has its recorded start
time; an identity mismatch or inspection error forbids the signal and fails the
gate. The transport enumerates every other member of its session, including a
descendant that changed process group, and revalidates each PID, start time, and
session membership immediately before an individual signal. Process and
session inspection is tri-state: an inspection error is never absence, and
success requires a proven absent session. A raw shell `wait` is allowed only
after the recorded child is proven an exact-identity zombie or its `/proc` path
is proven absent. A start-time mismatch is a distinct identity error, never
"gone", and can never reach `wait`, because that numeric PID may now name a
different child. An uninterruptible kernel task therefore cannot suspend
cleanup past its deadline or become a false success. Such a task is a host
failure and keeps the gate failed.
The gate removes a reaped restart-driver PID from its cleanup set before any
subsequent acknowledgement or reconnection check, so PID reuse cannot direct a
failure cleanup signal at an unrelated process.

The fault-stream gate establishes one absolute cleanup deadline before it
removes any injected firewall or netem state. Every inspection and removal is
bounded by the residual deadline, duplicate-rule deletion has a finite bound,
and absence is verified. A removal or inspection failure records cleanup
failure but cannot skip the remaining fault rollback or process supervision;
the gate may report success only after both injected network state and every
owned process are proven absent.
The bounded fault result records exactly one verified signed permit, one
session binding, one permit consumption, two signed phase authorizations, one
same-channel commit, zero post-start `NRestarts` delta, and the fixed
5,000-millisecond post-commit stability interval. The edge-status
snapshot used as the next fault's baseline is captured only after that final
acknowledgement, while the original application stream and both edge
invocations are still proven continuous.

Every forced-command script uses the absolute `/bin/bash` interpreter in
privileged mode, fixes its executable search path, rejects inherited shell,
dynamic-loader, and OpenSSL provider/configuration injection variables, and
invokes privileged helpers through absolute paths. Relay provisioning verifies
the effective `sshd` policy, requires user environment files to be disabled,
and rejects accepted or server-set environment patterns that can supply those
variables. Every secret-bearing forced command, permit authorizer, actuator,
driver, and transport process independently lowers both its soft and hard
core-file limits to zero before parsing stdin or creating session material and
verifies the result; a host policy that prevents this fails closed. Therefore
a globally permissive SSH environment policy cannot turn
the restricted key or same-channel release/commit input into shell or provider
initialization code; such a host fails provisioning instead.

The TCP client performs its sole `connect` and the server performs its sole
`accept` before this authenticated restart begins. Only after validating both
the authenticated stopped proof and the two-edge control-outage observation,
the gate snapshots fresh per-direction receive-byte and monotonic-timestamp
baselines. Both receive-progress files must then advance in byte count and
monotonic timestamp from those post-stop baselines before the gate releases
the stopped relay process. A byte or timestamp observed during SSH setup,
before the stopped proof, or before the control-outage observation cannot
satisfy this requirement. Both edge invocations
must remain unchanged, the direct epoch/instance and exact peer-data identity
must remain pinned, and relay-data counters must remain unchanged. After the
relay returns, both edges must establish later authenticated control-session
serials without replacing the application socket. Fresh health connections
or a restart test performed outside the streaming interval are not relay
restart evidence.

The direct-path fault drops UDP in both router WAN namespaces while leaving
TCP control available. Both edges must publish `selected=none` with no usable
direct peer binding; selecting the warm relay is a failure. After actual
application receive progress has stopped in both directions, the drop is
retained until at least 15 seconds after the later last-received byte. This
exceeds the 12-second QUIC idle timeout and therefore forces withdrawal without
making the gate impossible to satisfy after the mandatory five-second direct
stability exchange. Both progress streams are monitored continuously; any
advance restarts the hold. Their final stalled counters are captured
immediately before removing the fault, and each later receive timestamp must
be strictly after that removal and prove a user-visible outage no greater than
25 seconds. Both edges must return to a healthy direct
selection with an exact selected-path/data-identity binding. Same-plan-epoch
retry is allowed, but the observed withdrawal, watchdog failure, and later
selection must prove that each edge's sanitized direct-instance generation
strictly increased. Recovery must also precede the independent 30-second
no-path process deadline.

Every systemd counter, progress sample, and measured rate used by this gate is
read through a canonical unsigned-decimal parser. Empty values, signs, leading
zeroes, overflow, failed reads, and failed conversions are errors. Each helper
and command-substitution caller propagates failure explicitly, so Bash
conditional-context semantics cannot mask an invalid measurement with a later
successful expression.

The gate pins both edge services' systemd invocation IDs and restart counts
before its first snapshot and checks them after every fault and after stream
completion. Each edge unit must enforce a memory maximum no greater than 96
MiB; kernel-reported memory and bounded periodic samples may not exceed that
ceiling. Memory-sample aggregation is fail closed: the aggregation producer's
exit status is checked directly and may not be hidden by process substitution.
`memory.tsv` must be nonempty, and every row must contain exactly two canonical
unsigned-decimal fields separated by one tab. Each field is bounded to the
configured memory ceiling before numeric comparison, so neither awk rounding
nor signed shell-arithmetic overflow is possible; malformed, empty,
leading-zero, oversized, or extra-field input fails the gate. The producer
writes through a root-private temporary file, and the consumer parses exactly
one canonical, bounded `<edge-a-peak> <edge-b-peak>` line. Both systemd
`MemoryPeak` reads are mandatory canonical unsigned-decimal evidence; a failed,
empty, malformed, leading-zero, or oversized read fails rather than being
ignored. The gate takes the greater of each sampled and kernel peak before
comparing both combined peaks with the ceiling. Across the entire transaction,
both directions' direct send, receive,
and authenticated progress counters must advance, while edge relay-data and
fallback counters remain exactly unchanged. Mux receive-queue drops and the
edge's top-level rejected/dropped packet counter must also remain exactly
unchanged; TCP checksum and retransmission success may not conceal loss inside
the tunnel implementation. Mux invalid-envelope/policy and replay-duplicate
counters must likewise remain exactly unchanged at every ordinary bulk and
fault-stream evidence boundary; transport retransmission cannot turn either
condition into a passing result. Authenticated relay raw-forwarding growth is
bounded only by the recorded time-based warm-keepalive allowance and must not
scale with stream bytes.

Under that fixed impairment profile, both measured application directions must
average at least 2.000 Mbit/s including the injected outages. At that floor a
2 GiB direction completes in about 2.4 hours, leaving more than 90 minutes of
the four-hour supervised-service budget for setup, fault observation,
re-establishment, and evidence validation. The marker records the fixed floor
and each measured rate in milli-Mbit/s so the chain compares integers.

The root-only atomic result binds the run, immutable candidate, run manifest,
and accelerated-fault prerequisite hash. It records the configured bytes,
impairment bounds, broker-outage duration, both sets of three receive-progress
samples, their per-direction byte deltas and final guard, both
last-byte-to-next-byte outages, configured and measured impaired throughput,
memory ceiling and observed peaks, process-continuity check count, checksum
directions, exactly one signed relay-restart permit and consumption, direct
withdrawal and re-establishment observations, exact
identity/path check count, and the sanitized counter deltas. The evidence-chain
validator recomputes all fixed bounds and refuses a cached, reordered,
test-mode, or schema-expanded marker.

### NAT-rebinding transaction and gate

The dedicated production NAT-rebinding gate runs immediately after
`fault-in-stream` and before the 24-hour soak. It starts exactly one TCP
connection from the A-side LAN process to the B-side LAN process; the client
has one `connect` and no reconnect path, and the server has one `accept` before
closing its listener. That connection continuously exchanges authenticated,
sequence-contiguous 1 MiB records in both directions. Each completed record's
two streaming SHA-256 values and reciprocal acknowledgements extend one
domain-separated transcript, and the stop marker is accepted only at a
completed record boundary.

After at least one completed record, the gate pins both edge service
invocations and restart counts, direct epochs and instances, authenticated
identities, relay application counters, and the continuous-stream identity. It
then tests edge A and edge B serially; no two temporary NAT rules may coexist.
For one edge, it identifies the sole UDP socket owned by the pinned edge
process, records the relay-facing translated port without serializing it, and
inserts one exact source/interface/protocol/socket-scoped `MASQUERADE` rule
whose port range is disjoint from every pre-fault translated port. Immediately
before deleting only that socket's bounded UDP conntrack entries, it pins a
fresh completed-record checkpoint. The forced mapping must be unique, inside
the forced range, and different from the old mapping; later evidence must
advance beyond that checkpoint. After direct progress resumes, all conntrack
entries for the exact socket, including its peer-facing direct entry, must use
the forced range. The rule remains until a later full-duplex record completes
on the original TCP connection.

The gate then removes only its exact rule, pins another fresh checkpoint,
deletes the same bounded conntrack entries, observes a unique restored mapping
different from the forced mapping, and completes another later record on the
same TCP connection. Every transition proves that the other WAN's mapping is
unchanged. After each site's forced/restored pair, and during failure or signal
cleanup, the complete NAT ruleset must be byte-for-byte equal to its pre-gate
snapshot; cleanup never flushes a table or deletes another source's conntrack
state.

Every post-change boundary again shows both edges on authenticated healthy
direct paths with one nonzero shared epoch and exact data identities. A valid
boundary is either a migration, where both edge instances and the epoch are
unchanged, or withdrawal and re-establishment, where both edge instances
strictly increase and the epoch does not regress. Mixed or one-sided instance
replacement, epoch regression, or identity mismatch fails closed. Each
transition must resume a later complete record within 25 seconds. Edge
invocations and restart counts remain exact; relay application sent/received,
fallback, queue-drop, invalid, duplicate, and dropped counters and
authenticated relay drop packet/byte counters remain unchanged. Raw relay
forwarding may grow only within the duration-derived warm-association packet
and byte allowances.

The root-owned mode-0600 atomic result is
`/run/campus-link/nat-rebinding.result`. Its exact format-1 key order is:

```text
FORMAT
STATUS
GATE
MODE
RUN_ID
CANDIDATE_SHA256
RUN_MANIFEST_SHA256
PREREQUISITE_MARKER_SHA256
START_MONOTONIC_MS
COMPLETE_MONOTONIC_MS
FAULT_SITES
FORCED_MAPPING_CHANGES
RESTORATION_MAPPING_CHANGES
MAPPING_CHANGE_OBSERVATIONS
SOCKET_MAPPING_PROFILE_CHECKS
UNTOUCHED_WAN_MAPPING_CHECKS
CONNTRACK_SCOPED_DELETIONS
NAT_RULESET_RESTORATIONS
FAULT_RECOVERY_TIMEOUT_MS
MATCHED_DIRECT_EPOCH_CHECKS
MIGRATED_PATHS
REESTABLISHED_PATHS
HIGHER_DIRECT_INSTANCE_EDGE_CHECKS
PROCESS_CONTINUITY_CHECKS
TCP_CONNECTIONS
TCP_RECONNECTS
STREAM_RECORD_BYTES
FULL_DUPLEX_RECORDS
STREAM_BYTES_A_TO_B
STREAM_BYTES_B_TO_A
FIRST_A_TO_B_SEQUENCE
LAST_A_TO_B_SEQUENCE
FIRST_B_TO_A_SEQUENCE
LAST_B_TO_A_SEQUENCE
STREAM_TRANSCRIPT_SHA256
MAX_PROGRESS_GAP_A_TO_B_MS
MAX_PROGRESS_GAP_B_TO_A_MS
EDGE_A_DIRECT_SENT_DELTA
EDGE_A_DIRECT_RECEIVED_DELTA
EDGE_A_DIRECT_PROGRESS_DELTA
EDGE_A_RELAY_SENT_DELTA
EDGE_A_RELAY_RECEIVED_DELTA
EDGE_B_DIRECT_SENT_DELTA
EDGE_B_DIRECT_RECEIVED_DELTA
EDGE_B_DIRECT_PROGRESS_DELTA
EDGE_B_RELAY_SENT_DELTA
EDGE_B_RELAY_RECEIVED_DELTA
RAW_RELAY_PACKET_LIMIT_PER_SITE
RAW_RELAY_BYTE_LIMIT_PER_SITE
RAW_RELAY_SITE_A_DELTA
RAW_RELAY_SITE_A_BYTES_DELTA
RAW_RELAY_SITE_B_DELTA
RAW_RELAY_SITE_B_BYTES_DELTA
```

The validator requires `GATE=nat-rebinding`, `MODE=production`, the exact
`fault-in-stream.result` prerequisite hash, and start time no earlier than that
marker's completion. It requires two fault sites, two forced and two
restoration mapping changes, four mapping observations, four socket-profile
checks, four untouched-WAN checks, four scoped deletions, two exact ruleset
restorations, a 25,000 ms recovery timeout, four matched-epoch checks, and 12
process-continuity checks. `MIGRATED_PATHS + REESTABLISHED_PATHS` is exactly
four and `HIGHER_DIRECT_INSTANCE_EDGE_CHECKS` is exactly twice the
re-established count.

Final stream evidence requires one connection, zero reconnects, 1,048,576-byte
records, at least one full-duplex record, a lowercase SHA-256 transcript,
contiguous sequence endpoints, and both maximum progress gaps no greater than
25,000 ms. Before multiplying, the validator bounds the record count to the
largest value whose product with 1,048,576 fits signed 64-bit shell
arithmetic; each directional byte total then equals that exact product.
Sequence relations are checked by nonnegative bounded differences, and every
other multiplication is similarly preceded by a range bound. All six direct
counter deltas are positive, all four edge relay application deltas are zero,
and each raw relay packet/byte delta is no greater than its corresponding
nonnegative allowance. The marker contains no address, translated port,
interface, namespace, PID, invocation ID, socket inode, credential, token, or
key material.

The candidate fingerprint covers the installed NAT runner, verifier, and unit.
The 24-hour unit both orders after this service and asserts its marker, and its
marker hash-chains this exact NAT result. The coordinator removes only the
bounded NAT marker before a new run. Adding this chain member makes all older
marker sets incompatible: deployment integration requires a fresh offline
qualification run, and no old result may be reinterpreted or grandfathered.

### Continuous 24-hour soak and seven-day burn-in

The 24-hour soak and seven-day burn-in each establish exactly one TCP
connection from A11 to B22 after all prerequisite and service-continuity
snapshots have passed. That same socket carries deterministic,
sequence-contiguous records in both directions simultaneously for the entire
required interval. Each direction's record is exactly 16 MiB and has an
independently checked streaming SHA-256 digest and reciprocal acknowledgement.
The client performs one
`connect`, the server performs one `accept`, and neither side contains a
reconnect path. An EOF, half-close, second connection, process replacement,
missing record, duplicate record, digest mismatch, or replacement edge
invocation fails the gate; a sequence of successful fresh health connections
is not soak evidence.  After EOF, the server must exit successfully and its
entire bounded log must be byte-for-byte equal to the canonical single line
`PASS connections=1 reconnects=0 records=N`, where `N` is the client's exact
verified full-duplex record count.  Signaling an unverified server or accepting
a prefix, extra line, missing newline, or mismatched count cannot produce a
passing soak.

The required interval begins at the continuous session's monotonic start, not
at server setup. Send and receive payload progress have independent 30-second
deadlines, so traffic in one direction cannot hide a stalled reverse
direction. Each direction must also average at least 2.000 Mbit/s across the
required interval. The transport has one absolute deadline: after the required
interval is reached, the in-flight bounded record and both authenticated
acknowledgements must finish within a 120-second completion grace. The runner
observes monotonically increasing per-direction byte totals at least every
five seconds, while independently rechecking the immutable candidate, route,
edge activity, invocation IDs, and restart counts. A malformed, stale,
regressing, symlinked, expanded, or non-root-private progress file fails
closed.

The same observation cadence captures both root-owned edge status files.  Each
successfully published edge status carries a nonzero, monotonically increasing
`status_generation`.  It also carries sticky, monotonically increasing
`selected_path_transitions` and `identity_transitions` counters.  A committed
selected-path change (including a direct-to-none/relay-to-direct round trip or
path-authority replacement) increments the former even if the final selected
path equals its starting value.  A control or selected-data identity/binding
change increments the latter even if the public expiry/slot view later returns
to its starting value.  These counters expose no key, certificate, address,
session, epoch, instance, or other private identifier.
The counters saturate instead of wrapping; a saturated transition counter or
publication generation is invalid evidence and fails closed.

The initial status snapshot precedes the sole application connection.  Every
later observation waits, within the bounded sample interval, until both edges'
publication generations have advanced beyond the immediately preceding
snapshot; repeatedly recapturing one still-fresh file is not a new observation.
The new snapshot is then checked against both the fixed baseline and the
immediately preceding snapshot.  Both sticky transition counters must remain
exactly pinned to their per-edge baseline values for the whole soak.  At every
observation both edges must remain healthy on the same exact direct epoch and
instance, with the same current-slot control and data identities and an exact
direct selected-path/data-identity binding.  Direct, telemetry, raw-forwarding,
and drop counters may not regress.  Edge relay, fallback, queue-drop,
invalid-envelope, replay-duplicate, top-level drop, and watchdog-failure
counters remain exactly unchanged.  The authenticated raw relay packet and byte
totals are bounded cumulatively from the single initial snapshot, so repeated
observations cannot repeatedly claim the setup allowance.  The final snapshot
must cover the full stream interval, show positive direct send, receive, and
authenticated-progress deltas in both directions, and show an advanced
authenticated relay-telemetry sequence without a control-session change.
Missing or late publications or observations, a transient relay or no-path
selection, identity or direct-instance replacement, and packet or byte growth
beyond the time-derived warm-keepalive allowances fail the soak.

The pass marker records `DIRECT_STATUS_OBSERVATIONS` and the complete sanitized
direct-evidence schema (`DIRECT_EVIDENCE_DURATION_MS`, per-edge direct and
forbidden-path deltas, and per-site authenticated raw-relay packet/byte limits
and deltas).  It contains no certificate, address, session, epoch, instance, or
other private identifier.  The status-evidence interval starts before the
application session and ends immediately after it; it may exceed the required
stream interval plus the 120-second completion grace by at most 60 seconds of
bounded setup and final-verification overhead.  The chain validator recomputes
both raw-relay limits from that exact duration and rejects missing, duplicate,
or inconsistent evidence fields.

Before multiplying a record count by the fixed 16 MiB record size, both the
runner and chain validator require `FULL_DUPLEX_RECORDS <= 549755813887`, the
largest count whose product fits signed 64-bit shell arithmetic.  The runner
passes its fully composed result through the same continuous-stream and direct
evidence value validators before the atomic marker rename; a schema-valid but
arithmetically invalid marker may not be emitted even if a later chain member
would reject it.

Every soak child starts in a shell wrapper behind a root-owned, mode-0600,
two-FIFO readiness/acknowledgement handshake inside the private evidence
directory.  The parent supplies a fresh 128-bit nonce.  Before `exec`, the
wrapper publishes that nonce, its `BASHPID`, and its own `/proc` start tick, then
remains alive and blocked for at most five seconds.  The parent requires the
exact nonce and `$!`, revalidates the reported start tick while the wrapper is
still blocked, records that identity, and only then returns the nonce as the
acknowledgement that permits `exec`.  Missing, malformed, late, mismatched, or
extra readiness data fails closed; an unacknowledged wrapper times out by
itself.  Thus a child that exits before readiness cannot cause a reused PID to
be enrolled as an owned child.

Every startup, running, and completion liveness poll rereads the same start
tick: `live`, `zombie`, `gone`, start-tick mismatch, and inspection failure are
distinct outcomes.  Only the exact `live` child may satisfy a required-live
check; only `zombie` or `gone` may end a completion poll; mismatch or inspection
failure fails the gate.  A raw numeric `kill -0` is never child identity
evidence.

On every exit, one absolute 25-second cleanup transaction revalidates
PID/start-tick identity before signaling.  Signals are sent only through a
Linux pidfd opened for that PID and bracketed by two matching `/proc/<pid>`
directory identities and matching start-tick reads; a raw numeric signal is
forbidden.  The transaction sends `TERM`, escalates a still-live exact child to
`KILL` after five seconds, waits only for a proven zombie or absent exact child,
and proves all tracked children cleared.  PID reuse, unreadable identity,
unsupported pidfd signaling, or failure to reap is a cleanup failure and never
reaches a signal or `wait`.  The unit's `KillMode=control-group` is a bounded
service-stop backstop, not a substitute for per-child identity proof.
Temporary evidence is removed only after that proof; failed cleanup leaves the
root-private evidence directory intact, and a cleanup failure converts an
otherwise successful runner exit to failure.  The 25-second shell bound remains
strictly inside each unit's 30-second stop bound.

Both long-running soak units set `MemoryMax=768M`, `TasksMax=256`, and
`LimitNOFILE=512` for the shell and its two streaming Python children.  They
retain `OOMPolicy=stop`; crossing any resource limit or suffering an OOM kill
fails the supervised service job and therefore cannot satisfy the qualification
chain, even if an untrappable kernel kill leaves a same-run bounded result file.
These bounds allow the fixed 64-KiB streaming buffers and bounded worker set
without allowing a seven-day worker, descriptor, or memory leak to consume the
host.

The atomic pass marker exposes no address, port, socket tuple, process ID, or
connection nonce. In addition to the common run, candidate, prerequisite, and
duration fields, its exact soak evidence is: `TCP_CONNECTIONS=1`,
`TCP_RECONNECTS=0`, `FULL_DUPLEX_RECORDS`, `STREAM_BYTES_A_TO_B`,
`STREAM_BYTES_B_TO_A`, `FIRST_A_TO_B_SEQUENCE`, `LAST_A_TO_B_SEQUENCE`,
`FIRST_B_TO_A_SEQUENCE`, `LAST_B_TO_A_SEQUENCE`,
`STREAM_TRANSCRIPT_SHA256`, `PROGRESS_TIMEOUT_MS=30000`,
`COMPLETION_GRACE_SECONDS=120`, `MAX_PROGRESS_GAP_A_TO_B_MS`,
`MAX_PROGRESS_GAP_B_TO_A_MS`, and `PROGRESS_OBSERVATIONS`. The validator
requires at least one fully acknowledged record, exact byte/sequence
accounting, at least 250,000 payload bytes per required second in each
direction, both maximum gaps within the progress deadline, sufficient
observations for the required interval, and a lowercase SHA-256 transcript of
all completed bidirectional record metadata and digests. The seven-day marker
hash-chains the qualifying 24-hour marker; neither gate may reuse the other's
TCP connection or progress file.

Outside the certificate-rotation transaction, every control and data identity
observation in a qualification snapshot must be in the `current` pin slot.
Seeing `next` in an ordinary bulk, fault-in-stream, NAT-rebinding, soak, or
final boundary is a failure, not evidence of proactive rotation; only the
rotation gate may temporarily admit and interpret next-slot observations.

Relay forwarding evidence is carried to each edge only in the authenticated,
deployment-bound control session. A qualification gate never trusts a local
copy of the remote relay's status file. Before and after the transfer, both
edge status snapshots must be fresh, must name the current control session,
and must show that an authenticated relay-telemetry sequence advanced. Missing,
cross-session, duplicate, future, or regressing telemetry and counter wrap all
fail closed. To tolerate observation skew without undercounting, raw relay
packet and byte growth are each the maximum forwarded total observed after the
transfer minus the minimum forwarded total observed before it, independently
for each direction. Production qualification requires forwarded byte growth to
remain within the recorded keepalive byte baseline as well as the packet
baseline, so a bulk transfer cannot be hidden inside a small packet count. Edge
relay-data counters must independently remain exactly unchanged. The two
allowances are independent and reproducible: each direction receives 32 setup
packets plus one packet per elapsed second, but only 65,536 setup bytes plus 64
bytes per elapsed second. The 2048-byte protocol maximum is not a byte
allowance: filling otherwise allowed packets to that maximum must fail the byte
gate. Both limits and both measured per-site deltas are recorded in the fixed
evidence schema and recomputed by the shell chain.

Because the sanitized control-session serial is process-local, full
qualification also binds the evidence interval to each edge service's exact
systemd invocation ID and restart count. The gate snapshots both values before
the first edge-status capture, verifies them again immediately after that
capture, and verifies the same values after the final capture. A missing or
malformed value, service-manager replacement, process restart, or invocation
change fails closed; a newly started process may not satisfy an in-progress
evidence interval even if it happens to reuse the same local counter values.

Each full-qualification edge snapshot also contains the four sanitized
identity observations already published by the edge: local and peer on the
control and data planes. Every observation has exactly an RFC 3339 UTC expiry
and a `current` or `next` pin-slot label, and must remain outside the five-minute
reconnect margin. Those four observations must remain identical across one
bulk-evidence interval; an identity transition is exercised by the separate
rotation gate, never hidden inside an ordinary throughput result.

Both edges must report synchronized time relative to the authenticated relay
with a conservative absolute bound no greater than one second before a
rendezvous gate; wall-clock plan timestamps are not treated as monotonic and
an unsynchronized edge fails
closed. Direct-path qualification covers endpoint-independent, address-
dependent, port-restricted, double-NAT, and the actual two deployment NATs.
The relay-observed tuple alone cannot traverse arbitrary endpoint-dependent
symmetric NAT. Such a case must either obtain an authenticated explicit
mapping (PCP/NAT-PMP/static rule), use a directly reachable authenticated IPv6
candidate, or fail the direct-only bulk gate. Until one of those authenticated
direct mechanisms succeeds, the production profile remains in bounded TUN
backpressure; carrying application bytes through the warm relay is forbidden.
