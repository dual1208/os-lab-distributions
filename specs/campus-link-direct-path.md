# campus-link rendezvous-assisted direct-path contract

Status: design approved by the user's 2026-07-28 correction; rendezvous
foundations only. Direct forwarding, migration, and production qualification
are not implemented.

## Objective

Carry routed traffic between `10.81.0.0/24` and `10.82.0.0/24` directly between
the two authenticated edges whenever NAT traversal succeeds. The `gz` host is
the rendezvous/control authority and an emergency blind relay, not the healthy
bulk-data path.

The canonical application pair remains A11 (`10.81.0.11`) and B22
(`10.82.0.22`). Existing Phase-1 relay service remains the rollback candidate
until every gate in this contract passes.

## Pinned donor study

FRP `xtcp` was inspected as an architectural donor, not adopted as a binary or
library dependency:

- upstream: `https://github.com/fatedier/frp`;
- user's fork: `https://github.com/dual1208/frp`;
- branch and inspected revision: `dev` at
  `5c6d761c1287e6153f07b824fb6d71b96ee598fe`;
- license: Apache-2.0.

At that revision, `xtcp` performs a pre-check through `frps`, discovers mapped
addresses with STUN, and sends the visitor and proxy observations to `frps`.
The server classifies the two NAT mappings, selects complementary sender and
receiver behavior, supplies peer candidates and timing, and records successful
strategies. The peers exchange secret-key-authenticated UDP session probes and
then run KCP or QUIC directly over the selected UDP socket. The visitor can
fall back to another FRP visitor after a timeout.

The following donor behavior is intentionally not copied:

- FRP's fallback transfers a new accepted TCP connection; it does not preserve
  a routed TUN or already-running arbitrary flows through an underlay change.
- Its shared `secretKey` authentication is weaker and less compartmentalized
  than campus-link's separate control and data PKIs.
- Its NAT categories and port-search heuristics are evidence-driven hints, not
  a guarantee that every CGNAT or symmetric-NAT pair is traversable.
- It exposes a TCP service abstraction rather than two fixed routed prefixes.

## Scope and non-goals

In scope:

- authenticated rendezvous over each edge's existing outbound TLS 1.3
  TCP/443 control session to `gz`;
- reflexive and local UDP candidate discovery from the same socket that will
  carry direct QUIC;
- coordinated authenticated UDP hole punching;
- direct end-to-end TLS 1.3 QUIC DATAGRAM transport between the two edges;
- automatic, bounded fallback through the existing blind UDP relay;
- automatic re-probing and make-before-break return to a stable direct path;
- persistent TUN devices and routes while at least one authenticated data path
  is usable; and
- deterministic unit, namespace, impairment, NAT, security, and soak tests.

Not in scope:

- claiming that UDP hole punching works through every NAT, CGNAT, firewall, or
  UDP-blocked network;
- lossless semantics for arbitrary inner UDP. Inner TCP and application-level
  reliable protocols retransmit; ordinary UDP remains best effort;
- hiding public endpoint candidates from `gz`, which must observe or convey
  them to coordinate traversal;
- preserving a flow through an edge reboot, certificate loss, or simultaneous
  loss of both direct and relay paths; or
- adopting FRP as the deployed router tunnel.

## Required architecture

```text
                     gz TCP/443 rendezvous
                 ┌──────────────────────────┐
                 │ mTLS control, candidates │
                 │ timing, path reports     │
                 │ UDP relay only on failure│
                 └────────────┬─────────────┘
                              │
        control + probes      │       control + probes
                 ┌────────────┴────────────┐
                 ▼                         ▼
       ┌──────────────────┐      ┌──────────────────┐
       │ edge A / router A│══════│ edge B / router B│
       │ 10.81.0.0/24     │ QUIC │ 10.82.0.0/24     │
       └──────────────────┘direct└──────────────────┘
```

### Control and rendezvous

1. Each edge authenticates to `gz` with its control certificate and registers
   its fixed site, circuit, prefix, generation, supported traversal version,
   and bounded capabilities.
2. Each edge allocates one UDP socket and sends authenticated observations to
   `gz` from that socket. `gz` records the observed reflexive tuple. Optional
   configured STUN servers may add observations from alternate server
   addresses, but discovery must retain the eventual data socket.
3. Once both current circuit owners are present, `gz` creates a random,
   expiring rendezvous session ID and probe key, then sends each edge the peer's
   candidates, complementary role, start deadline, attempt number, and bounded
   probe plan over its mTLS control connection.
4. Every plan is scoped to the two current owner generations. Replacing either
   owner invalidates all outstanding sessions and probe keys for the old pair.
5. Plans and candidates are bounded, syntactically validated, and never written
   to logs, status files, Git, or verification artifacts.

### Hole punching and direct QUIC

1. The peers send authenticated probes from the eventual data socket to the
   supplied candidates. A probe covers protocol version, circuit, session ID,
   attempt, role, expiry, random nonce, and asserted sender role with
   HMAC-SHA-256. Because `gz` and both routers know this attempt key, the HMAC
   proves attempt membership, not asymmetric router identity; subsequent exact
   data-plane mTLS remains the identity boundary.
2. Replays, expired plans, wrong roles, unknown sessions, invalid HMACs,
   reflected responses, unexpected source candidates, and oversized packets
   are rejected without changing path state.
3. The selected receiver keeps the winning socket and accepts exactly one QUIC
   connection from the authenticated peer; the sender dials that observed
   source. QUIC then performs the existing separate data-plane mTLS handshake,
   including exact expected peer identity. Possession of a rendezvous probe key
   is never sufficient to enter the routed data plane.
4. Routes are first installed only after the direct QUIC handshake, a bounded
   bidirectional application probe, and prefix/MTU validation succeed. Healthy
   data packets then travel edge-to-edge and do not traverse `gz`.
5. Candidate attempts start with observed and local/hairpin candidates. A later
   implementation phase may add bounded adjacent/random port search for NATs
   whose mapping evidence warrants it. The default must not scan the Internet
   or exceed the plan's packet, port, time, or rate budget.

### Persistent tunnel and fallback

The edge process owns the TUN for its lifetime instead of coupling it to one
QUIC session. Its path state machine is:

```text
STARTING -> RELAY_READY -> PUNCHING -> DIRECT_PROBING -> DIRECT
              ^              |              |             |
              └──────────────┴──────────────┴-- failure ---┘
```

- `DIRECT` is preferred. `gz` forwards no data while it is healthy.
- The relay path may remain authenticated and NAT-bound as a warm standby, but
  application packets must not be duplicated to it in steady state.
- Direct liveness requires recent authenticated QUIC activity and active probes,
  not merely a live process or control socket.
- On direct failure, the edge atomically selects a verified relay session,
  keeps the TUN and routes present, and resumes forwarding within the recovery
  objective. Packets in the failed outer path may be lost; inner TCP must
  recover by retransmission without reconnection in the qualification tests.
- The bounded transition queue drops explicitly on overflow. It never grows
  without limit, blocks control progress, or silently reports delivery.
- While relayed, both edges retry rendezvous with exponential backoff and
  jitter. A new direct path must pass a stability window before selection.
  Returning to direct is make-before-break and uses one monotonically increasing
  path epoch so stale sessions cannot reclaim traffic.
- Only simultaneous loss of direct and relay health withdraws routes and fails
  closed. Loss of rendezvous control alone does not immediately destroy a
  healthy authenticated direct QUIC connection; it prevents new sessions and
  starts a bounded control-recovery deadline.

## Security and privacy invariants

- Control and data trust roots remain distinct. `gz` never receives a data
  private key, data CA signing key, or decrypted LAN packet.
- TLS 1.3 and exact peer identities are mandatory on both direct and relay data
  QUIC. A path never becomes usable based only on an IP address or probe HMAC.
- Rendezvous keys are 256-bit random values delivered only over the two current
  mTLS control sessions, expire after at most 60 seconds, and are erased on
  success, replacement, disconnect, or timeout.
- Probe encoding has a fixed version and maximum size, constant-time MAC
  comparison, timestamps with a bounded skew policy, and replay caches bounded
  by count and expiry.
- Candidate lists allow only valid unicast UDP endpoints and reject unspecified,
  multicast, broadcast, loopback-from-a-remote-peer, and forbidden metadata or
  management ranges. Local/private candidates are attempted only under the
  documented same-network/hairpin policy.
- The relay accepts data only from both authenticated, challenged fallback
  tuples. Direct-path negotiation never weakens its current anti-amplification,
  size, generation-ownership, or fixed-prefix checks.
- Status exposes state, attempt counts, aggregate bytes, timing, and redacted
  error classes. It never exposes candidates, tokens, certificate identifiers,
  packet bodies, or public addresses.

## Reliability invariants

- One generation exclusively owns each site. Old disconnects and delayed
  rendezvous responses cannot clear or activate a replacement.
- Duplicate, reordered, and delayed control messages and probes are idempotent.
- Both peers deterministically agree on selected path epoch and role. A split
  state where one sends direct and the other only receives relay must converge
  or fail closed within a bounded deadline.
- Backoff, timers, queues, goroutines, sockets, replay state, and candidate
  counts are bounded and configuration-validated.
- NAT rebinding, public-address change, direct QUIC loss, `gz` restart, control
  replacement, and relay tuple replacement converge without manual route work.
- Existing A11↔B22 TCP sessions survive a direct-to-relay or relay-to-direct
  underlay transition in the mandatory tests. If evidence shows the selected
  QUIC/TUN implementation cannot meet this, the spec must be revised before
  code is weakened or a production claim is made.

## 2026-07-28 adversarial implementation gate

The first adversarial review established that every current data packet still
uses the relay. Rendezvous plans are enqueued but never consumed;
`rendezvous.Punch`, `ReplayCache`, `pathstate.Manager`, and `PathReport` have no
runtime caller. A shared generation emitted by the installer is rejected as its
own peer generation, and an invalid optional plan currently tears down the
otherwise healthy relay path. These conditions block deployment of current
HEAD, but do not invalidate the previously deployed Phase-1 candidate.

Implementation must close these defects in this order:

1. Generate independent site generations. Quarantine an invalid or failed
   direct attempt without cancelling a healthy fallback session.
2. Give one component exclusive ownership of the NAT-mapped UDP socket. It
   demultiplexes bounded binding, rendezvous, and QUIC traffic; raw punching and
   quic-go may not concurrently call `ReadFromUDP` or change each other's
   deadlines.
3. Replace the one-shot binding exchange with an authenticated transaction
   scoped to control session, site, request nonce, and challenge. Every flight,
   including READY, is replay-safe and idempotently retransmittable under loss
   and reorder.
4. Correlate probe responses to request nonces, invoke a bounded replay cache,
   expire and erase plans/keys, accept success/failure reports, and create fresh
   attempts with bounded jittered backoff. A failed punch settles on a stable
   relay without a reconnect storm.
5. Keep one process-lifetime TUN and central packet pump. Validate both paths,
   coordinate ready/commit with the peer, accept a narrowly bounded previous
   epoch during transition, and carry an authenticated tunnel envelope with
   version, path epoch, and packet sequence.
6. Validate a conservative end-to-end datagram budget before route activation.
   PMTU reduction, stalled packet progress, queue overflow, and transient relay
   sends are observable bounded path failures rather than process-global exits.
7. Bound pre-auth TLS admission and heartbeat rate, back off transient accept
   errors, revalidate relay owner/tuple epochs before sends, count forwarding
   only after successful writes, and move status filesystem I/O outside the
   forwarding mutex.

Warm standby means authenticated control plus a NAT binding whose keepalive
terminates at `gz`. A relayed QUIC data session is established only when needed;
otherwise its encrypted QUIC keepalives would make an exact zero-forwarded-
packet direct-path assertion impossible.

### Large-transfer reliability gate

The completed Phase-1 relay qualification transferred and hash-verified 1 GiB
in both directions, with bulk phases of 3,167.867 and 2,942.406 seconds
(approximately 2.71 and 2.92 Mbit/s). This is useful relay integrity evidence,
not acceptable proof of a practical direct bulk path.

The direct candidate must additionally pass:

- simultaneous bidirectional 1 GiB transfers and a 4–8 GiB single-connection
  stream made of sequence-unique deterministic chunks, with exact final hashes,
  progress at least every 30 seconds, no unexplained retransmission reset, and
  a lab floor of 25 Mbit/s per single direction and 15 Mbit/s per direction
  while simultaneous;
- one long-lived sequenced TCP stream across direct-to-relay-to-direct,
  NAT rebinding, rendezvous/control loss, and `gz` restart without application
  reconnect, missing/duplicate records, or hash mismatch;
- mid-transfer burst loss, duplication, severe reorder, bandwidth restriction,
  packet corruption, and PMTU step-down with ICMP blocked;
- deterministic loss/reorder of every binding flight, repeated punching while
  fallback traffic is active, and 1,000 in-process path transitions with RSS,
  goroutine, descriptor, socket, queue, and per-reason drop counters returning
  to bounded baselines; and
- relay counter and bounded-capture proof that healthy bulk bypasses `gz` while
  control and rendezvous remain available.

No bulk phase may run without a whole-phase deadline. If the measured lab floor
is infeasible on the selected design, revise this contract with the user before
weakening the gate or making a production claim.

## Acceptance checks

### Functional and no-relay proof

- Establish a direct path between distinct NAT namespaces, then complete the
  existing 10,000-record, 100-concurrent-flow, bidirectional 1 GiB SHA-256,
  ICMP, long-idle TCP, half-close, and UDP best-effort tests.
- Snapshot `gz` relay forwarding counters immediately before and after each
  healthy 1 GiB transfer. Their delta must be zero. Bounded `gz` capture and
  interface byte counters must show only control, rendezvous probes, and
  baseline noise; edge WAN counters must show the bulk transfer.
- No inner prefix, canary payload, or application plaintext may appear at `gz`.

### NAT matrix

- Deterministic namespace/conntrack models cover no NAT, endpoint-independent
  mapping/filtering, address-restricted, port-restricted, double NAT, hairpin,
  regular port-shift, randomized/symmetric mapping, rebinding, and UDP blocked.
- Cases known to be traversable must become `DIRECT`. Cases intentionally made
  non-traversable must select `RELAY_READY` without route loss or retry storms.
- At least one real test places the edges behind different public NAT devices;
  same-host namespace success alone is not sufficient evidence.

### Failure, migration, and security

- While a long-lived TCP stream transfers unique sequenced records, inject
  direct-path loss, NAT rebinding, control loss, delayed/replayed plans, `gz`
  restart, relay loss, edge replacement, MTU black holes, 1% loss, 100 ms delay,
  jitter, reorder, duplication, and corruption. Reliable records and final
  hashes must remain exact; no manual repair is allowed.
- Direct-to-warm-relay recovery is at most 10 seconds and p95 at most 5 seconds
  over 30 trials. Cold-relay recovery retains the existing 30-second maximum.
- Return to direct requires at least 30 seconds of stable probes and causes no
  broken canonical TCP stream or path flapping.
- Unit and fuzz tests cover malformed candidates, sizes, MACs, timestamps,
  nonces, replays, reflected probes, owner replacement, stale epochs, queue
  overflow, role disagreement, and configuration bounds. Race tests cover 100
  reconnect/re-punch cycles with goroutine and descriptor return to baseline.

### Production gate

All existing production-readiness gates continue to apply. In addition, the
direct candidate requires a one-hour accelerated NAT/failover test, a 24-hour
no-fault soak, and a seven-day burn-in with no unexplained relay data, route
withdrawal, corruption, leak, restart, or secret-bearing log. Until then it is
experimental, regardless of individual successful transfers.

## Apply sequence

1. Commit and push this contract and donor provenance.
2. Add failing deterministic tests for rendezvous ownership, probe security,
   state convergence, persistent TUN behavior, and zero-relay bulk counters.
3. Implement the control messages and state machine without changing the
   deployed Phase-1 services.
4. Implement same-socket discovery, authenticated punching, and direct QUIC in
   isolated namespaces. Keep adjacent/random port search disabled initially.
5. Add warm fallback and migration tests, then run unit, fuzz-seed, race, vet,
   build, NAT-matrix, security, impairment, resource, and recovery gates.
6. Wait for the currently running Phase-1 qualification jobs to finish. Install
   the direct candidate under versioned paths and activate it only after a
   pre-state snapshot and rollback validation.
7. Run the no-relay proof, real distinct-NAT test, soaks, and burn-in. Publish
   only sanitized evidence and immutable source/release hashes.

## Failure and rollback

- Any security failure, bulk relay-counter increase in `DIRECT`, route flap,
  data corruption, or failed long-lived TCP migration blocks deployment.
- On candidate health failure, atomically restore the last verified Phase-1
  edge and relay binaries/configurations and rerun its smoke test. Do not delete
  candidate evidence needed for diagnosis.
- The user fork is reference provenance only. Uninstalling the donor from this
  project requires no host action; removing its documentation reference is
  sufficient. Deleting the GitHub fork is destructive and is not part of
  rollback.
