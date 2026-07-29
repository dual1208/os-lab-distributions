# campus-link production-readiness contract

## Status

This contract governs the work after the verified Phase-1 lab. Phase 1 is a
sound encrypted prototype, not a production release. A production claim is
forbidden until every mandatory gate below has current evidence.

## Scope

Provide reliable, fail-closed IPv4 unicast communication between authorized
processes in `10.81.0.0/24` and `10.82.0.0/24` through two routing boundaries.
The canonical qualification pair is:

- A11: `10.81.0.11`;
- B22: `10.82.0.22`.

Addresses and ports remain configurable in the test harness. TCP, ICMP, and
ordinary UDP must traverse without tunnel corruption. TCP and other reliable
inner protocols must recover loss themselves; campus-link must not claim that
QUIC DATAGRAM makes application UDP lossless.

## Non-goals for this gate

- IPv6, multicast, broadcast extension, overlapping prefixes, full-tunnel
  Internet routing, and dynamic route advertisement.
- Transparent preservation of a flow through an endpoint reboot.
- HTTP/3 or CONNECT-IP branding until RFC 9484 framing and negotiation are
  implemented and interoperability-tested. Raw QUIC DATAGRAM remains accurately
  labelled `campus-link/1`.

## Security invariants

- TLS 1.3 is the minimum for both planes. Control and data trust roots remain
  distinct; no data private key or data CA signing key reaches a relay.
- Both data peers verify an explicit expected identity. Possession of another
  certificate from the same CA is insufficient.
- Control registration is bounded in size and time. The newest authenticated
  session for a site exclusively owns that leg; an older handler disconnecting
  must never clear a replacement session.
- UDP binding tokens are random, scoped to one control session, invalidated on
  replacement/disconnect, and never logged or stored in status.
- Every UDP binding flight (request, challenge, response, and READY) is
  HMAC-authenticated and carries the site, non-zero monotonic sequence, request
  nonce, and server challenge. Replies are idempotent for one transaction.
  A response is applied only from the tuple that received its challenge. During
  rebinding, the last proven tuple remains active until the pending tuple proves
  return routability; the switch is then atomic and the pending tuple can never
  forward early. Lost READY packets are recoverable by replaying the matching
  authenticated request or response.
- The relay forwards only packets from the two currently challenged tuples,
  applies an explicit maximum outer datagram size, and never amplifies payloads.
- The edge rejects malformed IPv4, invalid header checksums, expired TTL, wrong
  prefixes, and packets larger than the configured inner MTU. Rejected packets
  never enter QUIC or TUN.
- Routes exist only while the authenticated data path is usable. Loss of
  control authority or stale QUIC must fail closed by removing the TUN device
  and its routes.
- Logs, status, metrics, captures, tests, and Git never expose keys, bind tokens,
  public addresses, provider IDs, LAN packet bodies, or application payloads.

## Reliability and operations invariants

- Edge and relay state machines distinguish control, binding, QUIC, TUN, route,
  and application probe health. A process being alive is not path health.
- Timeouts, retry intervals, exponential backoff, and jitter are bounded and
  configurable. A reconnect storm cannot spin CPU or flood the relay.
- The relay admits at most 32 concurrent pre-authentication control handshakes.
  TLS handshake plus registration has a 10-second deadline, accept failures use
  bounded backoff, and excess sockets are closed before a goroutine is created.
  Heartbeat sequences are strictly increasing and heartbeats arriving faster
  than once per second close only that control session.
- A malformed optional rendezvous plan is quarantined and counted; it never
  cancels an otherwise healthy authenticated relay path. A failed UDP send is
  counted as a packet drop and cannot terminate the relay process.
- Packet ingestion and delivery use bounded memory. Congestion or a slow TUN
  increments explicit drop counters instead of creating an unbounded queue.
- A relay or edge restart, WAN address change, stale control connection, and NAT
  tuple replacement converge automatically without operator route repair.
- Certificates can be staged with overlapping validity and activated by an
  atomic configuration/service restart. The status surface reports days until
  peer/local expiry without printing certificate identifiers.
- systemd hardening, resource limits, restart limits, health checks, and exact
  rollback remain version-controlled and replay-safe.

## Measurable service objectives

- Steady state: 10,000 ordered A11↔B22 request/response records complete with
  exact sequence and payload hashes; 100 simultaneous TCP flows complete.
- Bulk: a 1 GiB A11→B22 transfer and reverse transfer match SHA-256.
- Impairment: with 1% random loss, 100 ms delay, 20 ms jitter, and 0.1% reorder,
  reliable application tests complete without corruption or manual repair.
- Recovery: killing either edge or restarting the active relay restores route
  and A11↔B22 probes within 20 seconds at p95 and 30 seconds maximum across 30
  measured trials. SSH management remains reachable throughout.
- Rebinding: changing each edge WAN tuple restores an authenticated binding and
  application probe within 30 seconds without changing credentials.
- Isolation: wrong-prefix, bad-checksum, TTL-expired, oversized, malformed,
  unauthenticated binding, replayed challenge, stale-session, and foreign-data
  certificate cases all fail closed.
- Resources: steady-state RSS stays below 64 MiB for the relay and 96 MiB per
  edge; file descriptors and goroutines return to baseline after 100 reconnects.
- Soak: a one-hour accelerated fault test passes before candidate deployment;
  a 24-hour no-fault soak and seven-day burn-in with no unexplained restart,
  corruption, route leak, or secret-bearing log are required before the word
  “production-ready” appears in release notes.

### Soak health semantics

- Each direction is probed at least every ten seconds. One transport timeout is
  recorded as a transient miss, then retried at one-second intervals within the
  same bounded outage window. Recovery within 30 seconds is recorded with its
  measured duration; failure to recover by 30 seconds fails the gate. This
  implements the recovery objective instead of treating one scheduler or
  packet-delay outlier as an unexplained terminal failure.
- Digest, sequence, framing, or policy corruption fails immediately and is
  never retried as availability noise. A dead probe server, missing route,
  inactive edge, or unknown probe exit also fails immediately.
- The bounded result records successful application probes, total attempts,
  transient misses, recovered outages, and maximum outage duration. A failed
  run writes a separate sanitized failure marker with direction and failure
  class; only a completed-duration pass writes the pass marker.
- A supervising runtime limit, when used, must exceed the requested soak
  duration plus startup and shutdown margin. Service state alone is not gate
  evidence; the exact pass marker is mandatory.

## Required tests

- Unit/table tests for state ownership, backoff, packet validation, checksums,
  size limits, identity verification, counters, and configuration validation.
- Native Go fuzz targets for binding parsers, control framing, and IPv4 packet
  validation, with bounded CI fuzz time and retained regression corpus.
- Race-enabled tests and repeated tests (`-race`, `-count`) on amd64.
- Linux network-namespace integration tests with real TUN/QUIC when privileges
  permit, plus deterministic in-memory tests in unprivileged CI.
- A11/B22 application harnesses for request/response sequence integrity, bulk
  hashing, long-lived idle connections, reconnect, half-close, concurrent flows,
  UDP best-effort measurement, and policy denial.
- `tc netem` matrices for loss, delay, jitter, reorder, duplication, corruption,
  MTU black holes, relay restart, edge kill, and tuple rebinding.
- Bounded relay captures proving outer traffic exists and known inner headers or
  canary payloads do not appear.

## Apply sequence

1. Commit and push this contract before implementation.
2. Add deterministic tests that fail against Phase 1 for each defect being fixed.
3. Implement the smallest state-machine/security change and run unit, fuzz-seed,
   race, static-analysis, and build gates with pinned Go 1.26.4.
4. Deploy to the lab as a versioned candidate while retaining the last working
   binaries and configs for atomic rollback.
5. Run the impairment, recovery, rebinding, resource, capture, and soak gates.
6. Update sanitized evidence with distributions, not only best-case timings.

## Failure and rollback

- Any failed security invariant blocks deployment. Any failed SLO keeps the
  candidate labelled experimental and preserves the last verified Phase-1 path.
- Candidate installers copy current binaries/configs to a private bounded backup,
  install atomically, and restart synchronously. On failed health gates they
  restore only that backup and rerun the prior smoke.
- Provider ingress remains the exact recorded Aliyun UDP/443 edge `/32` rule.
  No test widens it. Relay redundancy may add a new exact rule only under a
  separate spec and identity-convergence check.
- Stop tests immediately if SSH reachability, unrelated firewall state, disk
  headroom, or cloud identity diverges from the recorded pre-state.
