# campus-link production-candidate lab

This directory implements the narrow two-site structure specified in section 4
of `../2routers.md`:

- `campus-link-relay` accepts mutually authenticated TCP/443 control sessions,
  challenges UDP bindings, and blindly splices UDP/443 packets between the two
  authenticated tuples;
- `campus-link-edge` creates a TUN interface, applies fixed prefix policy, and
  carries authorized IPv4 packets in end-to-end TLS 1.3 QUIC DATAGRAM frames.
  It keeps a warm broker/liveness association while establishing
  exporter-bound, mutually authenticated direct QUIC between the two edges.
  The production profile never carries an inner TUN packet through that
  broker association;
- `campus-linkctl` prints the bounded status JSON emitted by either component.

The relay owns the control-plane server key but receives no data-plane private
key. It can observe timing and sizes and can drop traffic, but accepted QUIC
payloads are authenticated and encrypted between `site-a` and `site-b`.

The current candidate uses raw QUIC DATAGRAM frames with ALPN
`campus-link/1`. It is deliberately **not** labelled HTTP/3 or CONNECT-IP. The
pinned `quic-go/connect-ip-go` source is an inspected donor for a later H3
packet context, TTL/MTU behavior, and route advertisement.

Generated certificates, bind tokens, runtime configs, host addresses, and
status files must stay under `/etc/campus-link`, `/run/campus-link`, or ignored
`.state/` paths. None belong in Git.

## Qualification chain

`campus-link-qualification-chain.service` is the only supported entry point
for release evidence. Its coordinator holds the edge deployment lock in shared
mode, creates one root-only run manifest, clears only the bounded gate markers,
and starts these tracked one-shot services in order:

1. `campus-link-full-qualification.service`;
2. `campus-link-accelerated-fault.service`;
3. `campus-link-fault-in-stream.service`;
4. `campus-link-nat-rebinding.service`;
5. `campus-link-24h-soak.service`;
6. `campus-link-7d-burn-in.service`.

Every marker is bound to the coordinator's random run ID, boot, deployment
attestation, complete installed-candidate fingerprint, and the SHA-256 of its
prerequisite marker. Durations use kernel monotonic time. A later service
rejects a cached, reordered, cross-run, cross-candidate, or modified marker.
The full gate also runs sequence-unique simultaneous 1 GiB full-duplex streams
and a bounded 4 GiB-per-direction full-duplex stream with progress and
throughput deadlines. It now requires both edges to remain on the authenticated
direct path, proves full-width delivery-progress acknowledgements advance,
proves edge relay-data counters and watchdog/fallback counters do not advance,
and bounds the blind relay's raw keepalive traffic independently of transfer
size. Passing this chain does not waive the remaining NAT-matrix,
relay-redundancy, TCP/441 fallback, snapshot-anchor, rotation, or key-isolation
release gates in `PROTOCOL.md`; the implementation remains a production
candidate until every normative gate passes.

The dedicated fault-in-stream gate keeps one sequence-unique, checksum-
acknowledged TCP connection active for at least 2 GiB in each direction under
the fixed loss/reorder/latency profile. During that same socket it uses a
host-key-pinned, Ed25519-authenticated forced command to stop and restart the
real relay process, separately removes broker control and the direct UDP path,
and proves both receive directions continue or recover as appropriate. The
restart key has no password, shell, PTY, forwarding, or access outside the
bounded actuator. It is not sufficient by itself: an independent root-only
Ed25519 signing key creates a candidate-, manifest-, deployment-, run-, and
expiry-bound one-time permit whose public verifier is pinned on the relay. The
actuator consumes that exact permit before service mutation, so a copied fault
SSH key cannot invent an authorized run. The gate then proves both receive directions resume within
25 seconds after a 15-second idle-expiring direct withdrawal and requires at
least 2.000 Mbit/s measured in each direction. It pins both edge process
invocations and their 96 MiB limits, requires larger direct-instance
generations, and rejects any relay payload byte or inexact selected identity.

The NAT-rebinding gate then retains one authenticated, sequence-contiguous
full-duplex TCP stream while it forces and restores the exact UDP mapping for
each edge, one WAN at a time. It uses only socket-scoped conntrack deletion and
exact temporary NAT rules, proves the peer WAN mapping stays untouched, and
requires the complete NAT ruleset to match its pre-gate bytes after each site.
Its sanitized marker is hash-chained from `fault-in-stream.result`; the 24-hour
soak orders after this gate and hashes `nat-rebinding.result`, so pre-integration
markers cannot satisfy the current chain.
