Your instinct about FRP’s **problem class** was dead-on. Whatever the exact star count when you first used it, you noticed early that the primitive people actually needed was not “install a VPN appliance,” but:

> keep an outbound authenticated agent alive behind NAT, rendezvous through one reachable server, create data paths on demand, recover automatically, and make the whole thing operationally boring.

FRP now sits around **107–108 thousand GitHub stars**, with its latest release at v0.69.0 in May 2026. It has grown from a reverse proxy into a fairly serious connection-control framework with QUIC, peer-to-peer traversal, an SSH gateway, a TUN-based VirtualNet, configuration hot reload, metrics, and a new authenticated-encryption wire protocol. ([GitHub][1])

After excluding WireGuard, IPsec, OpenVPN, and similar named VPN protocols, I think the correct design is:

> **an FRP-inspired control plane, an end-to-end QUIC/TLS 1.3 packet plane, a blind `gz` relay, and a TLS/441 + SSH recovery plane.**

No pre-existing VPN protocol is the foundation. QUIC, HTTP/3, TLS, and SSH are used as general-purpose transports and cryptographic machinery.

---

# 1. What the named Chinese universities actually deploy

There is no single “Chinese university VPN protocol.” The four universities you named currently cover at least three quite different families.

| Institution             | Publicly documented system                                         | Broad traffic and operational model                                                                                                                                                                                                                                                                                                          |
| ----------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Tsinghua**            | aTrust PC/mobile, WebVPN, Ivanti Secure, and older SSL-VPN clients | A mixture of browser HTTPS reverse proxying and installed-client encrypted tunnels. Tsinghua’s current service pages added aTrust instructions in January 2026 but still retain several older SSL-VPN paths. ([Tsinghua Info Service][2])                                                                                                    |
| **Zhejiang University** | aTrust RVPN, clientless WebVPN, legacy EasyConnect                 | aTrust supports Web, SSH, Telnet, RDP, and FTP with an installed client and SMS secondary authentication. The old EasyConnect service ceased supporting non-Web protocols on May 19, 2025. ([Zhejiang University][3])                                                                                                                        |
| **Jilin University**    | aTrust zero-trust client plus WebVPN                               | Browser-based university identity authentication, SMS second factor, device binding, an explicit “enable tunnel access” action, retained login tickets, and a separate browser-only WebVPN. ([N/A][4])                                                                                                                                       |
| **USTC**                | Panabit iWAN from July 1, 2026                                     | University SSO, several ISP-specific ingress lines, full-route or prefix-route operation, and multi-platform clients. Panabit describes iWAN as a proprietary, IP-change-resistant UDP tunnel with an eight-byte tunnel header; its general cloud setup uses UDP 58000 by default, though USTC may remap that port. ([USTC Email System][5]) |

That gives us an important correction to the original goal:

> We cannot make one connection simultaneously resemble aTrust, Ivanti, WebVPN, and iWAN. They do not resemble one another.

What we can build is a service offering **two honest traffic personalities**:

1. A modern HTTP/3/QUIC secure-access profile.
2. An aTrust-like HTTPS-control plus TLS-tunnel profile.

An optional compact UDP profile can later borrow iWAN’s *design ideas* without pretending to implement iWAN.

---

# 2. The common institutional architecture

Although the wire protocols differ, university and corporate systems repeatedly converge on the same planes.

## Identity plane

A browser or client talks to an HTTPS portal. It performs university single sign-on, a second factor, and sometimes device enrollment or posture verification. The resulting authorization is not the tunnel itself; it grants permission to establish the tunnel.

For your fixed routers, repeated human MFA would be silly. Adapt the institutional model as:

* Human administrator authenticates once to an enrollment portal.
* The portal approves a router identity.
* The router receives a machine certificate.
* Every subsequent 24/7 connection uses mutual TLS.
* Certificates can be revoked or rotated without changing the LAN routing design.

## Control plane

One durable authenticated connection carries:

* identity and node generation;
* advertised capabilities;
* peer presence;
* route and prefix authorization;
* keepalives;
* UDP endpoint binding;
* requests to create fallback data connections;
* key and certificate rotation notifications;
* health information.

This is exactly the part FRP understands unusually well.

## Data plane

Traffic moves separately from the control messages. Institutional products commonly have:

* an efficient UDP path when available;
* a TLS-over-TCP path when UDP is unavailable;
* multiple ingress addresses or ISP-specific gateways;
* split-tunnel and full-tunnel profiles;
* a virtual network adapter and pushed routes.

## Clientless WebVPN

This is not a network tunnel. It is a reverse HTTP proxy that rewrites links, cookies, and sometimes JavaScript. It is excellent for library databases and internal websites but cannot provide arbitrary LAN-to-LAN process communication.

For your system, an ordinary HTTPS portal can coexist with the real packet tunnel. That gives active probes a legitimate web service rather than a fake dead page.

---

# 3. What aTrust is doing under the hood

Sangfor’s own support material gives surprisingly useful protocol clues.

The documented default arrangement separates:

* the client/control side on HTTPS;
* a tunnel endpoint on **TCP 441**;
* Web resources from opaque tunnel resources.

On the tunnel path, the client establishes TCP, sends a TLS ClientHello, and then uses a SOCKS5-like session protocol inside the encrypted connection. Sangfor explicitly warns that an application-layer load balancer or TLS-decryption appliance breaks this connection; it needs layer-4 forwarding. ([Sangfor Support][6])

That explains why aTrust can expose selected SSH, RDP, FTP, and application resources without necessarily routing the user’s entire machine:

```text
browser / client authentication
             │
             ▼
       HTTPS control
             │
       policy/resource list
             │
             ▼
 TCP 441 → TLS → SOCKS-like application sessions
```

For your two-home problem, a pure SOCKS design is not quite enough because arbitrary LAN devices should communicate without installing local clients. But its **separation of portal, authorization, tunnel, and published resources** is worth absorbing.

---

# 4. The recommended architecture

I’ll call the system `campus-link` merely to give the pieces names.

```text
                          public Internet

       Home A                                         Home B
┌──────────────────┐                          ┌──────────────────┐
│ 10.81.0.0/24     │                          │ 10.82.0.0/24     │
│ LAN processes    │                          │ LAN processes    │
└────────┬─────────┘                          └────────┬─────────┘
         │ routes                                      │ routes
         ▼                                             ▼
┌──────────────────┐     end-to-end TLS 1.3    ┌──────────────────┐
│ campus-link edge │═══════════════════════════│ campus-link edge │
│ TUN + policy     │       QUIC / H3           │ TUN + policy     │
└────────┬─────────┘                           └────────┬─────────┘
         │ UDP packets to gz:443                       │ UDP packets to gz:443
         └────────────────┐             ┌──────────────┘
                          ▼             ▼
                      ┌────────────────────┐
                      │ gz blind UDP relay │
                      │ no LAN plaintext   │
                      └────────────────────┘

Both edges also maintain authenticated TCP/443 control sessions to gz.
```

The critical invariant is:

> **`gz` controls reachability but is not an endpoint of the A↔B data encryption.**

It may observe packet timing, sizes, and volume. It may drop or delay traffic. It cannot decrypt, modify, or forge accepted LAN packets.

---

# 5. Primary profile: end-to-end HTTP/3 over a blind relay

This is the profile I would implement first.

## 5.1 Establishing reachability

Both routers initiate outbound connections, so neither home needs port forwarding or a public address.

Each router maintains an mTLS control connection to:

```text
gz TCP/443
```

The control connection identifies:

```text
node identity
boot generation
software version
supported transports
authorized circuit
local LAN prefix
current health
```

The relay sees two online members:

```text
circuit home-pair-1:
    leg A = site-a certificate identity
    leg B = site-b certificate identity
```

Each edge then sends a bind packet from the **same UDP socket** that will carry QUIC. `gz` performs a return-path challenge before committing the observed public IP and port. A NAT tuple cannot be replaced merely because somebody sent a spoofed registration message.

Once both legs are bound, `gz` applies one tiny rule:

```text
authenticated UDP source tuple A → forward unchanged to tuple B
authenticated UDP source tuple B → forward unchanged to tuple A
```

It does not parse HTTP, TLS, IP, or application traffic.

## 5.2 End-to-end QUIC handshake

Site A is the deterministic QUIC client; site B is the QUIC server.

A sends a QUIC Initial packet to `gz:443`. `gz` forwards it unchanged to B. B’s reply travels through the reverse mapping.

Therefore:

* the network address is `gz`;
* the cryptographic peer is B;
* B presents its certificate;
* A verifies B’s certificate and pinned identity;
* B requires and verifies A’s client certificate;
* `gz` has neither private key.

QUIC uses TLS for authentication and key establishment, and then protects QUIC packets itself with the negotiated authenticated-encryption algorithm. ([RFC Editor][7])

## 5.3 Carrying IP packets

Each router owns a TUN interface:

```text
site A:
    remote route 10.82.0.0/24 → cl0

site B:
    remote route 10.81.0.0/24 → cl0
```

Packets read from TUN are sent as QUIC DATAGRAM frames. They are:

* end-to-end encrypted;
* integrity protected;
* congestion controlled by QUIC;
* not retransmitted by the tunnel;
* independently delivered without stream head-of-line blocking.

That last property matters. If an inner TCP packet is lost, the inner TCP implementation performs recovery. The outer tunnel should not stall every unrelated packet while retransmitting it.

RFC 9221 explicitly identifies an encrypted IP packet tunnel as a use case for reliable QUIC control streams combined with unreliable QUIC datagrams. ([RFC Editor][8])

### CONNECT-IP as a donor, not a religion

RFC 9484 defines precisely this packet-over-HTTP model. It supports remote-access and site-to-site scenarios and uses HTTP Datagrams for the packet path. ([RFC Editor][9])

The MIT-licensed `quic-go/connect-ip-go` code is an excellent source donor:

* it sends and receives IP packets through HTTP/3 datagrams;
* implements route advertisement and address assignment;
* validates permitted source and destination prefixes;
* decrements IPv4 TTL or IPv6 Hop Limit;
* generates ICMP Packet Too Big when a packet cannot fit.

Its license explicitly permits copying and modification with retained notice.

I would fork this small library, not deploy it unchanged. Strip out unnecessary general proxy behavior and add:

* fixed two-site identities;
* static authorized prefixes;
* mandatory mutual TLS;
* relay-awareness;
* explicit health messages;
* route-change auditing;
* bounded datagram queues;
* OpenWrt integration.

This is not adopting a mainstream VPN. It is using HTTP/3’s packet-delivery vocabulary instead of inventing an inferior framing format.

---

# 6. Prefix authorization

Encryption answers “who possesses the session keys?” It does not by itself answer “which source addresses may this peer claim?”

Every packet from B should be accepted only when:

```text
source ∈ 10.82.0.0/24
destination ∈ 10.81.0.0/24 or local tunnel control addresses
```

And vice versa for A.

Authorization should exist at three layers:

1. The peer certificate identifies the site.
2. `campus-link` maps that identity to permitted prefixes.
3. OpenWrt’s firewall maps the tunnel interface to permitted protocols and services.

Do not place all trust in source IP alone. A compromised device inside site B can originate traffic from site B’s authorized range, so sensitive services should retain their own SSH keys, mTLS, passwords, or application authorization.

---

# 7. Secondary profile: the aTrust-like TLS/441 path

QUIC/UDP will occasionally be blocked. The fallback should broadly resemble the installed-client university VPN pattern:

```text
TCP/443    HTTPS portal and durable control
TCP/441    long-lived TLS tunnel
```

Both routers still initiate outward.

## Pairing two outbound connections

FRP’s work-connection model is ideal here:

1. A and B each have a durable control session to `gz`.
2. `gz` sends `REQUEST_DATA_CONNECTION` to both.
3. Each opens an outer mTLS connection to `gz:441`.
4. The connections present one-time pairing tickets.
5. `gz` joins the byte streams.
6. Across that joined stream, A and B perform a second, **end-to-end mTLS handshake**.
7. IP packets or logical flows travel inside the inner TLS session.

The outer TLS authenticates each leg to the relay and protects the pairing token. The inner TLS keeps the relay from seeing LAN traffic.

```text
A ─ outer TLS ─ gz ─ outer TLS ─ B
       └────── inner A↔B mutual TLS ──────┘
```

Yes, this is double encryption. It is a fallback, not the high-throughput path.

For the first implementation, carry length-delimited IP packets. Later, a flow-aware mode can terminate each captured TCP flow at the router and map it to an independent multiplexed stream, with UDP remaining message-oriented. That is closer to aTrust’s SOCKS-like model and avoids TCP-over-TCP coupling, but it requires a real userspace network stack.

---

# 8. Optional experimental profile: iWAN-inspired compact UDP

USTC’s current deployment is particularly interesting because it is conceptually closer to your topology than a road-warrior SSL VPN.

USTC’s official instructions expose:

* several ISP-specific access lines;
* full-route and prefix-route modes;
* university SSO;
* support for roaming devices;
* a replacement of older PPTP/L2TP access. ([USTC Email System][5])

Panabit’s own materials claim:

* a proprietary UDP-oriented tunnel;
* rapid reconnection;
* resilience to client IP changes;
* only eight bytes of tunnel header;
* UDP 58000 as a common default deployment port. ([Panabit BBS][10])

There is not enough public material to responsibly assert its cipher, handshake, replay protection, or exact header layout.

A clean-room experimental equivalent could use:

```text
TCP/443:
    end-to-end TLS 1.3 authentication and control

UDP/58000:
    version / flags        1 byte
    key epoch              1 byte
    circuit ID             2 bytes
    packet number          8 bytes
    encrypted IP packet
    AEAD authentication tag 16 bytes
```

Data keys would be derived from the authenticated TLS session using a TLS exporter and separate labels for A→B and B→A. TLS exporters are designed to produce independent secret key material bound to a completed TLS session. ([RFC Editor][11])

I would deliberately use a **12-byte clear header**, not chase Panabit’s advertised eight-byte figure. Four bytes are noise beside IP, UDP, and a 16-byte authentication tag; a full 64-bit packet number dramatically simplifies nonce uniqueness and replay protection.

This profile would also require:

* a sliding replay window;
* key-epoch overlap during rotation;
* authenticated path challenges;
* strict packet-size bounds;
* pacing and aggregate rate control;
* path-MTU discovery;
* congestion behavior for non-TCP traffic;
* extensive fuzzing and adversarial testing.

That is why it belongs after the QUIC design, not before it. QUIC already solves these difficult problems.

---

# 9. Why FRP is the right donor—but not the whole implementation

FRP’s success is not just marketing or a convenient CLI. Its internal model is solid.

## What should be absorbed

### Durable control identity and generations

Current FRP has a notion of a client run identity and carefully replaces stale control generations. The server marks a new generation pending, waits for the predecessor’s finalization barrier, activates only the current generation, and prevents old connections from reclaiming ownership. That is exactly what a 24/7 router system needs after reboots, half-open sessions, and delayed packets.

Your equivalent should use:

```text
node_id       stable identity
boot_id       random on every daemon start
generation    monotonic within boot
session_id    random per control connection
```

Only the newest authenticated generation may control routes or claim relay bindings.

### Control versus work connections

FRP’s control channel receives `ReqWorkConn`, opens a new authenticated connection, sends `NewWorkConn`, waits for `StartWorkConn`, and dispatches the resulting stream to the relevant proxy.

That maps almost directly to:

```text
REQUEST_TLS_FALLBACK
OPEN_RELAY_LEG
PAIR_READY
START_END_TO_END_TLS
```

### Heartbeats and bounded reconnection

FRP sends authenticated pings, tracks pongs, closes dead sessions, and uses backoff with jitter.

Copy the behavior, not necessarily the code.

### QUIC and TCP connector abstraction

FRP’s connector can maintain one QUIC connection and open logical streams, or use TCP multiplexing. It centralizes TLS settings, keepalive, proxy connection, and transport selection.

Your abstraction should instead expose:

```go
type Path interface {
    SendPacket([]byte) error
    ReceivePacket(context.Context) ([]byte, error)
    Health() PathHealth
    Close() error
}
```

Implementations:

```text
H3DatagramPath
TLS441Path
SSHRecoveryPath
DirectQUICPath        later
CompactUDPPath        experimental
```

### NAT-traversal coordination

FRP’s `xtcp` mode uses the server to exchange endpoint information, attempts direct traversal, and retains a relayed fallback because peer-to-peer traversal does not work through every NAT. Its own documentation explicitly advises falling back when direct punching fails. ([GitHub][1])

That is the correct policy:

```text
relay first
probe direct asynchronously
switch only after bidirectional validation
keep relay warm
fall back immediately on direct failure
```

### VirtualNet’s TUN and routing code

FRP’s new VirtualNet reads IPv4/IPv6 packets from TUN, routes by destination, learns source-to-connection associations, and writes received packets back to TUN. That is useful scaffolding.

## What should not be copied

### VirtualNet’s packet transport

VirtualNet currently frames each IP packet as:

```text
4-byte little-endian length
packet bytes
```

over a reliable `io.ReadWriteCloser`.

In FRP’s QUIC mode, `Connect()` opens a **QUIC stream**, not a QUIC datagram path.

That means a lost outer packet can delay unrelated later IP packets while the stream recovers. It is acceptable for a quick alpha feature, but it is not the packet plane I would choose for a routed home-to-home network.

### The full proxy taxonomy

You do not need:

* arbitrary public port publication;
* HTTP virtual hosts;
* a plugin marketplace;
* many visitors and proxies;
* dashboard administration for thousands of arbitrary services;
* a generic multi-tenant server.

Your topology is two peers and one circuit. Ruthlessly delete.

### Legacy encryption helpers

The current FRP v0.69 wire protocol is much improved: its v2 control protocol negotiates either AES-256-GCM or XChaCha20-Poly1305 and prefers AES-GCM where hardware support is detected. ([GitHub][12])

However, older FRP helper paths still contain PBKDF2-SHA1 with only 64 iterations and AES-CFB without integrated authentication.

Do not import those. In your system:

* TLS 1.3 protects control sessions.
* QUIC/TLS protects the primary data plane.
* Any custom packet mode uses an AEAD and a formally specified key schedule.
* No unauthenticated CFB, CTR, or homemade “encrypt then checksum” construction.

---

# 10. Cryptographic configuration

## Separate trust domains

Use three independent identities:

```text
site A data certificate
site B data certificate
relay-control certificates for A, B, and gz
```

Compromise of `gz`’s control certificate must not allow impersonating A to B.

## Mutual TLS 1.3

For A↔B:

* TLS 1.3 minimum and maximum.
* Both sides present certificates.
* Verify the private CA.
* Also verify the expected site identity in a SAN URI or pinned public-key hash.
* Map that identity to permitted LAN prefixes.
* Disable state-changing use of 0-RTT.

The current TLS 1.3 specification warns that 0-RTT lacks cross-connection replay guarantees and weaker forward-secrecy properties. Tunnel establishment, route changes, relay binding, and administrative operations should use 1-RTT data only. ([RFC Editor][13])

## Cipher selection

Do not manually invent a cipher-suite list.

Current Go TLS supports TLS 1.3 and includes hybrid post-quantum key exchanges by default in Go 1.26. ([Go][14])

The current OpenWrt `mt7622` target enables ARM64 AES crypto extensions and PMULL/GHASH acceleration, so AES-GCM is likely attractive on the E8450. That still needs measurement with your exact firmware and Go build.

A sensible policy is:

* allow Go/QUIC to choose AES-GCM or ChaCha20-Poly1305;
* retain the Go 1.26 hybrid key-exchange defaults initially;
* benchmark handshake latency, binary size, memory, and throughput;
* change defaults only from measured evidence.

---

# 11. Traffic resemblance: what is honest and technically durable

There is a useful boundary here.

## Architectural resemblance: yes

Your service can legitimately have:

```text
vpn.your-domain.example TCP/443
    real HTTPS portal
    enrollment/status/API
    HTTP/2 and HTTP/3

vpn.your-domain.example UDP/443
    long-lived HTTP/3 tunnel

vpn.your-domain.example TCP/441
    long-lived TLS fallback tunnel

gz TCP/22
    SSH administration and recovery

optional UDP/58000
    experimental compact tunnel
```

That produces the same broad classes as institutional secure access:

* ordinary HTTPS portal traffic;
* long-lived encrypted client traffic;
* separate control and data planes;
* UDP-first and TCP-fallback behavior;
* split/full route profiles;
* machine or device authorization;
* periodic keepalive and rapid recovery.

## Exact impersonation: no—and it would be bad engineering anyway

I would not clone:

* `vpn.tsinghua.edu.cn` or another university’s SNI;
* its certificate chain;
* proprietary HTTP paths;
* exact TLS extension ordering or JA3/JA4 fingerprint;
* Sangfor or iWAN packet bytes;
* university branding or authentication pages.

Apart from impersonation, exact fingerprint cloning is fragile. QUIC Initial packet keys are derived from public connection information, and the Initial carries the TLS handshake; therefore a passive observer can recover substantial ClientHello metadata even though later traffic is strongly protected. ([RFC Editor][7])

Research on OpenVPN fingerprinting also shows that traffic classifiers combine passive packet properties with active probing; superficial packet-shape obfuscation often fails. ([arXiv][15])

The robust answer is to run a **real HTTPS/H3 service with your own identity**, not paint fake university whiskers on a custom protocol.

---

# 12. SSH’s proper role

SSH is excellent here, but not as the principal packet plane.

The SSH connection protocol already supplies multiplexed authenticated channels and TCP forwarding over one encrypted connection. ([RFC Editor][16])

Use it for:

* emergency router access through `gz`;
* configuration repair;
* status and log collection;
* forwarding the control socket when HTTP/3 and TLS/441 are broken;
* bootstrapping a replacement certificate;
* a last-resort TCP data splice.

FRP’s `tiny-frpc` project independently confirms that standard SSH reverse forwarding can provide a very small embedded reverse-proxy client, though its maintainers currently label it preview-quality.

On `gz`, dedicate a restricted account and constrain forwarding with `PermitListen`, `PermitOpen`, no PTY, no agent forwarding, no X11, and no shell command beyond the required dispatcher. OpenSSH provides server-side controls for exactly these forwarding restrictions. ([OpenBSD Manual Pages][17])

Remember: if A and B each create separate SSH sessions terminating at `gz`, `gz` can see the forwarded bytes. Any sensitive fallback data must still have an inner A↔B TLS layer.

---

# 13. OpenWrt implementation model

## Routing

Use two non-overlapping subnets, for example:

```text
site A LAN: 10.81.0.0/24
site B LAN: 10.82.0.0/24
```

No inter-site masquerading. Preserve original source addresses.

Install:

```text
A: 10.82.0.0/24 via cl0
B: 10.81.0.0/24 via cl0
```

When the tunnel is unavailable, the route should fail closed into an unreachable/blackhole state rather than leak packets through WAN.

## Firewall

Place `cl0` in a dedicated OpenWrt firewall zone.

Default deny, then explicitly permit, for example:

```text
A → B:
    TCP 22 to administration hosts
    TCP 443 to selected services
    PostgreSQL only between named hosts
    ICMP diagnostics

B → A:
    corresponding explicit policy
```

The two homes need not become one undifferentiated trusted blob.

## DNS

Use distinct `home.arpa` zones:

```text
nas.a.home.arpa
build.b.home.arpa
```

Conditionally forward the opposite zone across the tunnel.

## MTU

Begin with TUN MTU **1280**. This is conservative, preserves IPv6’s minimum link MTU, and matches the defensive behavior in `connect-ip-go`. Raise it only after DPLPMTUD and real path tests. `quic-go` implements QUIC DATAGRAM and datagram packetization-layer path-MTU discovery.

## Supervision

Package the daemon as an `.ipk` against the exact OpenWrt SDK release installed on the routers.

Use `procd` for:

* automatic restart;
* dependency on WAN availability;
* stdout/stderr to syslog;
* configuration reload;
* resource limits;
* optional `ujail`.

Keep volatile state in RAM:

```text
NAT tuples
RTT estimates
packet counters
QUIC state
replay windows
health history
```

Do not continuously write counters or endpoint changes to UBI flash.

---

# 14. Proposed source tree

```text
campus-link/
├── cmd/
│   ├── campus-link-edge/
│   ├── campus-link-relay/
│   └── campus-linkctl/
├── internal/
│   ├── control/
│   │   ├── session.go
│   │   ├── generation.go
│   │   ├── messages.go
│   │   └── heartbeat.go
│   ├── relay/
│   │   ├── circuit.go
│   │   ├── udp_binding.go
│   │   ├── challenge.go
│   │   └── splice.go
│   ├── h3ip/
│   │   ├── connection.go
│   │   ├── datagram.go
│   │   ├── routes.go
│   │   └── icmp.go
│   ├── tls441/
│   │   ├── pair.go
│   │   ├── inner_tls.go
│   │   └── framing.go
│   ├── tun/
│   │   ├── linux.go
│   │   └── packet.go
│   ├── policy/
│   │   ├── identity.go
│   │   ├── prefix.go
│   │   └── firewall.go
│   ├── path/
│   │   ├── selector.go
│   │   └── health.go
│   ├── sshrecovery/
│   ├── metrics/
│   └── config/
├── openwrt/
│   ├── Makefile
│   └── files/
│       ├── campus-link.init
│       ├── campus-link.config
│       └── campus-link.hotplug
├── tests/
│   ├── netns/
│   ├── fuzz/
│   └── integration/
├── THIRD_PARTY.md
├── go.mod
└── LICENSE
```

Suggested dependency strategy:

* Depend on `quic-go`; do not fork it initially.
* Fork the small `connect-ip-go` package.
* Reimplement FRP’s narrow state-machine ideas or copy isolated Apache-2.0 portions with clear attribution.
* Do not import the entire FRP server/client stack.
* Do not copy proprietary Sangfor or Panabit code.
* Record every copied upstream path, commit, license, and modification in `THIRD_PARTY.md`.

---

# 15. State machine

The system should never report merely “connected.”

```text
control:
    down
    connecting
    authenticated
    peer-present

udp relay:
    unbound
    challenging
    bound

end-to-end QUIC:
    idle
    handshaking
    active
    stale

TLS/441:
    idle
    requesting-work-connections
    pairing
    inner-handshake
    active

selected path:
    h3-relay
    h3-direct
    tls441
    ssh-recovery
    none
```

Convergence should be deterministic:

```text
1. Start control connection.
2. Authenticate certificate and generation.
3. Register LAN prefix and capabilities.
4. Bind UDP source tuple.
5. Wait until both circuit legs are ready.
6. A initiates end-to-end QUIC.
7. Establish HTTP/3 packet context.
8. Enable routes.
9. On QUIC failure, start TLS/441.
10. Keep retrying QUIC with jitter while fallback remains active.
```

A replacement process must not race an old process. FRP’s generation and handoff-barrier design is particularly worth reproducing here.

---

# 16. Implementation order

## Phase 1: the smallest sound system

Build only:

* fixed A and B identities;
* fixed LAN prefixes;
* TCP/443 mTLS control;
* authenticated UDP binding;
* blind `gz` relay;
* end-to-end QUIC/TLS;
* raw IP over QUIC DATAGRAM;
* TUN and static routes;
* status JSON;
* OpenWrt `procd` service.

No NAT punching, Web UI, compact UDP, dynamic users, or application publishing.

## Phase 2: institutional reliability shell

Add:

* certificate rotation with overlapping validity;
* generation-safe reconnects;
* real HTTPS status/enrollment portal;
* TLS/441 fallback;
* split/full route profiles;
* Prometheus metrics and qlog;
* second relay configuration, even if only one exists initially.

## Phase 3: direct path optimization

Borrow FRP’s rendezvous idea:

* exchange endpoint candidates through control;
* probe direct UDP;
* establish a second end-to-end QUIC connection;
* switch only after bidirectional validation;
* leave the relay connection warm.

Do not make successful NAT punching a condition of service availability.

## Phase 4: compact UDP experiment

Only after profiling proves that QUIC userspace processing is the bottleneck:

* TLS exporter-derived AEAD keys;
* explicit packet-number/replay model;
* pacing;
* DPLPMTUD;
* rekey epochs;
* formal wire specification;
* parser fuzzing;
* adversarial review.

---

# 17. The final design choice

For your specific two-router, one-relay topology, I would build:

```text
Primary:
    TCP/443 real HTTPS control portal
    UDP/443 end-to-end HTTP/3 packet tunnel
    gz blindly forwards QUIC datagrams

Fallback:
    TCP/441 paired relay connections
    inner end-to-end TLS 1.3
    initially raw IP framing

Recovery:
    restricted OpenSSH reverse-forwarding accounts

Later:
    direct QUIC path
    second relay
    experimental compact UDP/58000 profile
```

This absorbs the best ideas from all the references:

* **FRP:** outbound agents, durable control, generations, requested work connections, optional direct traversal.
* **aTrust:** separate browser authorization and tunnel planes; a recognizable 443/441 institutional deployment shape.
* **USTC/Panabit:** route profiles, multiple access paths, and rapid recovery from source-IP changes.
* **QUIC/HTTP/3:** end-to-end authenticated encryption, datagrams, congestion control, streams for reliable control, and path-aware transport.
* **SSH:** the wonderfully boring break-glass mechanism.

The next engineering artifact should be a narrow protocol specification covering identities, control messages, relay binding, route authorization, state transitions, failure semantics, and the exact H3 packet context. That spec—not a giant borrowed binary—becomes the source of truth for the implementation.

[1]: https://github.com/fatedier/frp "https://github.com/fatedier/frp"
[2]: https://its.tsinghua.edu.cn/1wzcycejdh_content.jsp?urltype=news.NewsContentUrl&wbnewsid=4535&wbtreeid=1771 "https://its.tsinghua.edu.cn/1wzcycejdh_content.jsp?urltype=news.NewsContentUrl&wbnewsid=4535&wbtreeid=1771"
[3]: https://coc.intl.zju.edu.cn/en/node/879088 "https://coc.intl.zju.edu.cn/en/node/879088"
[4]: https://nic.jlu.edu.cn/info/1113/2209.htm "https://nic.jlu.edu.cn/info/1113/2209.htm"
[5]: https://email.ustc.edu.cn/notice/iwan/ "https://email.ustc.edu.cn/notice/iwan/"
[6]: https://support.sangfor.com.cn/cases/list?category_id=3432&product_id=19 "https://support.sangfor.com.cn/cases/list?category_id=3432&product_id=19"
[7]: https://www.rfc-editor.org/rfc/rfc9001.html "https://www.rfc-editor.org/rfc/rfc9001.html"
[8]: https://www.rfc-editor.org/rfc/rfc9221.html "https://www.rfc-editor.org/rfc/rfc9221.html"
[9]: https://www.rfc-editor.org/info/rfc9484/ "https://www.rfc-editor.org/info/rfc9484/"
[10]: https://bbs.panabit.com/thread-23686-1-1.html "https://bbs.panabit.com/thread-23686-1-1.html"
[11]: https://www.rfc-editor.org/info/rfc8446/?utm_source=chatgpt.com "RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3 | RFC Editor"
[12]: https://github.com/fatedier/frp/releases "https://github.com/fatedier/frp/releases"
[13]: https://www.rfc-editor.org/info/rfc9846/?utm_source=chatgpt.com "RFC 9846: The Transport Layer Security (TLS) Protocol Version 1.3 | RFC Editor"
[14]: https://go.dev/doc/go1.26 "https://go.dev/doc/go1.26"
[15]: https://arxiv.org/abs/2403.03998 "https://arxiv.org/abs/2403.03998"
[16]: https://www.rfc-editor.org/info/rfc4254/ "https://www.rfc-editor.org/info/rfc4254/"
[17]: https://man.openbsd.org/OpenBSD-7.1/sshd_config.5 "https://man.openbsd.org/OpenBSD-7.1/sshd_config.5"

