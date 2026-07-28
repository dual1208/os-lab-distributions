# campus-link external-relay lab

This is the advanced companion to `TWO-ROUTER-LABS.md`. It preserves both real
OpenWrt QEMU guests and their endpoint LANs, removes only the offline plaintext
relay namespace, and inserts two isolated `campus-link` edge namespaces. The
edges reach the `gz` relay through separate WAN veths and host NAT.

```text
10.81.0.10 -- OpenWrt A -- campus-a/cl0 == QUIC DATAGRAM/TLS 1.3 == gz:UDP/443
                                                                    blind splice
10.82.0.10 -- OpenWrt B -- campus-b/cl0 == QUIC DATAGRAM/TLS 1.3 == gz:UDP/443

             both campus-a and campus-b also use mTLS control to gz:TCP/443
```

Phase 1 uses raw QUIC DATAGRAM frames with ALPN `campus-link/1`. It is not
HTTP/3 or CONNECT-IP yet. The relay can observe outer addresses, packet sizes,
timing, and loss; it never receives a data-plane private key or data CA signing
key and cannot decrypt an accepted inner LAN packet.

## Deploy or replay the setup

Install Alibaba Cloud CLI 3.3 or newer and its STS/ECS plugins, then run from
this Windows repository. Supplying the CLI path avoids changing `PATH`:

```powershell
.\scripts\Deploy-CampusLink.ps1 -AliyunCli C:\path\to\aliyun.exe
```

The deployment correlates `gz` metadata, ECS identity, and the SSH destination;
creates or reuses only the edge-host `/32` UDP rule; reuses the generated PKI;
and accepts an existing port-443 listener only when its own relay service owns
it. Runtime addresses, IDs, certificates, and keys remain ignored.
## What is live

- site A LAN: `10.81.0.0/24`; site B LAN: `10.82.0.0/24`;
- fixed edge policy admits only those two source/destination prefixes;
- the TUN MTU is 1280 and every forwarded IPv4 packet has TTL decremented with
  its header checksum updated;
- router B still allows ICMP and TCP/8080 but blocks TCP/12345;
- LuCI remains loopback-only at `https://127.0.0.1:8443/` through the documented
  SSH local forward;
- the Aliyun UDP/443 rule is restricted to the router-lab host's private-state
  public `/32`, not the whole Internet.

## Observe the three planes

On the router-lab host, check supervisor state and sanitized edge status:

```bash
systemctl status campus-link-external.target --no-pager
systemctl status campus-link-edge-a.service campus-link-edge-b.service --no-pager
campus-linkctl -status /run/campus-link/site-a.json
campus-linkctl -status /run/campus-link/site-b.json
ip -n campus-a route get 10.82.0.10
ip -n campus-b route get 10.81.0.10
```

On `gz`, check the relay without exposing tuples or tokens:

```bash
systemctl status campus-link-relay.service --no-pager
cat /run/campus-link/status.json
journalctl -u campus-link-relay.service -n 30 --no-pager
```

`control=authenticated` proves client identity and circuit registration.
`udp=bound` proves the control-issued token and nonce challenge authenticated
the observed UDP tuple. `quic=active` proves the edge-to-edge data TLS session.
None alone proves that router policy allows a particular application flow.

## Re-run the complete test

From this Windows repository:

```powershell
.\scripts\Test-CampusLink.ps1
```

The helper runs allowed ICMP and TCP/8080, proves TCP/12345 remains blocked,
captures at most 96 outer UDP/443 packets on `gz`, scans for the exact inner
IPv4 address header in both directions, deletes the pcap, and verifies the
relay's `/etc/campus-link` file boundary. It does not print host addresses.

## Exercise A11 and B22 as real processes

The production-candidate pair is A11 at `10.81.0.11` and B22 at
`10.82.0.22`. Each OpenWrt router admits all IP protocols only for this exact
pair in the inbound inter-site direction. The broader lab policy remains
deny-by-default, with its separate TCP/8080 lesson exception.

Run the bounded bidirectional application suite on the router-lab host:

```bash
/usr/local/libexec/campus-link-qualify-a11-b22 /srv/openwrt-lab/repo smoke
```

It checks 10,000 ordered payload digests, 100 simultaneous TCP flows, bulk
SHA-256, TCP half-close behavior, and paced UDP delivery in both directions.
UDP is measured rather than described as lossless; the inner TCP tests must be
exact despite loss and reordering.

The fault and impairment gates are also executable:

```bash
/usr/local/libexec/campus-link-test-edge-recovery /srv/openwrt-lab/repo full
/usr/local/libexec/campus-link-test-netem /srv/openwrt-lab/repo
```

From Windows, the relay restart gate is:

```powershell
.\scripts\Test-CampusLinkRelayRecovery.ps1 -Mode full
```

These tests never widen cloud ingress. Netem is attached only to the two edge
WAN namespace devices and is removed by a trap.

## Learn failure versus policy

Stopping the relay demonstrates a transport failure:

```bash
# on gz
systemctl stop campus-link-relay.service

# on the router-lab host, while fail-closed recovery runs
ip -n campus-a route show 10.82.0.0/24
ip -n campus-b route show 10.81.0.0/24
```

Both outputs become empty because `cl0` disappears with the edge process. A
five-second acknowledged control heartbeat and coordinated leg invalidation
then restart both data peers. SSH to each cloud host remains independent and
reachable. Manual restart remains available:

```bash
# on gz
systemctl start campus-link-relay.service

# on the router-lab host
systemctl restart campus-link-edge-a.service campus-link-edge-b.service
/usr/local/libexec/campus-link-smoke-external
```

By contrast, TCP/12345 fails while both TUN routes and QUIC remain healthy. That
is a router-B firewall decision, not a route or tunnel failure.

## Return to the deterministic offline lab

On the router-lab host:

```bash
/usr/local/libexec/campus-link-restore-offline
```

This stops the external target, removes only its two namespaces and tagged
forward/NAT rules, restores the prior host forwarding value, and restarts the
known offline topology. It does not stop the `gz` relay or change Aliyun.

To revoke the provider rule later, first install Alibaba Cloud CLI 3.3 or newer
and its ECS plugin, then run from Windows with explicit confirmation:

```powershell
.\scripts\Revoke-CampusLinkAliyunIngress.ps1 -AliyunCli C:\path\to\aliyun.exe
```

The helper reads ignored private rule state, revokes only the exact UDP/443
`/32` rule, and verifies it is absent. Stopping the relay itself is separate:

```bash
ssh gz 'systemctl disable --now campus-link-relay.service'
```

## Limits

This lab teaches routing, policy, TUN behavior, mTLS control, UDP tuple binding,
and end-to-end QUIC encryption. It does not validate Linksys E8450 hardware,
Wi-Fi, NAND/UBI, bootloaders, multipath, or HTTP/3 CONNECT-IP semantics. The
candidate still has one relay, no TCP/441 fallback, no live certificate
rotation, and low bulk throughput on the current long-haul relay path. Those
are production blockers, not hidden caveats. Use the current candidate report
before making a production claim.

The last installed candidate is recoverable with:

```bash
# edge host
/usr/local/libexec/campus-link-rollback-edge

# gz
/usr/local/libexec/campus-link-rollback-relay
```
