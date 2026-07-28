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

## Learn failure versus policy

Stopping the relay demonstrates a transport failure:

```bash
# on gz
systemctl stop campus-link-relay.service

# on the router-lab host, after the 45-second QUIC idle timeout
ip -n campus-a route show 10.82.0.0/24
ip -n campus-b route show 10.81.0.0/24
```

Both outputs become empty because `cl0` disappears with the edge process. SSH
to each cloud host remains independent and reachable. Restart with:

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
Wi-Fi, NAND/UBI, bootloaders, roaming edge addresses, NAT rebinding after an
active session, multipath, congestion tuning, or HTTP/3 CONNECT-IP semantics.
