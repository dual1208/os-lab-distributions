# Two-router OpenWrt learning labs

This lab turns the architecture in `2routers.md` into something you can break,
observe, and reset. Two real OpenWrt x86-64 guests run under QEMU/KVM. Each has
its own LAN, and a deliberately simple Linux namespace forwards packets between
their transit links.

This document starts with the deterministic offline plaintext-relay lessons. The
advanced companion in `docs/CAMPUS-LINK-LAB.md` replaces only that relay with
two isolated edges, authenticated control, and end-to-end QUIC/TLS through
`gz`. Neither mode emulates the Linksys E8450's MediaTek hardware.

```text
endpoint A          router A          blind relay          router B          endpoint B
10.81.0.10  ──  10.81.0.1   172.31.1.1 ── 172.31.1.2  172.31.2.2 ── 172.31.2.1   10.82.0.1 ── 10.82.0.10
   oslab-a            OpenWrt A           oslab-relay          OpenWrt B            oslab-b
```

## Open LuCI on your Windows machine

From this repository in PowerShell:

```powershell
.\scripts\Start-OpenWrtLabTunnel.ps1
.\scripts\Copy-OpenWrtLabPassword.ps1
```

Open `https://127.0.0.1:8443/`, accept the lab's self-signed certificate, log in
as `root`, and paste the password from the clipboard. The SSH forward and QEMU
host forward both bind to loopback; LuCI is not on the public Internet.

When finished:

```powershell
.\scripts\Stop-OpenWrtLabTunnel.ps1
```

## The packet's story

When endpoint A contacts endpoint B, six layers make a decision:

1. Endpoint A's route sends the packet to `10.81.0.1`.
2. Router A looks up `10.82.0.0/24` and selects its transit interface.
3. Router A's stateful firewall permits LAN-originated transit traffic.
4. The relay routes the still-encrypted-in-the-future, plain-in-this-lab packet
   between two isolated transit networks.
5. Router B's firewall decides whether transit traffic may enter LAN B.
6. Endpoint B receives the original source address; there is no inter-site NAT.

That separation is the central router lesson: a route answers *where next*;
a firewall answers *whether*; NAT rewrites identity; a tunnel protects or
encapsulates the packet but does not replace the first three decisions.

SSH to the lab host using the private address stored in `.state` through the
normal provisioning workflow, then run all following commands as root.

## Lab 1: routes are decisions, not permissions

Observe endpoint A's next hop and the relay's two remote-LAN routes:

```bash
ip netns exec oslab-a ip route get 10.82.0.10
ip -n oslab-relay route
```

Expected shape: endpoint A selects `via 10.81.0.1 dev ep-a`; the relay has one
route via each OpenWrt transit address.

Prove the complete allowed path:

```bash
ip netns exec oslab-a ping -c 3 10.82.0.10
```

Now remove only the relay's route to LAN B and observe that routing—not DNS or
the endpoint service—is the failure:

```bash
ip -n oslab-relay route del 10.82.0.0/24
ip netns exec oslab-a ping -c 2 -W 1 10.82.0.10 || true
ip -n oslab-relay route add 10.82.0.0/24 via 172.31.2.1
```

## Lab 2: a firewall is stateful policy

The automated smoke test runs real listeners on endpoint B. TCP/8080 is
allowed; TCP/12345 is blocked even though both destinations have a listening
process.

```bash
/usr/local/libexec/openwrt-lab-smoke
cat /run/openwrt-lab/smoke.status
```

Expected result:

```text
STATUS=pass
ALLOWED=icmp,tcp/8080
BLOCKED=tcp/12345
```

Open router B's serial console to inspect the generated nftables policy:

```bash
socat -,raw,echo=0 UNIX-CONNECT:/run/openwrt-lab/router-b.console
nft list ruleset
```

Press `Ctrl-]` to leave socat. In LuCI, compare **Network → Firewall** with the
ruleset. LuCI edits UCI intent; `fw4` compiles it into nftables kernel rules.

## Lab 3: inter-site routing should preserve identity

Capture packets on relay B while endpoint A pings endpoint B:

```bash
ip netns exec oslab-relay tcpdump -ni relay-b -c 4 icmp &
ip netns exec oslab-a ping -c 2 10.82.0.10
```

The source remains `10.81.0.10`. That matters for logs and service policy. WAN
masquerading is useful for Internet access, but applying NAT between trusted
sites would hide which endpoint originated a flow.

## Lab 4: MTU is a path contract

Lower endpoint A's MTU and compare a legal ping with an oversized
don't-fragment probe:

```bash
ip -n oslab-a link set ep-a mtu 1200
ip netns exec oslab-a ping -c 2 -s 1100 -M do 10.82.0.10
ip netns exec oslab-a ping -c 2 -s 1400 -M do 10.82.0.10 || true
ip -n oslab-a link set ep-a mtu 1500
```

The second probe should fail locally or report that the message is too long.
Tunnels add headers, so their effective packet budget is smaller. Campus-link's
current authenticated QUIC DATAGRAM profile fixes the inner route at 1200;
forwarded TCP is MSS-clamped and DF-clear IPv4 fragments are individually
validated across the tunnel.

## Lab 5: distinguish supervisor, control, and data planes

Observe the host supervisor and the data path:

```bash
systemctl status openwrt-lab.service --no-pager
ip netns exec oslab-a ping -c 1 10.82.0.10
ip link set tap-a-transit down
ip netns exec oslab-a ping -c 2 -W 1 10.82.0.10 || true
ip link set tap-a-transit up
```

Systemd remains healthy while the data plane is broken. A production control
plane must therefore report path health rather than merely “the daemon is
running.” In this offline mode the control plane remains an explicit stub. The advanced
companion reports mTLS presence, authenticated UDP binding, QUIC state, and
packet counters separately so you can compare supervisor health with path health.

## DNS observation

From router A's serial console:

```sh
ubus call network.interface.wan status
nslookup openwrt.org
logread -e dnsmasq
```

This shows the local stub/forwarder relationship: clients ask dnsmasq; dnsmasq
uses upstream resolvers learned on WAN. Inter-site `home.arpa` conditional
forwarding is intentionally left for a later lab because it needs named
authoritative zones, not a misleading `/etc/hosts` trick.

## Reset to the known image

This deletes only the two exact qcow2 overlays, recreates them from the verified
base image, boots both routers, reapplies the generated password, and reruns the
smoke test:

```bash
/usr/local/libexec/openwrt-lab-reset
```

The base image, build artifacts, repository, cloud host, and unrelated droplet
are untouched.
