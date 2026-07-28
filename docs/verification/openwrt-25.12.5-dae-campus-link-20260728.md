# Sanitized verification record — 2026-07-28

## Cloud and build

- Three DigitalOcean Basic Droplets use `s-4vcpu-8gb-intel` (4 vCPU, 8 GiB,
  160 GiB) for a combined live rate of USD 0.24999/hour and combined monthly
  caps of USD 168 while all three remain running.
- The authorized old 1 vCPU, volume-free Droplet was retired by exact ID.
- The primary E8450 build completed successfully from OpenWrt commit
  `f0a60eee2fe051741c643ea6118718aae1ef17fb` for only
  `linksys_e8450-ubi`, Linux 6.12.94, dae 2.0.0-r1, and Go 1.26.4.
- The x86-64 build completed from the same OpenWrt commit and user-space pins.
  Its architecture-difference manifest explicitly excludes E8450 hardware
  validation.
- A clean independent E8450 reproduction remains bounded to Ninja `-j2` after
  the first attempt proved six concurrent LLVM C++ compilers can exhaust 8 GiB.

## Router lab

- Two OpenWrt x86-64 QEMU guests boot with KVM and survive host reboot.
- LuCI returns success through the loopback-only host forward and documented
  SSH tunnel; independent public probes cannot reach it.
- The deterministic offline smoke allows ICMP and TCP/8080 and blocks
  TCP/12345. Reset removes the four exact persistent taps before recreation.

## External campus-link relay

- `gz` runs the relay as the unprivileged `campus-link` systemd account with
  only `CAP_NET_BIND_SERVICE`; TCP/443 and UDP/443 are owned by that process.
- Both TLS 1.3 control sessions authenticated, both token/nonce UDP challenges
  bound, and both raw QUIC DATAGRAM edges reached `quic=active`.
- Routed ICMP and TCP/8080 crossed OpenWrt A, the site-A TUN, the blind relay,
  the site-B TUN, and OpenWrt B. TCP/12345 remained blocked by router B.
- A bounded `gz` capture contained UDP/443 packets but not the exact inner LAN
  IPv4 source/destination header. The pcap was deleted immediately.
- `/etc/campus-link` on `gz` contained exactly the relay control certificate,
  relay control key, public control CA, and relay configuration. It contained
  no edge data key, data certificate, or data CA.
- Stopping the relay withdrew both advanced routes after the QUIC idle timeout
  while SSH remained reachable. Restart restored both routes and the full smoke.
- The one Aliyun ingress rule admits UDP/443 only from the current edge host's
  public `/32`; its exact IDs and rollback parameters remain ignored private
  state rather than Git.

## Publication

- GitHub prerelease tag: `openwrt-25.12.5-dae2-lab-20260728`.
- Four remote asset sizes and GitHub-reported SHA-256 digests match the local
  verified release set.
- The physical archive is 67,506,947 bytes; the QEMU lab archive is
  257,804,698 bytes. Release notes contain experimental, UBI-layout, dae-disabled,
  and x86-versus-E8450 warnings.
