# campus-link Phase-1 lab

This directory implements the narrow two-site structure specified in section 4
of `../2routers.md`:

- `campus-link-relay` accepts mutually authenticated TCP/443 control sessions,
  challenges UDP bindings, and blindly splices UDP/443 packets between the two
  authenticated tuples;
- `campus-link-edge` creates a TUN interface, applies fixed prefix policy, and
  carries authorized IPv4 packets in end-to-end TLS 1.3 QUIC DATAGRAM frames;
- `campus-linkctl` prints the bounded status JSON emitted by either component.

The relay owns the control-plane server key but receives no data-plane private
key. It can observe timing and sizes and can drop traffic, but accepted QUIC
payloads are authenticated and encrypted between `site-a` and `site-b`.

This Phase-1 implementation uses raw QUIC DATAGRAM frames with ALPN
`campus-link/1`. It is deliberately **not** labelled HTTP/3 or CONNECT-IP. The
pinned `quic-go/connect-ip-go` source is an inspected donor for a later H3
packet context, TTL/MTU behavior, and route advertisement.

Generated certificates, bind tokens, runtime configs, host addresses, and
status files must stay under `/etc/campus-link`, `/run/campus-link`, or ignored
`.state/` paths. None belong in Git.
