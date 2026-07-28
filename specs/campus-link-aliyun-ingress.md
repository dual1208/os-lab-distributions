# campus-link Aliyun UDP ingress addendum

## Scope

Permit the already specified `campus-link` blind relay on `gz` to receive its
lab edges' UDP/443 traffic when a bounded host capture proves that Aliyun drops
those packets before they reach the instance. This addendum changes one inbound
security-group rule; it does not broaden SSH, TCP/443, other ports, or sources.

## Invariants

- Correlate the instance metadata ID and region, the `ssh gz` destination, and
  the ECS API public address before mutation. Exactly one running instance and
  exactly one attached security group must match.
- Mirror the NIC type used by the existing TCP/443 accept rule.
- Allow UDP port `443/443` only from the current edge host's public IPv4 `/32`.
  Do not use `0.0.0.0/0`, another port, or an address copied into Git.
- Keep the instance ID, security-group ID, source address, client token, and any
  returned rule identifier only in ignored `.state/` data.
- Never print or commit Aliyun account, instance, security-group, address, OAuth,
  AccessKey, STS, or request identifiers.

## Acceptance checks

- The pre-state contains one TCP/443 accept rule and no matching UDP/443 accept
  rule for the edge `/32`.
- `AuthorizeSecurityGroup` succeeds for one rule with protocol UDP, port
  `443/443`, policy accept, the mirrored NIC type, and the edge `/32` source.
- A fresh `DescribeSecurityGroupAttribute` response contains exactly one matching
  rule, while existing rule counts and unrelated rules remain otherwise intact.
- A bounded `tcpdump` on `gz` observes UDP/443 packets from restarted edges;
  both authenticated tuple challenges then bind and the end-to-end smoke passes.

## Failure behavior

- If identity, region, address, group count, or TCP rule shape is ambiguous, do
  not authorize ingress.
- If authorization fails, preserve the installed relay and the passing offline
  OpenWrt lab; do not widen the source or priority to work around the failure.
- If UDP reaches `gz` but binding still fails, stop provider changes and diagnose
  the protocol using bounded captures that are deleted immediately.

## Apply

1. Record the exact private pre-state under `.state/` and generate a unique
   client token.
2. Call ECS `AuthorizeSecurityGroup` once for UDP `443/443`, the existing
   TCP/443 rule's NIC type, policy accept, and the edge public `/32`.
3. Re-query the exact group and run packet, binding, QUIC, and policy tests.

## Rollback

Call `RevokeSecurityGroup` with the same region, group, protocol, port, NIC type,
policy, and source `/32`. Re-query until the matching rule is absent, then use a
bounded `gz` capture to verify the lab UDP packets no longer arrive. Remove only
the ignored private rule state after rollback evidence is complete.
