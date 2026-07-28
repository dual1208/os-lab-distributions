# Third-party provenance

## quic-go

- Source: `https://github.com/quic-go/quic-go`
- Version: `v0.61.0`
- Resolved commit: `579ee19d5b54c4f9320ffca668113c3513a138e5`
- License: BSD-3-Clause
- Purpose: TLS 1.3 QUIC handshake and RFC 9221 DATAGRAM transport.
- Network behavior: the edge opens one outbound UDP flow to the configured
  relay; the relay itself does not import or run quic-go.
- Uninstall: remove the campus-link binaries; no global Go module installation
  is performed.

## connect-ip-go (inspected donor; not copied or linked in Phase 1)

- Source: `https://github.com/quic-go/connect-ip-go`
- Revision: `6ece6b8295f2fd5c49282d56de809640b282246d`
- License: MIT
- Purpose: reference behavior for a later RFC 9484 HTTP/3 CONNECT-IP context,
  packet validation, TTL handling, MTU errors, and route advertisement.
- Credential requirements: none.
- Uninstall: delete the ignored research clone; the Phase-1 binary has no
  dependency on this repository.

## frp xtcp (inspected donor; forked, not copied or linked)

- Upstream: `https://github.com/fatedier/frp`
- User fork: `https://github.com/dual1208/frp`
- Branch/revision inspected: `dev` at
  `5c6d761c1287e6153f07b824fb6d71b96ee598fe`
- License: Apache-2.0
- Purpose: reference architecture for STUN-assisted endpoint discovery,
  authenticated rendezvous, server-selected NAT-hole behavior, direct QUIC/KCP
  sessions, retry scoring, and relayed fallback.
- Network behavior: the inspected `xtcp` design keeps `frps` in the control
  path while established bulk sessions run directly between clients. It uses
  configured STUN servers and sends authenticated UDP probes to peer candidate
  addresses. No FRP binary is installed or executed by campus-link.
- Credentials/permissions: GitHub authentication was used only to create the
  user's fork; source inspection itself requires no credentials. A deployed FRP
  service would require its own configuration and secret key, but none was
  created.
- Verification: GitHub reports the fork parent as `fatedier/frp`, default branch
  `dev`, and the pinned fork commit above on 2026-07-28.
- Uninstall: campus-link has no installed FRP component. Removing the fork would
  require a separate destructive GitHub action and is intentionally excluded.

## GitHub Actions used for CI

- `actions/checkout` v7.0.1, pinned to commit
  `3d3c42e5aac5ba805825da76410c181273ba90b1`.
- `actions/setup-go` v7.0.0, pinned to commit
  `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`.
- Purpose: obtain the repository and an exact Go 1.26.4 toolchain for test,
  race, vet, fuzz-seed, and build gates on GitHub-hosted Linux runners.
- Permissions/network: the job has read-only repository contents permission;
  the actions access GitHub and the official Go toolchain distribution.
- Verification: versions and commits were resolved through the official
  GitHub API on 2026-07-28. Workflow references immutable commits.
- Uninstall: remove `.github/workflows/campus-link.yml`; neither action is
  installed on a router, relay, Droplet, or workstation.
