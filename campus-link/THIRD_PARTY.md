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
