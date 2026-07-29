# campus-link asymmetric identity and key-rotation contract

Status: required by user; partial foundations only; runtime wiring, safe
provisioning, rotation, expiry visibility, and migration remain pending.

## Objective

Only the two provisioned OpenWrt edges may authenticate to `gz`, obtain peer
candidates, authenticate each other, and establish the direct bulk-data path.
Passwords, API tokens, static pre-shared secrets, circuit names, source
addresses, and broker-issued rendezvous keys are never identities.

The system uses asymmetric proof of private-key possession at both trust
boundaries:

1. router-to-`gz` TLS 1.3 mutual authentication for control/rendezvous; and
2. router-to-router TLS 1.3 mutual authentication for the direct and fallback
   data paths.

The second boundary is independent of `gz`. Compromise of `gz` may deny
service, withhold or falsify candidates, or observe public endpoint metadata;
it must not enable data decryption or impersonation of either router.

## Explicit non-identities

- The short-lived 256-bit rendezvous probe key authenticates packets belonging
  to one already-authorized attempt. Because `gz` creates and knows it, it is
  not proof of router identity and grants no data-plane access.
- UDP tuple challenges prove return routability and possession of a control
  session token, not durable identity.
- LAN prefixes, DNS names, certificate common names, public addresses, Droplet
  metadata, and GitHub identity are assertions that must be bound to a verified
  public key; none is accepted alone.
- No password or long-lived PSK is added as a fallback authentication path.

## Key hierarchy

All production keys use Ed25519. The two CA private keys are offline and never
installed on a router or `gz`.

```text
offline control root
├── gz-control              serverAuth
├── router-a-control        clientAuth
└── router-b-control        clientAuth

offline data root
├── router-a-data           serverAuth + clientAuth
└── router-b-data           serverAuth + clientAuth
```

Each leaf has digital-signature key usage, a critical or otherwise enforced
extended-key-usage restriction, and a URI subject alternative name scoped to
the one circuit and plane:

```text
spiffe://campus-link/home-pair-1/relay/control
spiffe://campus-link/home-pair-1/site-a/control
spiffe://campus-link/home-pair-1/site-b/control
spiffe://campus-link/home-pair-1/site-a/data
spiffe://campus-link/home-pair-1/site-b/data
```

`gz-control` additionally has the configured DNS SAN. Common-name fallback is
forbidden. The two data certificates contain both TLS endpoint EKUs because
NAT analysis may assign either edge the QUIC client or server role.

Root certificates may be valid for five years. Leaf certificates are valid for
at most 90 days and are rotated with an overlap. Lab credentials may use a
shorter lifetime but must exercise the same identity and pin checks.

## Exact authorization

CA validation alone is insufficient: another leaf signed by the same CA must
not join this circuit.

### At `gz`

The relay configuration has exactly two authorized control identities. Each
entry binds all of the following:

- fixed site (`site-a` or `site-b`);
- circuit;
- expected control URI SAN;
- permitted current and optional next SHA-256 SPKI pins; and
- required `clientAuth` EKU.

After normal X.509 chain and time validation, `gz` verifies the URI, EKU, and
SPKI allowlist in constant time. It derives the site from this authorization
entry, not from a common name or registration JSON. The subsequent registration
must repeat the same site, circuit, and fixed prefix or it is rejected.

### At each router

The control client verifies `gz` using the control root, configured DNS SAN,
relay control URI SAN, `serverAuth` EKU, and current/next relay SPKI pins.

The data connection verifies the other router using the data root, exact peer
data URI SAN, role-appropriate EKU, and current/next peer SPKI pins. Both QUIC
roles run this verification. A certificate for `gz`, the other control plane,
the wrong circuit, the wrong site, or merely the same CA is rejected.

The direct bulk path starts only after the end-to-end data mTLS handshake and
an authenticated bidirectional application probe. `gz` never receives a data
private key, the data root private key, or plaintext LAN packet.

## Private-key custody

- A router generates each replacement leaf key locally when feasible and
  exports only a CSR. Initial lab provisioning may generate keys on the trusted
  lab host, but keys must travel directly to the intended router over the
  administrative channel, never through `gz`.
- Router private keys live below `/etc/campus-link/keys`, owned by root and mode
  `0600`; the directory is mode `0700`. Services receive read access only to
  their own leaf keys.
- `gz` stores only its control server key, public control root, and the two
  router control public-certificate/SPKI authorizations. It stores no data-plane
  private material or data-root certificate unless a separate public audit use
  is explicitly justified.
- CA private keys, CSRs containing local identifiers, unredacted certificates,
  runtime pins, and inventories stay outside Git. Git contains generators,
  schemas, public examples, and sanitized evidence only.
- Private keys are never printed, logged, placed in command-line arguments,
  returned by status APIs, or copied into crash reports.

## Rotation and revocation

Rotation is current-plus-next, not replace-in-place:

1. Generate a new key on the destination and sign its CSR offline.
2. Validate its circuit URI, EKU, validity, key algorithm, and SPKI pin offline.
3. Add the next public certificate/pin to the peer allowlists while the current
   identity remains accepted.
4. Atomically stage the next certificate/key and restart one endpoint. Verify
   control, rendezvous, direct data mTLS, fallback, and application probes.
5. Rotate the peer, then remove old pins only after both sides have used the new
   identities for the overlap window.
6. Securely retire old private keys from the service path. Destructive media
   sanitization is an operator action, not an automatic installer action.

Emergency revocation removes the compromised SPKI pin and invalidates its
active owner generation, rendezvous sessions, probe keys, UDP bindings, and
QUIC sessions. Routes fail closed unless the other already-authenticated data
path remains valid. Short leaf lifetimes and exact pin removal are the primary
revocation mechanisms; the system does not depend on public OCSP availability.

## Expiry visibility

Status reports only coarse, non-identifying fields:

- local control/data days remaining;
- verified peer control/data days remaining;
- state: `ok`, `rotate-soon`, `critical`, `expired`, or `not-yet-valid`; and
- whether current or next slot is active, without printing a fingerprint,
  serial number, subject, URI, or certificate body.

Warnings begin at 30 days, become critical at 14 days, and block a new session
after expiry. Existing TLS sessions are revalidated by bounded reconnect before
the certificate expires; they do not run indefinitely on an expired identity.

## Release-blocking adversarial closure gate

The 2026-07-28 adversarial review found that the strict verifier was not called
by any active TLS path. The relay still derived a site from a certificate
common name, the edge control client relied on CA plus DNS verification, and
the data server accepted a DNS-or-common-name fallback. Generated pins were not
runtime authorizations, and the generated `site-a.campus-link` data identity did
not match the server installer's `site-a` expectation. These are defects, not
migration compatibility.

Before any asymmetric-identity candidate is staged:

- security-bearing JSON rejects unknown, duplicate, and case-smuggled fields;
- every TLS verifier retains native X.509 verification and requires a non-empty
  verified chain, exactly one expected URI, the exact allowed EKU set, an
  Ed25519 non-CA digital-signature leaf with a lifetime no longer than 90 days,
  and a canonical strictly padded Base64 SPKI pin;
- pin uniqueness is checked on decoded bytes, and one current plus at most one
  next pin is accepted;
- relay authorization contains exactly two entries binding site, circuit,
  prefix, control URI, client-auth EKU, and pins. The site is derived from the
  matched entry, never from a certificate or registration common name;
- the edge control client and both QUIC roles enforce chain, DNS transport name,
  exact URI/EKU, and SPKI authorization. Common-name fallback is deleted;
- full TLS handshake tests reject foreign same-root leaves in every verifier
  position and prove the generated A/B pair succeeds in either QUIC role;
- the all-in-one generator is labeled lab-only and refuses physical or
  production installation. Production bundles contain one endpoint's leaves,
  public roots, and peer pins only; neither router nor `gz` receives a CA key or
  another endpoint's private key; and
- services use separate least-privilege identities. Certificate/key paths are
  regular files reached through non-symlink, root-owned, non-group/world-
  writable path components and are validated for key match, profile, mode,
  ownership, and authorization even when a completion marker exists.

Rotation atomically backs up and replaces the complete cert/key/root/
authorization tuple independently of binary version. Pin retirement or
emergency revocation invalidates the owner generation, rendezvous plans and
probe keys, UDP binding, control session, and QUIC session. Sanitized closure
evidence is required before staging or rerunning production gates.

## Acceptance checks

- The intended two router control certificates authenticate and map to exactly
  their configured site and prefix.
- A third certificate signed by the control root is rejected by `gz`.
- Wrong site, wrong circuit URI, absent URI SAN, common-name-only, wrong EKU,
  malformed pin, unlisted SPKI, expired, and not-yet-valid certificates fail.
- Each router rejects the other router's control certificate on the data plane,
  rejects `gz` on the data plane, and rejects a foreign data leaf signed by the
  data root.
- Current and next pins are accepted during overlap. The old pin is rejected
  after removal, including on a new control connection and a new direct QUIC
  connection.
- A broker that supplies an attacker's candidate and a valid broker-known probe
  key still cannot complete data mTLS or inject a routed packet.
- Key files and directories have exact ownership/modes; public configuration
  cannot substitute a different key through a symlink or world-writable path.
- Rotation preserves an A11↔B22 long-lived TCP stream or fails the candidate
  gate. Expiry warnings are visible without certificate identifiers.
- Tests include unit tables, TLS handshakes, race runs, fuzz seeds for pin/URI
  parsing, rollback to current credentials, and a sanitized on-router rotation
  rehearsal.

## Apply and rollback

1. Commit and push this contract before verifier or PKI-generator changes.
2. Add strict URI/EKU/SPKI verification and full TLS rejection tests without
   changing the running candidate.
3. Replace the lab generator with plane-separated Ed25519 leaves and emit a
   private runtime authorization file. Never overwrite an existing PKI.
4. Wire the verifier into all TLS boundaries, remove common-name compatibility,
   and add current/next configuration, expiry status, and atomic credential-
   tuple rotation helpers.
5. Build and test in an isolated candidate. Stage the new trust configuration
   on all three machines before activating any new certificate.
6. Activate one plane at a time and retain the current certificate, key, and
   allowlist as a bounded rollback slot until all gates pass.

On failure, restore the previous complete certificate/key/allowlist tuple
atomically and rerun the prior mTLS and A11/B22 smoke tests. Never weaken the
verifier, enable common-name fallback, accept every CA-signed leaf, or introduce
a password/PSK escape hatch to make a failed rotation pass.
