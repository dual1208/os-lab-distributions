# campus-link production-candidate verification — 2026-07-28

## Claim boundary

This is a hardened production candidate, not a production-ready release. The
mandatory 1 GiB, accelerated one-hour, 24-hour, and seven-day gates were not
complete when this record was written. A single `gz` relay and the absence of
TCP/441 fallback also remain availability blockers.

The deployed edge/relay binaries report source version
`phase1-5045bd92779a`. Later commits in this report add only tracked test and
qualification orchestration. All host addresses, provider identifiers,
credentials, bind tokens, packet bodies, and raw captures are excluded.

## Passed gates

- Go 1.26.4: `go test -race ./...`, `go vet ./...`, and `go build ./...`
  passed on linux/amd64. Binding, bounded control framing, and IPv4 validation
  fuzz targets each passed bounded native fuzzing. GitHub CI also passed.
- Security regressions cover latest-session ownership, coordinated circuit-leg
  invalidation, explicit data peer identity, bad IPv4 checksum, TTL expiry,
  malformed lengths, wrong prefixes, bounded control JSON, and the outer
  datagram size limit.
- A11→B22: 10,000 ordered request/response hashes passed in 40.075 s.
- B22→A11: 10,000 ordered hashes passed in 45.493 s; 100 simultaneous TCP
  flows passed in 5.002 s; half-close passed.
- Unimpaired A11→B22: 100 simultaneous flows passed; a 4 MiB exact-hash bulk
  transfer passed in 87.575 s; paced UDP delivered 97/100.
- Netem on both isolated edge WANs (`1%` loss, `100 ms` delay, `20 ms` jitter,
  `0.1%` reorder): ordered records, 10 simultaneous TCP flows, 1 MiB exact
  hash, and half-close passed; UDP delivered 96/100. Cleanup restored both
  qdiscs to `noqueue`.
- Thirty edge-A kill trials all withdrew the route and restored an application
  probe: min 4.985 s, median 5.782 s, p95 9.318 s, max 9.640 s.
- Thirty `gz` relay restart trials all withdrew the route and restored an
  application probe: min 6.801 s, mean 8.990 s, p95 11.129 s, max 11.918 s.
- After more than 100 aggregate edge reconnections, each edge used about 9 MiB
  RSS and 8 file descriptors. The relay used about 16 MiB RSS and 9 file
  descriptors. These are below the contract ceilings.
- The prior bounded no-plaintext UDP/443 capture, mTLS control, authenticated
  tuple binding, TCP/8080 allow, and TCP/12345 denial smoke remains passing.

## Active and queued gates

The router-lab host supervises this sequence:

1. `campus-link-full-qualification.service`: 10,000 records, 100 concurrent
   flows, and a 1 GiB SHA-256 transfer in each direction;
2. `campus-link-accelerated-fault.service`: at least one hour of repeated
   30-trial edge kill/recovery batches, conditional on gate 1;
3. `campus-link-24h-soak.service`: bidirectional application probes every ten
   seconds for 24 hours, conditional on gate 2.

Inspect without exposing private state:

```bash
systemctl status campus-link-full-qualification.service \
  campus-link-accelerated-fault.service campus-link-24h-soak.service --no-pager
journalctl -u campus-link-full-qualification.service -n 30 --no-pager
ls -l /run/campus-link/*result
```

The seven-day burn-in must start only after these results pass. Until then,
documentation and releases must retain the `production candidate` label.

## Rollback

Both installers retain one private, bounded previous version under
`/var/lib/campus-link`. Use `campus-link-rollback-edge` on the edge host and
`campus-link-rollback-relay` on `gz`. A failed coordinated deployment invokes
both automatically, then reruns the prior smoke before any production claim.
