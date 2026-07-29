# Sanitized DigitalOcean capacity and co-tenancy record — 2026-07-29

## Fleet

The three exact recorded Basic Droplets now use workload-oriented provider
names. No guest was rebooted or service restarted by the metadata rename.

| Provider name | Reserved role | Plan capacity |
|---|---|---|
| `openwrt-e8450-build` | verified E8450 build artifacts plus bounded agent work | 4 vCPU, 8 GiB RAM, 160 GiB disk |
| `campus-link-router-lab` | two QEMU routers and campus-link qualification | 4 vCPU, 8 GiB RAM, 160 GiB disk |
| `openwrt-e8450-repro` | independent clean E8450 reproduction and isolated security builds | 4 vCPU, 8 GiB RAM, 160 GiB disk |

Combined provisioned capacity is 12 vCPU, 24 GiB RAM, and 480 GiB local disk.
The combined live rate remains USD 0.24999/hour, with individual monthly caps
unchanged. IDs, addresses, credentials, account data, and raw inventories are
excluded.

## Read-only snapshot

The snapshot was taken after the rename. Values are deliberately coarse and
will change as builds run.

| Host role | Available RAM | Free `/srv` | Load (1/5/15 min) | Reserved work |
|---|---:|---:|---:|---|
| E8450 build | 7.14 GiB | 125.5 GiB | 0.08 / 0.07 / 0.03 | verified artifacts; no active OpenWrt compiler |
| router lab | 6.82 GiB | 121.4 GiB | 0.16 / 0.07 / 0.02 | router lab active; 24-hour soak active |
| E8450 reproduction | 7.18 GiB | 133.2 GiB | 0.00 / 0.00 / 0.00 | reproduction tree retained; no active compiler |

The completed full campus-link gate and accelerated-fault gate remained passed.
The 24-hour result was still pending and its service remained active, so the
router-lab host is not available to unrelated heavy work.

## Resource reservations

The Chromium/DevTools agent team is assigned only
`openwrt-e8450-build`, using a separate
`/srv/chromium-devtools-observatory` workload root:

- at most 3 vCPU and 6 GiB RAM;
- at most about 100 GiB of new data, with a hard 25 GiB free-disk floor;
- no write below `/srv/openwrt-lab` and a before/after metadata baseline;
- no public listener; browser debugging is loopback-only plus SSH forwarding;
- stop rather than exceed a bound or disturb the retained OpenWrt release.

The campus-link security build/test work may use
`openwrt-e8450-repro` when it does not overlap the next clean reproduction
attempt. It retains at least 2 GiB available RAM and 25 GiB free disk, and uses
an isolated temporary tree. The router-lab host remains exclusive to QEMU,
qualification, soak, and burn-in until every mandatory gate finishes.

These reservations divide capacity; they do not guarantee that a Chromium
link step will fit inside 6 GiB RAM or that a full checkout/build will fit in
100 GiB. Either condition fails closed and is reported instead of borrowing
from a protected workload.
