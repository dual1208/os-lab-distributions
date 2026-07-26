# Offline build references

These files are retained locally for the OS Lab builds. Binary/manual payloads
are deliberately ignored by Git; `SOURCES.tsv` records provenance and
`MANIFEST.sha256` verifies the local copies.

The collection is anchored to LFS/BLFS 13.0-systemd and supplemented with the
current LFS development recipe's systemd manual bundle and the latest Linux
man-pages release available on the retrieval date. The small `glibc.html` and
`ld.html` files are official manual landing/index pages; the corresponding
PDFs contain the complete manuals.

Verify from this directory with a SHA-256 implementation that accepts the
standard two-column format, for example:

```sh
sha256sum --check MANIFEST.sha256
```
