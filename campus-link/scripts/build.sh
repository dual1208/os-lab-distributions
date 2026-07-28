#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly GO_BIN=${GO_BIN:-/srv/openwrt-lab/build/openwrt-x86/staging_dir/hostpkg/lib/go-1.26/bin/go}
readonly OUT=/srv/openwrt-lab/build/campus-link
readonly VERSION=phase1-$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)

[[ -x ${GO_BIN} ]]
test "$(${GO_BIN} version | awk '{print $3}')" = go1.26.4
install -d -m 0755 "${OUT}"
cd "${REPO_ROOT}/campus-link"
"${GO_BIN}" test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO_BIN}" build \
  -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
  -o "${OUT}/campus-link-relay" ./cmd/campus-link-relay
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO_BIN}" build \
  -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
  -o "${OUT}/campus-link-edge" ./cmd/campus-link-edge
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO_BIN}" build \
  -trimpath -ldflags "-s -w" \
  -o "${OUT}/campus-linkctl" ./cmd/campus-linkctl
sha256sum "${OUT}"/campus-link-* > "${OUT}/SHA256SUMS"
printf '%s\n' "${VERSION}" > "${OUT}/VERSION"
