#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=${1:-/srv/openwrt-lab/repo}
readonly GO_BIN=${GO_BIN:-/srv/openwrt-lab/build/openwrt-x86/staging_dir/hostpkg/lib/go-1.26/bin/go}
readonly OUT=/srv/openwrt-lab/build/campus-link
readonly -a SOURCE_SCOPE=(campus-link lab cloud/cloud-init.yaml scripts/Deploy-CampusLink.ps1)

read_complete_nul_inventory() {
  local input=$1 output_name=$2 input_size consumed=0 item
  local LC_ALL=C
  local -n output=${output_name}
  output=()
  input_size=$(stat -c '%s' -- "${input}") || return 1
  (( input_size > 0 )) || return 1
  while IFS= read -r -d '' item; do
    output+=("${item}")
    consumed=$((consumed + ${#item} + 1))
  done < "${input}"
  (( consumed == input_size && ${#output[@]} > 0 ))
}

verify_source_checkout_unchanged() {
  local expected_commit=$1 actual_commit untracked
  actual_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD) || return 1
  [[ ${actual_commit} == "${expected_commit}" ]] || return 1
  git -C "${REPO_ROOT}" diff --quiet -- "${SOURCE_SCOPE[@]}" || return 1
  git -C "${REPO_ROOT}" diff --cached --quiet -- "${SOURCE_SCOPE[@]}" || return 1
  untracked=$(git -C "${REPO_ROOT}" ls-files --others -- "${SOURCE_SCOPE[@]}") || return 1
  [[ -z ${untracked} ]]
}

[[ -x ${GO_BIN} ]]
go_version=$(${GO_BIN} version | awk '{print $3}') || exit 1
[[ ${go_version} == go1.26.4 ]]
repo_toplevel=$(git -C "${REPO_ROOT}" rev-parse --show-toplevel) || exit 1
[[ ${repo_toplevel} == "${REPO_ROOT}" ]]
git -C "${REPO_ROOT}" diff --quiet -- "${SOURCE_SCOPE[@]}"
git -C "${REPO_ROOT}" diff --cached --quiet -- "${SOURCE_SCOPE[@]}"
untracked=$(git -C "${REPO_ROOT}" ls-files --others -- "${SOURCE_SCOPE[@]}") || exit 1
[[ -z ${untracked} ]]

commit=$(git -C "${REPO_ROOT}" rev-parse HEAD) || exit 1
[[ ${commit} =~ ^[a-f0-9]{40}$ ]]
source_listing=$(mktemp)
source_paths=$(mktemp)
cleanup() {
  rm -f -- "${source_listing}" "${source_paths}"
}
trap cleanup EXIT
git -C "${REPO_ROOT}" ls-files -z -- "${SOURCE_SCOPE[@]}" | \
  LC_ALL=C sort -z > "${source_paths}" || exit 1
declare -a source_path_inventory=()
read_complete_nul_inventory "${source_paths}" source_path_inventory || exit 1
for path in "${source_path_inventory[@]}"; do
  [[ ${path} =~ ^[A-Za-z0-9._/-]+$ ]]
  index_entry=$(git -C "${REPO_ROOT}" ls-files --stage -- "${path}")
  read -r mode object stage <<< "${index_entry%%$'\t'*}"
  [[ (${mode} == 100644 || ${mode} == 100755) && ${object} =~ ^[a-f0-9]{40}$ && ${stage} == 0 ]]
  [[ ${index_entry#*$'\t'} == "${path}" ]]
  digest=$(sha256sum "${REPO_ROOT}/${path}" | awk '{print $1}')
  [[ ${digest} =~ ^[a-f0-9]{64}$ ]]
  printf '%s %s %s\n' "${mode}" "${digest}" "${path}" >> "${source_listing}"
done
[[ -s ${source_listing} ]]
source_tree_digest=$(sha256sum "${source_listing}" | awk '{print $1}')
[[ ${source_tree_digest} =~ ^[a-f0-9]{64}$ ]]
readonly VERSION=phase1-${commit:0:12}-${source_tree_digest:0:12}

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
verify_source_checkout_unchanged "${commit}" || exit 1
printf '%s\n' "${VERSION}" > "${OUT}/VERSION"
printf '%s  source-tree\n' "${source_tree_digest}" > "${OUT}/SOURCE_TREE.sha256"
printf '%s\n' "${commit}" > "${OUT}/SOURCE_COMMIT"
rm -f -- "${OUT}/SHA256SUMS"
trap - EXIT
cleanup
