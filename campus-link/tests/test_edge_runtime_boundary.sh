#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=../scripts/gate-evidence.sh
source "${REPO_ROOT}/campus-link/scripts/gate-evidence.sh"

tmp=$(mktemp -d)
cleanup() {
  rm -rf -- "${tmp}"
}
trap cleanup EXIT

readonly TEST_BINARY=${tmp}/installed/campus-link-edge
readonly TEST_PROC=${tmp}/proc
readonly TEST_ROOT=${tmp}/root
mkdir -p "$(dirname "${TEST_BINARY}")" "${TEST_PROC}" "${TEST_ROOT}"
printf 'edge-binary-bytes\n' > "${TEST_BINARY}"

declare -A PROPERTIES=()
set_property() {
  PROPERTIES["$1|$2"]=$3
}
get_property() {
  local key=$1
  [[ ${PROPERTIES[${key}]+present} == present ]] || return 1
  printf '%s' "${PROPERTIES[${key}]}"
}

systemctl() {
  local property= unit= key all=0
  [[ ${1:-} == show ]] || return 1
  shift
  for argument in "$@"; do
    case ${argument} in
      --all) all=1 ;;
      --no-pager|--value) ;;
      --property=*) property=${argument#--property=} ;;
      -*) return 1 ;;
      *) [[ -z ${unit} ]] || return 1; unit=${argument} ;;
    esac
  done
  [[ -n ${unit} ]] || return 1
  if (( all == 1 )); then
    while IFS= read -r key; do
      [[ ${key} == "${unit}|"* ]] || continue
      printf '%s=%s\n' "${key#*|}" "${PROPERTIES[${key}]}"
    done < <(printf '%s\n' "${!PROPERTIES[@]}" | LC_ALL=C sort)
    return
  fi
  [[ -n ${property} ]] || return 1
  get_property "${unit}|${property}"
}
campus_link_global_service_dropin_sha256() {
  [[ $1 == */service.d/*.conf ]] || return 1
  printf '%064d' 7
}
campus_link_proc_path() {
  printf '%s/%s/%s' "${TEST_PROC}" "$1" "$2"
}
campus_link_edge_binary_path() {
  printf '%s' "${TEST_BINARY}"
}
campus_link_edge_config_path() {
  printf '%s/etc/campus-link/%s/edge.json' "${TEST_ROOT}" "$1"
}
campus_link_edge_fragment_path() {
  printf '%s/etc/systemd/system/campus-link-edge-%s.service' "${TEST_ROOT}" "$1"
}
campus_link_edge_namespace_path() {
  printf '%s/run/netns/campus-%s' "${TEST_ROOT}" "$1"
}
campus_link_edge_identity() {
  case $1 in
    campus-link-a) printf '41001 41001' ;;
    campus-link-b) printf '41002 41002' ;;
    *) return 1 ;;
  esac
}
campus_link_process_executable_matches() {
  cmp -s -- "$1" "$2"
}

populate_unit() {
  local suffix=$1 site=site-$1 unit=campus-link-edge-$1.service
  local user=campus-link-$1 namespace binary config fragment property expected pid
  namespace=$(campus_link_edge_namespace_path "${suffix}")
  binary=$(campus_link_edge_binary_path)
  config=$(campus_link_edge_config_path "${site}")
  fragment=$(campus_link_edge_fragment_path "${suffix}")
  pid=41001
  [[ ${suffix} == b ]] && pid=41002
  set_property "${unit}" DropInPaths ''
  while IFS='|' read -r property expected; do
    set_property "${unit}" "${property}" "${expected}"
  done <<EOF
LoadState|loaded
FragmentPath|${fragment}
Type|simple
User|${user}
Group|${user}
SupplementaryGroups|
DynamicUser|no
RemainAfterExit|no
GuessMainPID|yes
NotifyAccess|none
PIDFile|
FileDescriptorStoreMax|0
KillMode|control-group
SendSIGKILL|yes
SameProcessGroup|no
NetworkNamespacePath|${namespace}
NoNewPrivileges|yes
CapabilityBoundingSet|
AmbientCapabilities|
SecureBits|0
DevicePolicy|closed
PrivateTmp|yes
PrivateDevices|no
PrivateNetwork|no
PrivateUsers|no
PrivateMounts|no
ProtectClock|yes
ProtectControlGroups|yes
ProtectHome|yes
ProtectHostname|no
ProtectKernelLogs|yes
ProtectKernelModules|yes
ProtectKernelTunables|yes
ProtectProc|default
ProtectSystem|strict
ProcSubset|all
RestrictNamespaces|yes
RestrictRealtime|yes
RestrictSUIDSGID|yes
LockPersonality|yes
SystemCallArchitectures|native
UMask|0077
Restart|on-failure
RestartUSec|10s
StartLimitIntervalUSec|0
MemoryHigh|83886080
MemoryMax|100663296
TasksMax|128
LimitNOFILE|512
LimitNOFILESoft|512
LimitCORE|0
LimitCORESoft|0
MemoryDenyWriteExecute|no
KeyringMode|private
RootDirectory|
RootImage|
RootImageOptions|
RootDirectoryStartOnly|no
WorkingDirectory|
PAMName|
Environment|
EnvironmentFiles|
PassEnvironment|
UnsetEnvironment|
LoadCredential|
LoadCredentialEncrypted|
SetCredential|
SetCredentialEncrypted|
ImportCredential|
ImportCredentialEx|
OpenFile|
Sockets|
RuntimeDirectory|
StateDirectory|
CacheDirectory|
LogsDirectory|
ConfigurationDirectory|
ReadOnlyPaths|
BindPaths|
BindReadOnlyPaths|
TemporaryFileSystem|
MountImages|
ExtensionImages|
ExtensionDirectories|
MountFlags|
IPCNamespacePath|
JoinsNamespaceOf|
AppArmorProfile|
SELinuxContext|
SmackProcessLabel|
ExecCondition|
ExecStartPre|
ExecStartPost|
ExecReload|
ExecStop|
ExecStopPost|
StandardInput|null
StandardInputData|
NonBlocking|no
Delegate|no
EOF
  set_property "${unit}" DeviceAllow '/dev/net/tun rw'
  set_property "${unit}" RestrictAddressFamilies 'AF_UNIX AF_INET6 AF_INET'
  set_property "${unit}" ReadWritePaths "/run/campus-link/${site}"
  if [[ ${suffix} == a ]]; then
    set_property "${unit}" InaccessiblePaths \
      '-/srv/openwrt-lab -/var/lib/campus-link -/run/campus-link/site-b -/etc/campus-link/relay-fault -/etc/campus-link/pki -/etc/campus-link/site-b'
  else
    set_property "${unit}" InaccessiblePaths \
      '-/srv/openwrt-lab -/var/lib/campus-link -/run/campus-link/site-a -/etc/campus-link/relay-fault -/etc/campus-link/pki -/etc/campus-link/site-a'
  fi
  set_property "${unit}" ExecStart \
    "{ path=${binary} ; argv[]=${binary} -config ${config} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
  set_property "${unit}" ExecStartEx \
    "{ path=${binary} ; argv[]=${binary} -config ${config} ; flags= ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
  set_property "${unit}" ActiveState active
  set_property "${unit}" MainPID "${pid}"
}

write_status() {
  local pid=$1 uid=$2 gid=$3 groups=$4 no_new_privs=$5 cap_eff=$6
  {
    printf 'Uid:\t%s\t%s\t%s\t%s\n' "${uid}" "${uid}" "${uid}" "${uid}"
    printf 'Gid:\t%s\t%s\t%s\t%s\n' "${gid}" "${gid}" "${gid}" "${gid}"
    printf 'Groups:\t%s\n' "${groups}"
    printf 'NoNewPrivs:\t%s\n' "${no_new_privs}"
    printf 'CapInh:\t0000000000000000\n'
    printf 'CapPrm:\t0000000000000000\n'
    printf 'CapEff:\t%s\n' "${cap_eff}"
    printf 'CapBnd:\t0000000000000000\n'
    printf 'CapAmb:\t0000000000000000\n'
  } > "${TEST_PROC}/${pid}/status"
}

make_process() {
  local suffix=$1 pid=$2 uid=$3 gid=$4 site=site-$1 config namespace
  config=$(campus_link_edge_config_path "${site}")
  namespace=$(campus_link_edge_namespace_path "${suffix}")
  mkdir -p "${TEST_PROC}/${pid}/ns" "$(dirname "${namespace}")" "$(dirname "${config}")"
  [[ -e ${namespace} ]] || printf 'namespace-%s\n' "${suffix}" > "${namespace}"
  ln "${namespace}" "${TEST_PROC}/${pid}/ns/net"
  cp "${TEST_BINARY}" "${TEST_PROC}/${pid}/exe"
  printf '%s\0%s\0%s\0' "${TEST_BINARY}" -config "${config}" > "${TEST_PROC}/${pid}/cmdline"
  write_status "${pid}" "${uid}" "${gid}" "${gid}" 1 0000000000000000
}

expect_failure() {
  local label=$1
  if campus_link_assert_edge_runtime_boundary >/dev/null 2>&1; then
    printf 'unexpected pass: %s\n' "${label}" >&2
    exit 1
  fi
  [[ -z ${CAMPUS_LINK_EDGE_RUNTIME_BOUNDARY_SHA256} ]]
}

populate_unit a
populate_unit b
make_process a 41001 41001 41001
make_process b 41002 41002 41002

campus_link_assert_edge_runtime_boundary
readonly BASELINE_DIGEST=${CAMPUS_LINK_EDGE_RUNTIME_BOUNDARY_SHA256}
[[ ${BASELINE_DIGEST} =~ ^[a-f0-9]{64}$ ]]

unit=campus-link-edge-a.service
set_property "${unit}" DropInPaths /etc/systemd/system/campus-link-edge-a.service.d/override.conf
expect_failure unit-specific-drop-in
set_property "${unit}" DropInPaths /run/systemd/system.control/campus-link-edge-a.service.d/50-override.conf
expect_failure control-drop-in
set_property "${unit}" DropInPaths /run/systemd/transient/campus-link-edge-a.service.d/50-override.conf
expect_failure transient-drop-in
set_property "${unit}" DropInPaths /usr/lib/systemd/system/service.d/10-distro.conf
campus_link_assert_edge_runtime_boundary
[[ ${CAMPUS_LINK_EDGE_RUNTIME_BOUNDARY_SHA256} != "${BASELINE_DIGEST}" ]]
set_property "${unit}" DropInPaths ''

for mutation in \
  'FragmentPath|/tmp/other.service' \
  'User|root' \
  'Group|root' \
  'NetworkNamespacePath|/run/netns/other' \
  'NoNewPrivileges|no' \
  'CapabilityBoundingSet|cap_net_admin' \
  'AmbientCapabilities|cap_net_admin' \
  'DevicePolicy|auto' \
  'ProtectSystem|full' \
  'ExecStartPre|{ path=/bin/true ; argv[]=/bin/true ; ignore_errors=no ; }'; do
  property=${mutation%%|*}
  bad=${mutation#*|}
  old=$(get_property "${unit}|${property}")
  set_property "${unit}" "${property}" "${bad}"
  expect_failure "effective-${property}"
  set_property "${unit}" "${property}" "${old}"
done

old=$(get_property "${unit}|DeviceAllow")
set_property "${unit}" DeviceAllow '/dev/net/tun rw /dev/kvm rw'
expect_failure expanded-device-allow
set_property "${unit}" DeviceAllow "${old}"

old=$(get_property "${unit}|InaccessiblePaths")
set_property "${unit}" InaccessiblePaths '-/etc/campus-link/pki'
expect_failure weakened-inaccessible-paths
set_property "${unit}" InaccessiblePaths "${old}"

old=$(get_property "${unit}|ExecStartEx")
set_property "${unit}" ExecStartEx "${old/flags= /flags=privileged }"
expect_failure privileged-exec-flag
set_property "${unit}" ExecStartEx "${old}"

write_status 41001 41000 41001 41001 1 0000000000000000
expect_failure wrong-runtime-uid
write_status 41001 41001 41001 '41001 49999' 1 0000000000000000
expect_failure supplementary-group
write_status 41001 41001 41001 41001 0 0000000000000000
expect_failure runtime-no-new-privileges-disabled
write_status 41001 41001 41001 41001 1 0000000000002000
expect_failure runtime-effective-capability
write_status 41001 41001 41001 41001 1 0000000000000000

config=$(campus_link_edge_config_path site-a)
printf '%s\0%s\0%s\0%s\0' "${TEST_BINARY}" -config "${config}" unexpected > "${TEST_PROC}/41001/cmdline"
expect_failure extra-runtime-argument
printf '%s\0%s\0%s\0' "${TEST_BINARY}" -config "${config}" > "${TEST_PROC}/41001/cmdline"

rm "${TEST_PROC}/41001/ns/net"
printf 'other-namespace\n' > "${TEST_PROC}/41001/ns/net"
expect_failure wrong-network-namespace
rm "${TEST_PROC}/41001/ns/net"
ln "$(campus_link_edge_namespace_path a)" "${TEST_PROC}/41001/ns/net"

printf 'different-executable\n' > "${TEST_PROC}/41001/exe"
expect_failure executable-byte-mismatch
cp "${TEST_BINARY}" "${TEST_PROC}/41001/exe"

set_property "${unit}" MainPID 0
expect_failure invalid-main-pid
set_property "${unit}" MainPID 41001

set_property "${unit}" ActiveState inactive
set_property "${unit}" MainPID 0
rm -rf -- "${TEST_PROC}/41001"
expect_failure inactive-edge
set_property "${unit}" ActiveState active
set_property "${unit}" MainPID 41001
make_process a 41001 41001 41001
campus_link_assert_edge_runtime_boundary
[[ ${CAMPUS_LINK_EDGE_RUNTIME_BOUNDARY_SHA256} == "${BASELINE_DIGEST}" ]]

candidate_definition=$(declare -f campus_link_candidate_fingerprint)
[[ ${candidate_definition} == *'campus_link_assert_edge_runtime_boundary || return 1'* ]]
[[ ${candidate_definition} == *"printf 'edge-runtime-boundary\\0%s\\0'"* ]]

echo 'PASS edge runtime privilege boundary'
