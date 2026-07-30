#!/usr/bin/env bash
set -euo pipefail

readonly ROOT=${CAMPUS_LINK_PKI_ROOT:-/etc/campus-link/pki}
readonly CIRCUIT_URI=spiffe://campus-link/home-pair-1
readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly AUTH_HELPER=${SCRIPT_DIR}/pki-public-authorizations.sh
[[ ${CAMPUS_LINK_LAB_ONLY:-} == 1 ]] || {
  echo 'Refusing all-in-one PKI generation without CAMPUS_LINK_LAB_ONLY=1.' >&2
  exit 2
}
[[ ${ROOT} == /* && ${ROOT} != / && ${ROOT} != /etc ]]

assert_no_symlinks() {
  local root=$1 inventory status=0
  inventory=$(mktemp) || return 1
  if ! find "${root}" -type l -print0 -quit > "${inventory}"; then
    status=1
  elif [[ -s ${inventory} ]]; then
    status=1
  fi
  rm -f -- "${inventory}" || return 1
  (( status == 0 ))
}

if [[ -e ${ROOT}/.complete ]]; then
  [[ -d ${ROOT} && ! -L ${ROOT} ]]
  assert_no_symlinks "${ROOT}"
  [[ $(stat -c '%u:%a' "${ROOT}") == 0:700 ]]
  [[ -f ${AUTH_HELPER} && ! -L ${AUTH_HELPER} ]]
  for name in \
    control-ca.crt control-ca.key relay-control.crt relay-control.key \
    site-a-control.crt site-a-control.key site-b-control.crt site-b-control.key \
    data-ca.crt data-ca.key site-a-data.crt site-a-data.key \
    site-b-data.crt site-b-data.key authorization.env .complete; do
    [[ -f ${ROOT}/${name} && ! -L ${ROOT}/${name} ]]
  done
  for name in control-ca.key relay-control.key site-a-control.key site-b-control.key \
    data-ca.key site-a-data.key site-b-data.key authorization.env .complete; do
    [[ $(stat -c '%u:%a' "${ROOT}/${name}") == 0:600 ]]
  done
  for name in control-ca.crt relay-control.crt site-a-control.crt \
    site-b-control.crt data-ca.crt site-a-data.crt site-b-data.crt; do
    [[ $(stat -c '%u:%a' "${ROOT}/${name}") == 0:644 ]]
  done
  for name in control-ca relay-control site-a-control site-b-control \
    data-ca site-a-data site-b-data; do
    cert_public=$(openssl x509 -in "${ROOT}/${name}.crt" -pubkey -noout |
      openssl pkey -pubin -outform DER 2>/dev/null |
      openssl dgst -sha256)
    key_public=$(openssl pkey -in "${ROOT}/${name}.key" -pubout -outform DER 2>/dev/null |
      openssl dgst -sha256)
    [[ ${cert_public} == "${key_public}" ]]
  done
  check_file=$(mktemp)
  trap 'rm -f -- "${check_file}"' EXIT
  /bin/bash "${AUTH_HELPER}" "${ROOT}" "${check_file}"
  if ! cmp -s -- "${check_file}" "${ROOT}/authorization.env"; then
    legacy_file=$(mktemp)
    grep '_PIN=' "${check_file}" > "${legacy_file}"
    if [[ ${CAMPUS_LINK_ALLOW_AUTHORIZATION_MIGRATION:-} != 1 ]] ||
      ! cmp -s -- "${legacy_file}" "${ROOT}/authorization.env"; then
      rm -f -- "${legacy_file}"
      echo 'Existing lab PKI authorization metadata does not match its certificates.' >&2
      exit 3
    fi
    rm -f -- "${legacy_file}"
  fi
  rm -f -- "${check_file}"
  trap - EXIT
  echo 'Reusing existing campus-link lab PKI.'
  exit 0
fi
if [[ -e ${ROOT} ]]; then
  echo 'Incomplete PKI directory exists; refusing to overwrite it.' >&2
  exit 2
fi
umask 077
install -d -m 0700 "${ROOT}"

make_ca() {
  local name=$1 cn=$2
  openssl genpkey -algorithm ED25519 -out "${ROOT}/${name}.key" >/dev/null 2>&1
  openssl req -x509 -new -key "${ROOT}/${name}.key" -days 365 -sha256 \
    -out "${ROOT}/${name}.crt" -subj "/CN=${cn}" \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
}

make_leaf() {
  local ca=$1 name=$2 cn=$3 eku=$4 san=${5:-}
  openssl genpkey -algorithm ED25519 -out "${ROOT}/${name}.key" >/dev/null 2>&1
  local -a req_args=(req -new -key "${ROOT}/${name}.key"
    -out "${ROOT}/${name}.csr" -subj "/CN=${cn}"
    -addext 'basicConstraints=critical,CA:FALSE'
    -addext 'keyUsage=critical,digitalSignature'
    -addext "extendedKeyUsage=${eku}")
  if [[ -n ${san} ]]; then
    req_args+=(-addext "subjectAltName=${san}")
  fi
  openssl "${req_args[@]}" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 14 -copy_extensions copy \
    -in "${ROOT}/${name}.csr" -CA "${ROOT}/${ca}.crt" \
    -CAkey "${ROOT}/${ca}.key" -CAcreateserial \
    -out "${ROOT}/${name}.crt" >/dev/null 2>&1
  rm -f "${ROOT}/${name}.csr"
}

make_ca control-ca campus-link-control-lab-ca
make_leaf control-ca relay-control gz.campus-link serverAuth \
  "DNS:gz.campus-link,URI:${CIRCUIT_URI}/relay/control"
make_leaf control-ca site-a-control site-a clientAuth \
  "URI:${CIRCUIT_URI}/site-a/control"
make_leaf control-ca site-b-control site-b clientAuth \
  "URI:${CIRCUIT_URI}/site-b/control"

make_ca data-ca campus-link-data-lab-ca
make_leaf data-ca site-a-data site-a.campus-link 'serverAuth,clientAuth' \
  "DNS:site-a.campus-link,URI:${CIRCUIT_URI}/site-a/data"
make_leaf data-ca site-b-data site-b.campus-link 'serverAuth,clientAuth' \
  "DNS:site-b.campus-link,URI:${CIRCUIT_URI}/site-b/data"

/bin/bash "${AUTH_HELPER}" "${ROOT}" "${ROOT}/authorization.env"

chmod 0600 "${ROOT}"/*.key
chmod 0644 "${ROOT}"/*.crt
chmod 0600 "${ROOT}/authorization.env"
install -m 0600 /dev/null "${ROOT}/.complete"
