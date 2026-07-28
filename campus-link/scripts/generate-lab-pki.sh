#!/usr/bin/env bash
set -euo pipefail

readonly ROOT=${CAMPUS_LINK_PKI_ROOT:-/etc/campus-link/pki}
readonly CIRCUIT_URI=spiffe://campus-link/home-pair-1
[[ ${ROOT} == /* && ${ROOT} != / && ${ROOT} != /etc ]]
if [[ -e ${ROOT}/.complete ]]; then
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

spki_pin() {
  openssl x509 -in "$1" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null |
    openssl dgst -sha256 -binary |
    openssl base64 -A
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

cat > "${ROOT}/authorization.env" <<EOF
RELAY_CONTROL_PIN=sha256/$(spki_pin "${ROOT}/relay-control.crt")
SITE_A_CONTROL_PIN=sha256/$(spki_pin "${ROOT}/site-a-control.crt")
SITE_B_CONTROL_PIN=sha256/$(spki_pin "${ROOT}/site-b-control.crt")
SITE_A_DATA_PIN=sha256/$(spki_pin "${ROOT}/site-a-data.crt")
SITE_B_DATA_PIN=sha256/$(spki_pin "${ROOT}/site-b-data.crt")
EOF

chmod 0600 "${ROOT}"/*.key
chmod 0644 "${ROOT}"/*.crt
chmod 0600 "${ROOT}/authorization.env"
touch "${ROOT}/.complete"
