#!/usr/bin/env bash
set -euo pipefail

readonly ROOT=/etc/campus-link/pki
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
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 14 \
    -keyout "${ROOT}/${name}.key" -out "${ROOT}/${name}.crt" \
    -subj "/CN=${cn}" >/dev/null 2>&1
}

make_leaf() {
  local ca=$1 name=$2 cn=$3 eku=$4 san=${5:-}
  local -a req_args=(req -new -newkey rsa:3072 -nodes -sha256
    -keyout "${ROOT}/${name}.key" -out "${ROOT}/${name}.csr"
    -subj "/CN=${cn}" -addext "extendedKeyUsage=${eku}")
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
make_leaf control-ca relay-control gz.campus-link serverAuth DNS:gz.campus-link
make_leaf control-ca site-a-control site-a clientAuth
make_leaf control-ca site-b-control site-b clientAuth

make_ca data-ca campus-link-data-lab-ca
make_leaf data-ca site-a-data site-a clientAuth
make_leaf data-ca site-b-data site-b.campus-link 'serverAuth,clientAuth' DNS:site-b.campus-link

chmod 0600 "${ROOT}"/*.key
chmod 0644 "${ROOT}"/*.crt
touch "${ROOT}/.complete"
