#!/usr/bin/env bash
set -euo pipefail

readonly ROOT=${1:?usage: pki-public-authorizations.sh PKI_ROOT OUTPUT_FILE}
readonly OUTPUT=${2:?usage: pki-public-authorizations.sh PKI_ROOT OUTPUT_FILE}
readonly CIRCUIT_URI=spiffe://campus-link/home-pair-1

[[ ${ROOT} == /* && ${ROOT} != / ]]
[[ ${OUTPUT} == /* && ${OUTPUT} != / ]]
[[ -d ${ROOT} && ! -L ${ROOT} ]]
readonly OUTPUT_PARENT=$(dirname "${OUTPUT}")
[[ -d ${OUTPUT_PARENT} && ! -L ${OUTPUT_PARENT} ]]

assert_public_certificate() {
  local cert=$1 size
  [[ -f ${cert} && ! -L ${cert} ]] || return 1
  size=$(stat -c '%s' "${cert}") || return 1
  [[ ${size} =~ ^[1-9][0-9]*$ && ${size} -le 1048576 ]] || return 1
  # OpenSSL emits one deterministic PEM encoding for the parsed DER. A byte
  # comparison rejects DER input, extra PEM blocks, prose, whitespace, and
  # binary/private-material prefixes or suffixes.
  cmp -s -- "${cert}" <(openssl x509 -in "${cert}" -outform PEM 2>/dev/null) || return 1
}

spki_pin() {
  local cert=$1 encoded pin
  assert_public_certificate "${cert}" || return 1
  encoded=$(openssl x509 -in "${cert}" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null |
    openssl dgst -sha256 -binary |
    openssl base64 -A) || return 1
  pin="sha256/${encoded}"
  [[ ${pin} =~ ^sha256/[A-Za-z0-9+/]{43}=$ ]] || return 1
  printf '%s' "${pin}"
}

relay_control_pin=$(spki_pin "${ROOT}/relay-control.crt")
site_a_control_pin=$(spki_pin "${ROOT}/site-a-control.crt")
site_b_control_pin=$(spki_pin "${ROOT}/site-b-control.crt")
site_a_data_pin=$(spki_pin "${ROOT}/site-a-data.crt")
site_b_data_pin=$(spki_pin "${ROOT}/site-b-data.crt")
readonly relay_control_pin site_a_control_pin site_b_control_pin site_a_data_pin site_b_data_pin

declare -A seen=()
for pin in \
  "${relay_control_pin}" \
  "${site_a_control_pin}" \
  "${site_b_control_pin}" \
  "${site_a_data_pin}" \
  "${site_b_data_pin}"; do
  [[ -z ${seen[${pin}]+present} ]]
  seen[${pin}]=1
done

tmp=$(mktemp "${OUTPUT_PARENT}/.authorization.env.XXXXXX")
cleanup() {
  rm -f -- "${tmp}"
}
trap cleanup EXIT
umask 077
cat > "${tmp}" <<EOF
RELAY_CONTROL_URI=${CIRCUIT_URI}/relay/control
RELAY_CONTROL_PIN=${relay_control_pin}
SITE_A_CONTROL_URI=${CIRCUIT_URI}/site-a/control
SITE_A_CONTROL_PIN=${site_a_control_pin}
SITE_B_CONTROL_URI=${CIRCUIT_URI}/site-b/control
SITE_B_CONTROL_PIN=${site_b_control_pin}
SITE_A_DATA_URI=${CIRCUIT_URI}/site-a/data
SITE_A_DATA_PIN=${site_a_data_pin}
SITE_B_DATA_URI=${CIRCUIT_URI}/site-b/data
SITE_B_DATA_PIN=${site_b_data_pin}
EOF
chmod 0600 "${tmp}"
mv -fT -- "${tmp}" "${OUTPUT}"
trap - EXIT
