#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
readonly HELPER=${REPO_ROOT}/campus-link/scripts/pki-public-authorizations.sh
tmp=$(mktemp -d)
cleanup() {
  rm -rf -- "${tmp}"
}
trap cleanup EXIT
readonly PUBLIC_ROOT=${tmp}/public
readonly OUTPUT=${tmp}/authorization.env
mkdir "${PUBLIC_ROOT}"

# Construct only the public inputs expected by production authorization
# assembly. Private signing material lives outside PUBLIC_ROOT and is removed
# before the helper runs.
for name in relay-control site-a-control site-b-control site-a-data site-b-data; do
  openssl genpkey -algorithm ED25519 -out "${tmp}/issuer.key" >/dev/null 2>&1
  subject="/CN=${name}"
  if [[ $(uname -s) == MINGW* ]]; then
    subject="//CN=${name}"
  fi
  openssl req -x509 -new -key "${tmp}/issuer.key" -days 1 \
    -out "${PUBLIC_ROOT}/${name}.crt" -subj "${subject}" >/dev/null 2>&1
  rm -f -- "${tmp}/issuer.key"
done
[[ -z $(find "${PUBLIC_ROOT}" -mindepth 1 -maxdepth 1 ! -name '*.crt' -print -quit) ]]
[[ $(find "${PUBLIC_ROOT}" -mindepth 1 -maxdepth 1 -type f | wc -l) -eq 5 ]]

/bin/bash "${HELPER}" "${PUBLIC_ROOT}" "${OUTPUT}"

[[ -f ${OUTPUT} && ! -L ${OUTPUT} ]]
if [[ $(uname -s) != MINGW* ]]; then
  [[ $(stat -c '%a' "${OUTPUT}") == 600 ]]
fi
[[ $(wc -l < "${OUTPUT}") -eq 10 ]]
! grep -Eq 'PRIVATE|CERTIFICATE|\.key|CA_' "${OUTPUT}"
! grep -Eq '\.key|CAkey|genpkey' "${HELPER}"
diff -u <(cut -d= -f1 "${OUTPUT}") <(printf '%s\n' \
  RELAY_CONTROL_URI RELAY_CONTROL_PIN \
  SITE_A_CONTROL_URI SITE_A_CONTROL_PIN \
  SITE_B_CONTROL_URI SITE_B_CONTROL_PIN \
  SITE_A_DATA_URI SITE_A_DATA_PIN \
  SITE_B_DATA_URI SITE_B_DATA_PIN)

# A public certificate input contaminated with private material must fail
# closed even though OpenSSL's x509 reader would otherwise ignore the suffix.
cp -- "${PUBLIC_ROOT}/relay-control.crt" "${tmp}/relay-control.clean.crt"
openssl genpkey -algorithm ED25519 -out "${tmp}/contamination.key" >/dev/null 2>&1
cat "${tmp}/contamination.key" >> "${PUBLIC_ROOT}/relay-control.crt"
if /bin/bash "${HELPER}" "${PUBLIC_ROOT}" "${tmp}/contaminated.env"; then
  echo 'Public authorization assembly accepted private material in a certificate input.' >&2
  exit 1
fi
[[ ! -e ${tmp}/contaminated.env ]]

cp -- "${tmp}/relay-control.clean.crt" "${PUBLIC_ROOT}/relay-control.crt"
printf '\0junk-suffix' >> "${PUBLIC_ROOT}/relay-control.crt"
if /bin/bash "${HELPER}" "${PUBLIC_ROOT}" "${tmp}/junk.env"; then
  echo 'Public authorization assembly accepted a certificate with a junk suffix.' >&2
  exit 1
fi
[[ ! -e ${tmp}/junk.env ]]

openssl x509 -in "${tmp}/relay-control.clean.crt" -outform DER \
  -out "${PUBLIC_ROOT}/relay-control.crt"
if /bin/bash "${HELPER}" "${PUBLIC_ROOT}" "${tmp}/der.env"; then
  echo 'Public authorization assembly accepted non-canonical DER input.' >&2
  exit 1
fi
[[ ! -e ${tmp}/der.env ]]

echo 'PASS public authorization assembly uses public certificates only'
