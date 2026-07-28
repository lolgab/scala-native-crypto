#!/bin/bash

# TODO: unfinished and unverified

set -eux -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"
source "${WORKING_DIR}/../common.sh"

ROOT_PKEY_FILE="${WORKING_DIR}/ca.pkey.pem"
ROOT_CERT_FILE="${WORKING_DIR}/ca.cert.pem"
ROOT_PASSWORD="test-password-for-ca"

CHAIN_SIZE=3
CHAIN_CERT_PREFIX="${WORKING_DIR}/chain"
CHAIN_BUNDLE_CERT_FILE="${WORKING_DIR}/bundle.cert.pem"
CHAIN_BUNDLE_PKEY_FILE="${WORKING_DIR}/bundle.pkey.pem"

PKCS12_FILE="${WORKING_DIR}/testing.p12"

# generate CA and private key
openssl req \
  -x509 -new -newkey rsa:1024 \
  -passout "pass:${ROOT_PASSWORD}" \
  -days 36500 -subj '/CN=Hey/O=Scala Native' \
  -extensions v3_ca \
  -keyform PEM -keyout "${ROOT_PKEY_FILE}" \
  -outform PEM -out "${ROOT_CERT_FILE}"

for i in $(seq 1 ${CHAIN_SIZE}); do
  # generate private key and CSR for each certificate in the chain
  openssl req \
    -new -newkey rsa:1024 -noenc \
    -subj "/CN=Hey${i}/O=Scala Native" \
    -extensions v3_ca \
    -keyform PEM -keyout "${CHAIN_CERT_PREFIX}-${i}.pkey.pem" \
    -outform PEM -out "${CHAIN_CERT_PREFIX}-${i}.csr.pem"

  if [[ $i -eq 1 ]]; then
    # the first certificate in the chain is signed by the CA with password
    openssl req \
      -x509 \
      -days 36500 -copy_extensions copy \
      -CA "${ROOT_CERT_FILE}" -CAkey "${ROOT_PKEY_FILE}" -passin "pass:${ROOT_PASSWORD}" \
      -in "${CHAIN_CERT_PREFIX}-${i}.csr.pem" \
      -key "${CHAIN_CERT_PREFIX}-${i}.pkey.pem" \
      -outform PEM -out "${CHAIN_CERT_PREFIX}-${i}.cert.pem"
  else
    # subsequent certificates are signed by the previous certificate in the chain
    openssl req \
      -x509 \
      -days 36500 -copy_extensions copy \
      -CA "${CHAIN_CERT_PREFIX}-$((i - 1)).cert.pem" \
      -CAkey "${CHAIN_CERT_PREFIX}-$((i - 1)).pkey.pem" \
      -in "${CHAIN_CERT_PREFIX}-${i}.csr.pem" \
      -key "${CHAIN_CERT_PREFIX}-${i}.pkey.pem" \
      -outform PEM -out "${CHAIN_CERT_PREFIX}-${i}.cert.pem"
  fi
done

cat "${CHAIN_CERT_PREFIX}-${CHAIN_SIZE}.cert.pem" > "${CHAIN_BUNDLE_CERT_FILE}"
for i in $(seq "$((CHAIN_SIZE - 1))" -1 1); do
  cat "${CHAIN_CERT_PREFIX}-${i}.cert.pem" >> "${CHAIN_BUNDLE_CERT_FILE}"
done
# cat "${ROOT_CERT_FILE}" >> "${CHAIN_BUNDLE_CERT_FILE}"
cat "${CHAIN_CERT_PREFIX}-${CHAIN_SIZE}.pkey.pem" > "${CHAIN_BUNDLE_PKEY_FILE}"

  # -chain \
openssl pkcs12 \
  -export \
  -CAfile "${ROOT_CERT_FILE}" \
  -in "${CHAIN_BUNDLE_CERT_FILE}" -inkey "${CHAIN_BUNDLE_PKEY_FILE}" \
  -passout "pass:${PKCS12_PASSWORD}" \
  -out "${PKCS12_FILE}"

# Cleanup intermediate files
rm "${CHAIN_CERT_PREFIX}"-*.cert.pem "${CHAIN_CERT_PREFIX}"-*.pkey.pem "${CHAIN_CERT_PREFIX}"-*.csr.pem
