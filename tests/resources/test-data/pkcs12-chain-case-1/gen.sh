#!/bin/bash

set -eux -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"
source "${WORKING_DIR}/../common.sh"

ROOT_PKEY_FILE="${WORKING_DIR}/root.pkey.pem"
ROOT_CERT_FILE="${WORKING_DIR}/root.cert.pem"
ROOT_CONF_FILE="${WORKING_DIR}/root.conf"
ROOT_PASSWORD="test-password"
# generate root CA and private key
openssl req \
  -x509 -newkey rsa:1024 \
  -passout pass:${ROOT_PASSWORD} \
  -days 36500 -subj "${SUBJECT}" \
  -extensions v3_ca \
  -config "${ROOT_CONF_FILE}" \
  -keyout "${ROOT_PKEY_FILE}" \
  -out "${ROOT_CERT_FILE}"

INTERM_PKEY_FILE="${WORKING_DIR}/interm.key.pem"
INTERM_PASSWORD="${ROOT_PASSWORD}-for-interm"
INTERM_CONF_FILE="${WORKING_DIR}/interm.conf"
INTERM_CSR_FILE="${WORKING_DIR}/interm.csr.pem"
INTERM_CERT_FILE="${WORKING_DIR}/interm.crt.pem"
# generate private key and CSR for the intermediate certificate
openssl req \
  -newkey rsa:1024 \
  -subj "${SUBJECT}" \
  -passout "pass:${INTERM_PASSWORD}" \
  -keyout "${INTERM_PKEY_FILE}" \
  -out "${INTERM_CSR_FILE}"
# sign the intermediate certificate with the CA
openssl req \
  -x509 \
  -days 36500 -copy_extensions copy \
  -extensions v3_intermediate_ca \
  -config "${INTERM_CONF_FILE}" \
  -CA "${ROOT_CERT_FILE}" -CAkey "${ROOT_PKEY_FILE}" -passin "pass:${ROOT_PASSWORD}" \
  -in "${INTERM_CSR_FILE}" \
  -out "${INTERM_CERT_FILE}"

CERT_PKEY_FILE="${WORKING_DIR}/cert.key.pem"
CERT_CSR_FILE="${WORKING_DIR}/cert.csr.pem"
CERT_CERT_FILE="${WORKING_DIR}/cert.crt.pem"
CERT_CONF_FILE="${WORKING_DIR}/cert.conf"
CERT_PASSWORD="${PKCS12_PASSWORD}"
# generate private key and CSR for the leaf certificate
openssl req \
  -newkey rsa:1024 \
  -subj "/CN=Hey/O=Scala Native" \
  -passout "pass:${CERT_PASSWORD}" \
  -keyout "${CERT_PKEY_FILE}" \
  -out "${CERT_CSR_FILE}"
# sign the leaf certificate with the intermediate certificate
openssl req \
  -x509 \
  -days 36500 -copy_extensions copy \
  -extensions v3_leaf \
  -config "${CERT_CONF_FILE}" \
  -CA "${INTERM_CERT_FILE}" -CAkey "${INTERM_PKEY_FILE}" -passin "pass:${INTERM_PASSWORD}" \
  -in "${CERT_CSR_FILE}" \
  -out "${CERT_CERT_FILE}"

# verify the certificate chain
openssl verify \
  -show_chain \
  -CAfile "${ROOT_CERT_FILE}" \
  -untrusted "${INTERM_CERT_FILE}" \
  "${CERT_CERT_FILE}"

PKCS12_FILE="${WORKING_DIR}/${PKCS12_FILENAME}"

openssl pkcs12 \
  -export \
  -chain \
  -CAfile "${ROOT_CERT_FILE}"  \
  -untrusted "${INTERM_CERT_FILE}"  \
  -name "chain-end" \
  -caname "chain-interm" \
  -caname "chain-ca" \
  -in "${CERT_CERT_FILE}" -inkey "${CERT_PKEY_FILE}" -passin "pass:${CERT_PASSWORD}" \
  -out "${PKCS12_FILE}" -passout "pass:${PKCS12_PASSWORD}"
