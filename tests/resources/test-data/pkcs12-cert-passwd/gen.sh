#!/bin/bash

set -eux -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"
source "${WORKING_DIR}/../common.sh"

PRIVATE_KEY_FILE="${WORKING_DIR}/private.pem"
CERTIFICATE_FILE="${WORKING_DIR}/certificate.pem"
PKCS12_FILE="${WORKING_DIR}/${PKCS12_FILENAME}"

openssl req \
  -x509 -new -newkey rsa:1024 \
  -passout "pass:${PKCS12_PASSWORD}" \
  -days 36500 -subj "${SUBJECT}" \
  -keyout "${PRIVATE_KEY_FILE}" \
  -out "${CERTIFICATE_FILE}"

openssl pkcs12 \
  -export \
  -passin "pass:${PKCS12_PASSWORD}" \
  -in "${CERTIFICATE_FILE}" -inkey "${PRIVATE_KEY_FILE}" \
  -out "${PKCS12_FILE}" -passout "pass:${PKCS12_PASSWORD}"
