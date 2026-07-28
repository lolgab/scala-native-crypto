#!/bin/bash

set -eu -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"

PRIVATE_KEY_FILE="${WORKING_DIR}/private.pem"
PUBLIC_KEY_FILE="${WORKING_DIR}/public.pem"
CERTIFICATE_FILE="${WORKING_DIR}/certificate.pem"

PKCS12_PASSWORD="test-password-for-private-key"

openssl req \
  -x509 -new -newkey rsa:1024 \
  -passout "pass:${PKCS12_PASSWORD}" \
  -days 36500 -subj '/CN=Hey/O=Scala Native' \
  -keyform PEM -keyout "${PRIVATE_KEY_FILE}" \
  -outform PEM -out "${CERTIFICATE_FILE}"

# extract public key from the certificate
openssl x509 \
  -inform PEM -in "${CERTIFICATE_FILE}" \
  -outform PEM -out "${PUBLIC_KEY_FILE}" \
  -pubkey -nocert
