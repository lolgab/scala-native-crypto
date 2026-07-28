#!/bin/bash

set -eu -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"

PRIVATE_KEY_FILE="${WORKING_DIR}/private.pem"
PUBLIC_KEY_FILE="${WORKING_DIR}/public.pem"
CERTIFICATE_FILE="${WORKING_DIR}/certificate.pem"

openssl req \
  -x509 -new -newkey rsa:1024 \
  -noenc \
  -days 36500 -subj '/CN=Hey/O=Scala Native' \
  -keyout "${PRIVATE_KEY_FILE}" \
  -out "${CERTIFICATE_FILE}"

# extract public key from the certificate
openssl x509 \
  -in "${CERTIFICATE_FILE}" \
  -out "${PUBLIC_KEY_FILE}" \
  -pubkey -nocert
