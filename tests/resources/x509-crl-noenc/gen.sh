#!/bin/bash

set -eu -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"

PRIVATE_KEY_FILE="${WORKING_DIR}/private.pem"
CERTIFICATE_FILE="${WORKING_DIR}/certificate.pem"
CRL_FILE="${WORKING_DIR}/crl.pem"

PASSWORD="test-password-for-private-key"

openssl req \
  -x509 -new -newkey rsa:1024 \
  -passout "pass:${PASSWORD}" \
  -days 36500 -subj '/CN=Hey/O=Scala Native' \
  -keyform PEM -keyout "${PRIVATE_KEY_FILE}" \
  -outform PEM -out "${CERTIFICATE_FILE}"
