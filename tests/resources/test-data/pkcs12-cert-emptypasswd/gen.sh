#!/bin/bash

set -eu -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"

PRIVATE_KEY_FILE="${WORKING_DIR}/private.pem"
CERTIFICATE_FILE="${WORKING_DIR}/certificate.pem"
PKCS12_FILE="${WORKING_DIR}/testing.p12"

openssl req \
  -x509 -new -newkey rsa:1024 \
  -noenc \
  -days 36500 -subj '/CN=Hey/O=Scala Native' \
  -keyform PEM -keyout "${PRIVATE_KEY_FILE}" \
  -outform PEM -out "${CERTIFICATE_FILE}"

openssl pkcs12 \
  -export -passout pass: \
  -in "${CERTIFICATE_FILE}" -inkey "${PRIVATE_KEY_FILE}" \
  -out "${PKCS12_FILE}"
