#!/bin/bash

set -eu -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"

# BADSSL_CLIENT_PEM_FILE="${WORKING_DIR}/badssl.com-client.pem"
BADSSL_CLIENT_PKCS12_FILE="${WORKING_DIR}/badssl.com-client.p12"
BADSSL_CLIENT_PASSWORD="badssl.com"

BADSSL_CLIENT_CRT_FILE="${WORKING_DIR}/badssl.com-client.crt.pem"
BADSSL_CLIENT_PRIVATEKEY_FILE="${WORKING_DIR}/badssl.com.private.pem"

# if [[ ! -f "${BADSSL_CLIENT_PEM_FILE}" ]]; then
#   echo "badssl.com PEM file ${BADSSL_CLIENT_PEM_FILE} does not exist."
#   echo "  Downloading from badssl.com now ..."
#   curl -fsSL -o "${BADSSL_CLIENT_PEM_FILE}" https://badssl.com/certs/badssl.com-client.pem
# fi
if [[ ! -f "${BADSSL_CLIENT_PKCS12_FILE}" ]]; then
  echo "badssl.com PKCS12 file ${BADSSL_CLIENT_PKCS12_FILE} does not exist."
  echo "  Downloading from badssl.com now ..."
  curl -fsSL -o "${BADSSL_CLIENT_PKCS12_FILE}" https://badssl.com/certs/badssl.com-client.p12
fi

# no ca cert in the badssl PKCS12 file, so we skip it

# extract client cert from badssl PKCS12 file
openssl pkcs12 -legacy \
  -clcerts -nokeys \
  -passin "pass:${BADSSL_CLIENT_PASSWORD}" \
  -in "${BADSSL_CLIENT_PKCS12_FILE}" \
  -out "${BADSSL_CLIENT_CRT_FILE}"

# extract private key from badssl PKCS12 file
openssl pkcs12 -legacy \
  -passin "pass:${BADSSL_CLIENT_PASSWORD}" \
  -passout "pass:${BADSSL_CLIENT_PASSWORD}" \
  -nocerts \
  -in "${BADSSL_CLIENT_PKCS12_FILE}" \
  -out "${BADSSL_CLIENT_PRIVATEKEY_FILE}"
