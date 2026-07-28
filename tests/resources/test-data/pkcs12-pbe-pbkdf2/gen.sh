#!/bin/bash

# Generates PBE PKCS12 keystores with PBKDF2 and different MAC digest algorithms.

set -eux -o pipefail

WORKING_DIR=$(dirname "$(realpath "$0")")
echo "Current working dir is ${WORKING_DIR}"

source "${WORKING_DIR}/../common.sh"

NAME=test-trust

MAC_DIGESTS=(
  "sha256" # hmacsha256
  "sha384" # hmacsha384
  "sha512" # hmacsha512
)
PBE_OPTIONS=(
  "aes-128-cbc"
  "aes-256-cbc"
)

for md in "${MAC_DIGESTS[@]}"; do
  for pbe in "${PBE_OPTIONS[@]}"; do

    DATA_DIR="${WORKING_DIR}/${md}-${pbe}"
    mkdir -p "${DATA_DIR}"

    CERT_FILE="${DATA_DIR}/${NAME}.cert.pem"
    PKEY_FILE="${DATA_DIR}/${NAME}.pkey.pem"
    PKCS_FILE="${DATA_DIR}/${PKCS12_FILENAME}"

    # Create test private key and self signed ca
    openssl req \
      -x509 -newkey rsa:1024 \
      -sha256 -nodes \
      -days 36500 -subj "${SUBJECT}" \
      -keyout "${PKEY_FILE}" \
      -out "${CERT_FILE}"

    # Wrap up content in pkcs12
    openssl pkcs12 \
      -export \
      -certpbe "${pbe}" -keypbe "${pbe}" \
      -macalg "${md}" \
      -name "${NAME}" \
      -in "${CERT_FILE}" -inkey "${PKEY_FILE}" \
      -passout "pass:${PKCS12_PASSWORD}" -out "${PKCS_FILE}"

  done
done
