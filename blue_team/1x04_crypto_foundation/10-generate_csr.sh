#!/bin/bash

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out portal_key.pem
chmod 600 portal_key.pem

openssl req -new -key portal_key.pem -out portal.csr \
  -subj "/C=US/ST=Massachusetts/L=Boston/O=MedDefense Health Systems/OU=Information Technology/CN=portal.meddefense.local" \
  -addext "subjectAltName=DNS:portal.meddefense.local,DNS:patient.meddefense.local" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"

openssl req -text -noout -verify -in portal.csr
