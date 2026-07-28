#!/bin/bash

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out portal_key.pem
chmod 600 portal_key.pem
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
openssl req -text -noout -verify -in portal.csr
