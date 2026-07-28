#!/bin/bash

if [ "$1" = "sign" ]; then
    openssl dgst -sha256 -sign "$3" -out "$2.sig" "$2"

elif [ "$1" = "verify" ]; then
    openssl dgst -sha256 -verify "$4" -signature "$3" "$2"

else
    echo "Usage:"
    echo "$0 sign <file> <private_key>"
    echo "$0 verify <file> <signature_file> <public_key>"
fi
