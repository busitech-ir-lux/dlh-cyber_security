#!/bin/bash
echo "$(echo $1$(openssl rand -hex 8) | openssl dgst -sha512)" > ./3_hash.txt
