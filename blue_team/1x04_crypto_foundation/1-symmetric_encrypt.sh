#!/bin/bash
## If the input includes CBC, this script encrypts in cbc mode, and if it
## includes gcm, it encrypts in gcm mode
openssl enc -aes-256-$3 -salt -pbkdf2 -iter 200000 -in $1 -out $2

