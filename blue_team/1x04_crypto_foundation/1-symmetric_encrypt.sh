#!/bin/bash
## If the input includes CBC, this script encrypts in cbc mode, and if it
## includes gcm, it encrypts in gcm mode
if [ $3 == cbc ]; then
	openssl enc -aes-256-$3 -salt -pbkdf2 -iter 200000 -in $1 -out $2
elif [ $3 == gcm ]; then
	openssl cms -encrypt -binary -aes-256-$3 -in $1 -out $2.cms -outform DER gcm-lab-cert.pem
fi
