#!/bin/bash
openssl enc -aes-256-$3 -salt -pbkdf2 -iter 200000 -in $1 -out $2

