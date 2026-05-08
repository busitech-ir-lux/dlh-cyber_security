#!/bin/bash
find "$1" -user root -perm -6000 -exec ls -ldb {} \; > /tmp/ckprim1
