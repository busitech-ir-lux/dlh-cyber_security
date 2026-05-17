#!/bin/bash
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt $1 && john --show hash.txt > 4-password.txt
