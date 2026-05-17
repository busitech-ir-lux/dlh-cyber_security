#!/bin/bash
john --wordlist=/usr/share/wordlists/rockyou.txt --type=raw-md5 $1 && john --show $1 > 4-password.txt   
