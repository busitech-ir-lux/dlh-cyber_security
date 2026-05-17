#!/bin/bash
john --wordlist=/usr/share/wordlists/rockyou.txt --type=raw-sha1 hashes.txt
