#!/bin/bash
echo "$1" | sed 's/{xor}//'  | base64 -d | python3 -c '
import sys
data = sys.stdin.buffer.read()
key = 0x5F
print(bytes([b ^ key for b in data]).decode())
'
