#!/bin/bash
find "$1" -type f -mtime -1 -perm -6000 -exec ls -lo {} \; 2> /dev/null
