#!/bin/bash
inHash=$2
calHash=$(sha256sum $1 | cut -d ' ' -f1)
if [ $inHash == $calHash ]; then
	echo "INTEGRITY OK"; exit 0
else echo "INTEGRITY FAILED - EXPECTED {$calHash} got {$inHash}"; exit 1
fi

