#!/bin/bash
if [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$2" ]; then echo "test_file: OK"
fi

