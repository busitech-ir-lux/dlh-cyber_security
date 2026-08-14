#!/bin/bash
ps aux | grep "^$1[[:space:]]" | grep -v "[[:space:]]0[[:space:]]\+0[[:space:]]"
