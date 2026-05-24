#!/bin/bash
sudo find / -xdev -type d -perm -0002 -exec chmod 755 2>/dev/null
