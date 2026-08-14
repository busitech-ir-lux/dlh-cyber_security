#!/bin/bash
sudo visudo echo "$1 ALL=(root) NOPASSWD: ALL" >> /etc/sudoers
