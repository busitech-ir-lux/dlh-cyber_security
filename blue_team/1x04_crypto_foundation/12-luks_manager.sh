#!/bin/bash

if [ "$1" = "create" ]; then
    dd if=/dev/zero of="$2" bs=1M count="$3"
    sudo cryptsetup luksFormat "$2"
    sudo cryptsetup luksOpen "$2" secure_vol
    sudo mkfs.ext4 /dev/mapper/secure_vol
    sudo cryptsetup luksClose secure_vol

elif [ "$1" = "open" ]; then
    sudo cryptsetup luksOpen "$2" "$3"
    sudo mkdir -p "$4"
    sudo mount "/dev/mapper/$3" "$4"

elif [ "$1" = "close" ]; then
    sudo umount "$3"
    sudo cryptsetup luksClose "$2"

else
    echo "Usage:"
    echo "$0 create <image_file> <size_MB>"
    echo "$0 open <image_file> <mapper_name> <mount_point>"
    echo "$0 close <mapper_name> <mount_point>"
fi
