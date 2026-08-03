#!/bin/bash
set -euo pipefail

SUID_OK="/usr/bin/passwd /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd /usr/bin/newgrp /usr/bin/su /usr/bin/sudo /usr/bin/mount /usr/bin/umount /usr/bin/pkexec /usr/lib/openssh/ssh-keysign"
SGID_OK="/usr/bin/chage /usr/bin/expiry /usr/bin/crontab /usr/bin/wall /usr/bin/write /usr/bin/ssh-agent"

SUID_FIXED=0
SGID_FIXED=0
WW_FIXED=0

# ---------- SUID ----------
mapfile -t SUID_FILES < <(
    find / -xdev -type f -perm -4000 2>/dev/null
)

echo "Found ${#SUID_FILES[@]} SUID binaries"

WHITELISTED=0
for file in "${SUID_FILES[@]}"; do
    if [[ " $SUID_OK " == *" $file "* ]]; then
        ((WHITELISTED+=1))
    else
        chmod u-s "$file"
        echo "  $file   [SUID REMOVED]"
        ((SUID_FIXED+=1))
    fi
done

echo "Whitelisted: $WHITELISTED"
echo "Non-whitelisted: $SUID_FIXED"

# ---------- SGID ----------
mapfile -t SGID_FILES < <(
    find / -xdev -type f -perm -2000 2>/dev/null
)

echo "Found ${#SGID_FILES[@]} SGID binaries"

WHITELISTED=0
for file in "${SGID_FILES[@]}"; do
    if [[ " $SGID_OK " == *" $file "* ]]; then
        ((WHITELISTED+=1))
    else
        chmod g-s "$file"
        echo "  $file   [SGID REMOVED]"
        ((SGID_FIXED+=1))
    fi
done

echo "Whitelisted: $WHITELISTED"
echo "Non-whitelisted: $SGID_FIXED"

# ---------- World-writable ----------
mapfile -t WORLD_WRITABLE < <(
    find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /dev -prune -o \
        -perm -0002 -print 2>/dev/null
)

echo "Found ${#WORLD_WRITABLE[@]} world-writable files"

for file in "${WORLD_WRITABLE[@]}"; do
    chmod o-w "$file"
    echo "  $file   [FIXED]"
    ((WW_FIXED+=1))
done

# ---------- Mount hardening ----------
for dir in /tmp /var/tmp /dev/shm; do
    if ! mountpoint -q "$dir"; then
        mount --bind "$dir" "$dir"
    fi

    mount -o remount,bind,noexec,nosuid,nodev "$dir"

    options=$(findmnt -no OPTIONS "$dir")

    if [[ "$options" == *noexec* &&
          "$options" == *nosuid* &&
          "$options" == *nodev* ]]; then
        printf "%-10s noexec,nosuid,nodev  [OK]\n" "$dir:"
    else
        printf "%-10s noexec,nosuid,nodev  [FAIL]\n" "$dir:"
    fi
done

# ---------- Cron access ----------
printf "root\nmedadmin\nsysadmin\n" > /etc/cron.allow
rm -f /etc/cron.deny
chmod 600 /etc/cron.allow

echo "Cron access restricted to root, medadmin and sysadmin"

echo "SUID remediated: $SUID_FIXED | SGID remediated: $SGID_FIXED | World-writable fixed: $WW_FIXED"
