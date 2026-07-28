# 12. The Disk Encryption Lab

## Part 1 — LUKS Setup

`cryptsetup luksFormat`, `luksOpen`, and `luksClose` are the standard commands for creating, opening, and closing LUKS encrypted volumes.

### 1. Create the 500 MB virtual disk

```bash
dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
```

Representative output:

```text
500+0 records in
500+0 records out
524288000 bytes copied
```

### 2. Format the file with LUKS

```bash
sudo cryptsetup luksFormat encrypted_volume.img
```

Representative output:

```text
WARNING!
========
This will overwrite data on encrypted_volume.img irrevocably.

Are you sure? (Type 'yes' in capital letters): YES
Enter passphrase:
Verify passphrase:
```

### 3. Open the encrypted volume

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
```

Output:

```text
Enter passphrase for encrypted_volume.img:
```

No further output means success.

### 4. Create an ext4 filesystem

```bash
sudo mkfs.ext4 /dev/mapper/secure_vol
```

Representative output:

```text
Creating filesystem with 4k blocks
Filesystem UUID: [generated UUID]
Writing superblocks and filesystem accounting information: done
```

### 5. Mount the volume

```bash
sudo mkdir -p /mnt/secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
```

Output:

```text
No output on success
```

### 6. Write test data

```bash
echo "MedDefense encrypted backup test" | \
sudo tee /mnt/secure_vol/test.txt
```

Output:

```text
MedDefense encrypted backup test
```

Verify it:

```bash
sudo cat /mnt/secure_vol/test.txt
```

Output:

```text
MedDefense encrypted backup test
```

### 7. Unmount and close

```bash
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
```

Output:

```text
No output on success
```

---

## Part 2 — Verification

### Read the closed raw image

```bash
strings encrypted_volume.img | head -50
```

You may see LUKS header information or random-looking strings, but you should not see:

```text
MedDefense encrypted backup test
```

This proves that data stored inside the closed volume is not readable directly from the underlying disk image. An attacker who steals the image still needs the correct LUKS passphrase or key.

### Reopen and verify the data

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
```

Output:

```text
Enter passphrase for encrypted_volume.img:
```

Mount it:

```bash
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
```

Read the file:

```bash
sudo cat /mnt/secure_vol/test.txt
```

Output:

```text
MedDefense encrypted backup test
```

Close it again:

```bash
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
```

Output:

```text
No output on success
```

The data remained intact but was readable only while the encrypted volume was unlocked.

---

## Part 3 — LUKS Automation Script

### Create a 500 MB encrypted volume

```bash
./12-luks_manager.sh create encrypted_volume.img 500
```

### Open and mount it

```bash
./12-luks_manager.sh open \
encrypted_volume.img secure_vol /mnt/secure_vol
```

### Unmount and close it

```bash
./12-luks_manager.sh close \
secure_vol /mnt/secure_vol
```

---

## Part 4 — MedDefense Backup Encryption Design

### Encryption level

Use **volume-level encryption** for the NAS backup storage. What about file-level?

This protects all database dumps, medical records, configuration files, and backup metadata without requiring each application to encrypt individual files. Full-disk (full-disk) encryption would also protect the NAS operating system, but volume-level encryption provides better control over the dedicated backup area.

### Performance impact

The exact overhead cannot be calculated because the measured T1 AES timing results were not provided.

Use:

```text
Overhead % =
(encrypted backup time − unencrypted backup time)
÷ unencrypted backup time × 100
```

If the T1 AES throughput was higher than the NAS disk or network speed, the practical backup overhead should be low. MedDefense should confirm this using a full backup and restore test.

### Key storage

The encryption key must be stored in a separate:

- key-management system
    
- hardware security module
    
- protected backup-management server
    

It must not be stored on NAS-01 because an attacker who compromises the NAS could obtain both the encrypted backups and the key.

A protected recovery copy of the key should also be stored separately from the operational environment. NIST recommends independent protection and recovery arrangements for encryption keys and backup data.

### Key loss

If the encryption key and all recovery copies are lost, the backups are permanently unrecoverable.

MedDefense must therefore:

- maintain controlled recovery copies
    
- test key recovery
    
- document authorised key custodians
    
- protect the LUKS header and key backups
    

### Offsite replication

The cloud replica must also remain encrypted.

MedDefense should encrypt the backup before it leaves NAS-01 and retain control of the encryption key. The cloud provider may add its own storage encryption, but provider-managed encryption should not replace MedDefense-controlled encryption.

The offsite location must not store the plaintext key beside the encrypted backup.
