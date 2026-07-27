# The Hash Laboratory

## Part 1 — The Avalanche Effect

### SHA-256

Hash `MedDefense`:

```bash
echo -n "MedDefense" | sha256sum
```

Result:

```text
39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098
```

Hash `MedDefense1`:

```bash
echo -n "MedDefense1" | sha256sum
```

Result:

```text
97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92
```

### SHA-256 comparison

- Hexadecimal characters different: **62 of 64**
    
- Bits different: **131 of 256**
    
- Percentage of bits changed: **51.17%**
    

---

### MD5

Hash `MedDefense`:

```bash
echo -n "MedDefense" | md5sum
```

Result:

```text
75d47fd4b4d183456d0f98fd9ba6ae4d
```

Hash `MedDefense1`:

```bash
echo -n "MedDefense1" | md5sum
```

Result:

```text
0d2aed72043f78c2935e61ba8520306d
```

### MD5 comparison

- Hexadecimal characters different: **30 of 32**
    
- Bits different: **71 of 128**
    
- Percentage of bits changed: **55.47%**
    

### Explanation

A one-character change produced completely different-looking outputs. This demonstrates the avalanche effect: a small input change should alter approximately half of the output bits.

Hexadecimal-character differences are not the most accurate measurement because one hexadecimal character represents four bits. The bit comparison therefore gives the better avalanche measurement.

---

# Part 2 — Hash Collisions and the Birthday Problem

## Number of possible outputs

| Hash algorithm | Output length | Possible unique outputs |
| -------------- | ------------: | ----------------------: |
| MD5            |      128 bits |               **2^128** |
| SHA-256        |      256 bits |               **2^256** |

A perfect 128-bit hash has approximately:

```text
2^128 possible outputs
```

A perfect 256-bit hash has approximately:

```text
2^256 possible outputs
```

## Birthday-attack resistance

A generic collision attack does not normally require testing every possible output. Because of the birthday problem, a collision in an ideal `n`-bit hash is expected after approximately:

```text
2^n/2 attempts
```

Therefore:

| Algorithm | Approximate generic collision work |
| --------- | ---------------------------------: |
| MD5       |                            **2⁶⁴** |
| SHA-256   |                           **2¹²⁸** |

A shorter hash has fewer possible outputs, so collisions become likely after fewer attempts. A birthday attack exploits the probability that any two inputs in a large collection will produce the same output, rather than trying to match one specific target hash. MD5 is even weaker than its 128-bit length suggests because practical collision attacks have been demonstrated, and it should not be used where collision resistance is required.

## Connection to Finding 018

Finding 018 showed that MedDefense still permits RC4 for Kerberos. Microsoft’s RC4-HMAC Kerberos construction uses HMAC-MD5, but the practical password risk is not primarily an MD5 collision attack. RC4 service tickets can be captured through Kerberoasting and tested offline against password guesses; weak service-account passwords may therefore be recovered without creating repeated login failures.

MedDefense should identify accounts and devices that still request RC4 tickets, reset old service-account passwords where needed to generate AES keys, and disable RC4 after compatibility testing.

---

# Part 3 — Rainbow Table Demonstration

## 1. Unsalted password

Run:

```bash
echo -n "password123" | md5sum
```

Result:

```text
482c811da5d5b4bc6d497ffa98491e38
```

### CrackStation result

The expected crackstation.net lookup is:

|Hash|Type|Result|
|---|---|---|
|`482c811da5d5b4bc6d497ffa98491e38`|MD5|**password123**|

This is a very common password and its unsalted MD5 digest is present in public password-hash lookup databases.

The hash does not need to be mathematically reversed. CrackStation calculates hashes for large collections of known passwords and searches its precomputed tables for a matching digest. CrackStation reports using a 15-billion-entry lookup table for MD5 and SHA-1.

---

## 2. Salted password

Run:

```bash
echo -n "s4lt9xQ2:password123" | md5sum
```

Result:

```text
6d537fa53f1db2c22b0451ef4ef9fbe8
```

### CrackStation result

The expected result is:

|Hash|Result|
|---|---|
|`6d537fa53f1db2c22b0451ef4ef9fbe8`|**Not found**|

The CrackStation form requires interactive browser submission, so this lookup could not be submitted automatically from this environment. Record the exact displayed result from your manual browser test; it should normally show that the salted value is not present in its table.

## Why the salt works

A salt changes the hash input, so the same password produces a different digest for each salt. An attacker can no longer use one precomputed table against every account and instead must test password guesses separately for each salt. Every user needs a unique, randomly generated salt so that two users with the same password do not have identical stored hashes.

However, salting does **not** make MD5 suitable for password storage. MD5 remains extremely fast, so an attacker can still perform a dictionary or brute-force attack against each salted hash; the password should also be processed using a slow password-hashing function.

---

# Part 4 — Key Stretching

## Bcrypt

Bcrypt is an adaptive password-hashing scheme based on an intentionally expensive Blowfish key schedule. It includes a salt and repeatedly performs expensive key-expansion operations, making each password guess slower than a simple MD5 or SHA-256 calculation.

Its **cost factor** controls the amount of work exponentially. Increasing the cost by one approximately doubles the computational work, allowing the configuration to be raised as hardware becomes faster.

### Important limitation

Traditional bcrypt implementations process a maximum of approximately 72 password bytes. Applications must use a reputable library and handle long-password behaviour correctly.

---

## PBKDF2

PBKDF2 applies a pseudorandom function—normally HMAC—repeatedly to the password, salt and intermediate values. This converts one quick hash calculation into many calculations, increasing the cost of every password guess.

The **iteration count** controls how many repeated operations are performed. A higher count increases the work for both the legitimate authentication server and an offline attacker, but PBKDF2 is primarily CPU-intensive rather than memory-hard. NIST SP 800-132 specifies PBKDF2 for password-based key derivation in storage applications.

---

## Argon2

Argon2 is designed specifically as a memory-hard password-hashing function. It forces an attacker to provide both processing time and substantial memory for each password guess, making large GPU, FPGA and ASIC attacks more expensive.

Argon2 has several adjustable parameters:

- **Memory cost:** amount of memory used
    
- **Time cost:** number of passes or iterations
    
- **Parallelism:** number of processing lanes
    

Argon2id combines data-independent and data-dependent memory access, balancing side-channel resistance with protection against time-memory trade-off attacks. RFC 9106 requires Argon2id support and describes it as the primary general-purpose variant.

---

## Comparison

| Algorithm | Main defence                                 | Main parameter               | Memory-hard | General assessment                                               |
| --------- | -------------------------------------------- | ---------------------------- | ----------- | ---------------------------------------------------------------- |
| Bcrypt    | Expensive adaptive key schedule              | Cost factor                  | Limited     | Secure legacy choice                                             |
| PBKDF2    | Many repeated HMAC operations                | Iteration count              | No          | Good where approved/FIPS-compatible implementations are required |
| Argon2id  | Expensive memory and processing requirements | Memory, time and parallelism | **Yes**     | Preferred modern application-password choice                     |

## Recommendation for MedDefense applications

MedDefense should use **Argon2id** for new application password storage. Its memory-hard design raises the financial and hardware cost of offline password cracking more effectively than a simple iteration-only construction.

The implementation should:

1. Generate a unique cryptographically random salt for every password.
    
2. Store the algorithm and parameter values with the password hash.
    
3. Select parameters through performance testing on MedDefense production hardware.
    
4. Rehash passwords after login when parameters become outdated.
    
5. Consider a separately protected pepper as an additional control.
    
6. Use MFA so password hashing is not the only account-protection layer.
    

Where MedDefense has a formal requirement to use a FIPS-validated cryptographic implementation, **PBKDF2-HMAC-SHA-256** may be the more appropriate compliance choice because Argon2 is not currently a FIPS-approved password derivation algorithm.

---

## What Active Directory uses

Active Directory does **not** use bcrypt, PBKDF2 or Argon2 as its default password verifier.

Microsoft Active Directory stores an **NT hash**, calculated by applying MD4 to the password. The NT hash is not salted, although the hash is additionally encrypted while stored inside the `NTDS.DIT` database.

### Is it adequate?

The NT hash is not adequate as a modern standalone password-storage construction because:

- MD4 is extremely fast.
    
- It has no per-user salt.
    
- Extracted hashes can be tested offline very quickly.
    
- NT hashes may also be abused directly in pass-the-hash attacks.
    
- Weak passwords remain vulnerable even if the database file itself was encrypted.
    

MedDefense generally cannot replace Active Directory’s internal NT-hash format with Argon2. It must reduce the risk through long passwords or managed service accounts, MFA, Credential Guard, protection of domain controllers, limitation of administrative access, disabling legacy NTLM and RC4 where possible, and monitoring for credential dumping.

Microsoft currently recommends auditing and removing RC4 dependencies because RC4 Kerberos service tickets enable offline Kerberoasting attacks.

---

# Part 5 — Integrity Verification Script

## File name

```text
3-hash_verify.sh
```

## Script

```bash
#!/usr/bin/env bash

# Verify a file against an expected SHA-256 digest.

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <file-path> <expected-sha256>" >&2
    exit 2
fi

file_path=$1
expected_hash=${2,,}

if [[ ! -f "$file_path" ]]; then
    echo "Error: file not found: $file_path" >&2
    exit 2
fi

if [[ ! "$expected_hash" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Error: expected hash must contain exactly 64 hexadecimal characters" >&2
    exit 2
fi

actual_hash=$(sha256sum -- "$file_path" | awk '{print $1}')

if [[ "$actual_hash" == "$expected_hash" ]]; then
    echo "INTEGRITY OK"
    exit 0
fi

echo "INTEGRITY FAILED - expected $expected_hash got $actual_hash"
exit 1
```

## Make it executable

```bash
chmod +x 3-hash_verify.sh
```

## Generate an expected hash

```bash
sha256sum patient.txt
```

Example:

```text
<hash-value>  patient.txt
```

Copy only the hash value.

## Successful verification

```bash
./3-hash_verify.sh patient.txt <expected-hash>
```

Output:

```text
INTEGRITY OK
```

Check the exit code:

```bash
echo $?
```

Result:

```text
0
```

## Failed verification

Modify the file:

```bash
echo "unauthorised change" >> patient.txt
```

Run the verification again with the original hash:

```bash
./3-hash_verify.sh patient.txt <original-expected-hash>
```

Output format:

```text
INTEGRITY FAILED - expected [hash] got [hash]
```

Check the exit code:

```bash
echo $?
```

Result:

```text
1
```

## Security meaning

A matching SHA-256 digest shows that the file is identical to the file from which the expected digest was calculated. It does not prove who created the file because an attacker who can modify both the file and the expected hash can replace both.

For authenticated integrity, MedDefense should obtain the expected hash through a trusted channel or use a digital signature or HMAC.
