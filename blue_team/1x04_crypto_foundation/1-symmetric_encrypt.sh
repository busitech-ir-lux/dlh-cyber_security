#!/bin/bash
# Encrypt a file with AES-256-CBC or AES-256-GCM using OpenSSL.
#
# Usage:
#   ./1-symmetric_encrypt.sh INPUT_FILE OUTPUT_FILE cbc
#   ./1-symmetric_encrypt.sh INPUT_FILE OUTPUT_FILE gcm
#
# CBC output:
#   OpenSSL "enc" format with a random salt and PBKDF2-derived key/IV.
#
# GCM output:
#   DER-encoded CMS EnvelopedData. OpenSSL generates an AES-256-GCM content
#   key and protects it for the certificate in MEDDEFENSE_GCM_CERT.
#   Default certificate: ./gcm-lab-cert.pem

set -Eeuo pipefail

readonly PROGRAM_NAME="${0##*/}"
readonly PBKDF2_ITERATIONS=200000

usage() {
    cat >&2 <<USAGE
Usage: $PROGRAM_NAME INPUT_FILE OUTPUT_FILE MODE

MODE:
  cbc   AES-256-CBC using openssl enc, PBKDF2 and a random salt
  gcm   AES-256-GCM using openssl cms and a recipient certificate

CBC automation:
  Set MEDDEFENSE_CBC_PASSFILE to a protected file containing the passphrase.

GCM certificate:
  Set MEDDEFENSE_GCM_CERT or place gcm-lab-cert.pem in the current directory.

Example:
  $PROGRAM_NAME patient.txt patient-cbc.enc cbc
  $PROGRAM_NAME patient.txt patient-gcm.cms gcm
USAGE
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 3 ]] || { usage; exit 2; }

input_file=$1
output_file=$2
mode=${3,,}

command -v openssl >/dev/null 2>&1 || fail "OpenSSL is not installed or not in PATH."
[[ -f "$input_file" ]] || fail "Input file does not exist or is not a regular file: $input_file"
[[ "$input_file" != "$output_file" ]] || fail "Input and output files must be different."

# Avoid leaving a partial output file when encryption fails.
temporary_output="${output_file}.tmp.$$"
trap 'rm -f -- "$temporary_output"' EXIT

case "$mode" in
    cbc)
        # By default OpenSSL securely prompts for the passphrase and asks for
        # confirmation. A protected passphrase file may be supplied for
        # automation through MEDDEFENSE_CBC_PASSFILE.
        pass_options=()
        if [[ -n "${MEDDEFENSE_CBC_PASSFILE:-}" ]]; then
            [[ -r "$MEDDEFENSE_CBC_PASSFILE" ]] || fail \
                "CBC passphrase file is not readable: $MEDDEFENSE_CBC_PASSFILE"
            pass_options=(-pass "file:$MEDDEFENSE_CBC_PASSFILE")
        fi

        openssl enc \
            -aes-256-cbc \
            -e \
            -salt \
            -pbkdf2 \
            -iter "$PBKDF2_ITERATIONS" \
            -md sha256 \
            "${pass_options[@]}" \
            -in "$input_file" \
            -out "$temporary_output"
        ;;

    gcm)
        gcm_certificate=${MEDDEFENSE_GCM_CERT:-gcm-lab-cert.pem}
        [[ -r "$gcm_certificate" ]] || fail \
            "GCM certificate not found: $gcm_certificate. Generate it first or set MEDDEFENSE_GCM_CERT."

        # The 'enc' command intentionally does not support GCM. CMS provides
        # a standard authenticated-encryption container and manages the GCM
        # content key, nonce and authentication tag.
        openssl cms \
            -encrypt \
            -binary \
            -aes-256-gcm \
            -in "$input_file" \
            -out "$temporary_output" \
            -outform DER \
            "$gcm_certificate"
        ;;

    *)
        usage
        fail "Unsupported mode '$mode'. Use cbc or gcm."
        ;;
esac

mv -- "$temporary_output" "$output_file"
trap - EXIT
printf 'Encrypted successfully: %s -> %s using AES-256-%s\n' \
    "$input_file" "$output_file" "${mode^^}"
