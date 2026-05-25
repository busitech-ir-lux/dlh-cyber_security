#!/bin/bash
CONFIG="/etc/postfix/main.cf"
if grep -q "^smtpd_tls_security_level" "$CONFIG"; then
    grep "^smtpd_tls_security_level" "$CONFIG"
else
    echo "STARTTLS not configured"
fi
