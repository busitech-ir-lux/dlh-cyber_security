# 11. The TLS Audit

## Part 1 — SSL Labs Analysis

### Website 1: cloudflare-dns.com

| Item                | Result                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------- |
| **Overall grade**   | **A+**                                                                                                  |
| **Protocols**       | TLS 1.2 and TLS 1.3; no TLS 1.0 or TLS 1.1                                                              |
| **Key exchange**    | X25519 and hybrid X25519MLKEM768; forward secrecy supported                                             |
| **Cipher strength** | AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305                                                          |
| **Certificate**     | EC 256-bit; issued by SSL.com SSL Intermediate CA ECC R2; SHA384withECDSA; valid until 21 December 2026 |
| **Warnings**        | No major TLS weakness reported                                                                          |

The SSL Labs scan gave `cloudflare-dns.com` an A+ grade and reported TLS 1.3 and post-quantum hybrid key exchange support.

### Website 2: 3ack.com

| Item                | Result                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------ |
| **Overall grade**   | **B**                                                                                      |
| **Protocols**       | TLS 1.0, TLS 1.1, TLS 1.2 and TLS 1.3                                                      |
| **Key exchange**    | Modern key exchange is available for newer clients                                         |
| **Cipher strength** | Modern TLS ciphers are available, but old protocols permit weaker negotiation              |
| **Certificate**     | RSA 2048-bit; issued by Let’s Encrypt R12; SHA256withRSA; valid from 2 May to 31 July 2026 |
| **Warnings**        | TLS 1.0 and TLS 1.1 support capped the grade at B                                          |

SSL Labs explicitly reported that support for TLS 1.0 and TLS 1.1 capped the site’s grade at B.

---

## Part 2 — MedDefense Portal Assessment

### Predicted Grade: B

The portal would probably receive a **B** while its certificate remains valid. It could receive a **C or lower** if the default Apache cipher list includes 3DES or other weak cipher suites.

Issues affecting the result:

1. **TLS 1.0 is enabled**, which caps the SSL Labs grade.
2. **TLS 1.3 is not supported.**
3. **HSTS is missing**, preventing an A+ grade.
4. **Weak cipher suites may be enabled** through the default Apache configuration.
5. **OCSP stapling is missing.**
6. **The certificate expires in 18 days**, creating an urgent warning and future trust failure.
7. **Automatic certificate renewal is not configured.**

TLS 1.0 and TLS 1.1 are formally deprecated and must not be negotiated.

---

## Part 3 — Hardened Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name portal.meddefense.local;

    ssl_certificate     /etc/nginx/tls/portal-fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/portal_key.pem;

    ssl_protocols TLSv1.2 TLSv1.3;

    ssl_conf_command Ciphersuites
        TLS_AES_256_GCM_SHA384:
        TLS_CHACHA20_POLY1305_SHA256:
        TLS_AES_128_GCM_SHA256;

    ssl_ciphers
        ECDHE-ECDSA-AES256-GCM-SHA384:
        ECDHE-ECDSA-CHACHA20-POLY1305:
        ECDHE-ECDSA-AES128-GCM-SHA256;

    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519:secp256r1;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_early_data off;

    ssl_stapling on;
    ssl_stapling_verify on;

    add_header Strict-Transport-Security
        "max-age=31536000" always;
}
```

Nginx supports explicitly limiting connections to TLS 1.2 and TLS 1.3 and configuring server cipher preference.

### Configuration Reasons

| Choice                       | Reason                                                                                                  |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| **TLS 1.2 and TLS 1.3 only** | Removes deprecated TLS 1.0 and TLS 1.1.                                                                 |
| **AES-256-GCM first**        | Provides authenticated encryption with a 256-bit key.                                                   |
| **ChaCha20-Poly1305 second** | Performs well on mobile devices without AES hardware acceleration.                                      |
| **AES-128-GCM third**        | Provides strong security, good performance and broad compatibility.                                     |
| **ECDHE only**               | Provides forward secrecy so past sessions remain protected if the certificate key is later compromised. |
| **X25519 and P-256**         | These provide strong and efficient elliptic-curve key exchange.                                         |
| **HSTS for one year**        | Forces browsers to use HTTPS for future connections; one year equals 31,536,000 seconds.                |
| **Session tickets disabled** | Avoids risks from unmanaged or reused session-ticket encryption keys.                                   |
| **Early data disabled**      | Prevents TLS 1.3 zero-round-trip replay risks.                                                          |
| **OCSP stapling enabled**    | Allows the server to provide certificate-revocation status during the handshake.                        |
| **No legacy renegotiation**  | TLS 1.3 does not use renegotiation, and TLS 1.2 should use only secure renegotiation.                   |

---

## Part 4 — TLS Downgrade Attack

In a downgrade attack, an attacker interferes with the handshake and makes the TLS 1.2 connection appear to fail. A vulnerable client may retry using TLS 1.0, allowing the attacker to target weaknesses in the older protocol. Supporting several old protocol versions increases the opportunity for this manipulation. The simplest prevention is to disable TLS 1.0 and TLS 1.1 and allow only TLS 1.2 and TLS 1.3.

