# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.0.x   | ✅ |
| 1.0.x   | ❌ (superseded by 2.0.0; please upgrade) |

Only the latest 2.0.x release receives security fixes.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting: go to the repository's **Security** tab → **Report a vulnerability**. This opens a private advisory visible only to the maintainer until a fix is ready.

Please include, where possible: the affected version, a description of the issue, and steps to reproduce it. You will receive an acknowledgement and, once the issue is confirmed and fixed, credit in the release notes (unless you prefer to remain anonymous).

## Cryptographic Design

File Secure Suite uses:

- **AES-256-GCM** for authenticated payload encryption
- **RSA-4096 with OAEP** (SHA-256, MGF1-SHA-256) for wrapping a random AES-256 key in public-key (hybrid) mode
- **PBKDF2-HMAC-SHA-256** with 600,000 iterations for deriving an AES key from a password
- **PKCS#8** (private) and **SubjectPublicKeyInfo** (public) PEM key encodings, OpenSSL-compatible
- The authenticated **FSS2** container format; legacy **FSS1** containers can still be decrypted for backward compatibility but are never produced by new encryption

Both encryption modes provide authenticated encryption: a modified, incomplete, or tampered container fails authentication rather than producing silently altered plaintext.

## What File Secure Suite Protects

- The **confidentiality** of file or text content, given a sufficiently strong password or an uncompromised private key
- The **integrity** of encrypted containers — tampering with the ciphertext or header causes decryption to fail
- **Anonymity of the key itself**: an FSS key pair identifies only itself, never a verified real-world identity

## What File Secure Suite Does NOT Protect

- **A compromised endpoint.** Malware, keyloggers, screen-capture tools, clipboard monitors, or an unlocked/unattended computer can bypass this or any encryption software.
- **Sender identity or authenticity.** There is no digital signature functionality. A valid RSA-encrypted message proves only that it can be opened by the matching private key — not who created it.
- **Metadata.** Encrypted filenames typically still contain the original filename; the local audit log records filenames, methods, and outcomes (never plaintext or keys); Text-mode results are kept in memory and are not saved automatically; when you use **Save text…**, the file is written to disk **unencrypted** (starting text and result together, in readable form) in the location you choose (by default the `texts` folder).
- **Transport-level anonymity.** File Secure Suite protects content, not the channel it travels over — it is not an anonymity network and does not hide who is talking to whom.
- **Forward secrecy.** If a private key is later compromised, any previously recorded FSS2 container encrypted for it can then be decrypted. There is no ephemeral key ratcheting.
- **Post-quantum security.** RSA-4096 is not post-quantum; data that must stay confidential for a very long time should account for "harvest now, decrypt later" risk.
- **Weak, reused, or guessable passwords.** PBKDF2 (600,000 iterations) raises the cost of each guess but cannot make a predictable password strong.
- **A lost password or private key.** There is no recovery mechanism, backdoor, master key, or key escrow, by design.

## Hardening Measures

- Symlinks and Windows reparse points are rejected on every path the application reads from or writes to
- A hard 1 GiB combined-size cap plus a dynamic available-RAM check (5x safety margin) before every file operation
- The clipboard self-clears 15 seconds after copying decrypted text
- A non-blocking heuristic warning flags obviously weak passwords (short repeating patterns, sequential runs) without blocking them
- RSA private-key protection passwords require 12–128 characters including an uppercase letter, a lowercase letter, a digit, and a symbol
- Decryption failures return a single generic error rather than distinguishing "wrong password" from "wrong key" from "tampered data," to avoid giving an attacker a distinguishing oracle

## Recommended Practices

1. Use a unique, high-entropy password or passphrase — a password manager or a truly random multi-word passphrase is preferable to a predictable word with substitutions.
2. Generate a separate RSA key pair per identity, project, or conversation rather than reusing one everywhere.
3. Verify a correspondent's public-key **fingerprint** (full SHA-256, shown in Key Management) through a separate trusted channel before trusting it.
4. Keep at least one verified, offline backup of every private key you still need, stored **separately** from its password.
5. Treat decrypted files, saved text files, clipboard contents, and audit-log metadata according to their real sensitivity — none of these are encrypted at rest.
6. Never send a private key to someone who only needs to encrypt data for you — they only need your public key.

## Verifying the Windows Executable

The Windows executable is distributed inside a zip attached to each release, and it is **not code-signed with a Windows certificate**, so SmartScreen or antivirus software may flag it. To confirm that what you downloaded is what the author published, check the zip's SHA-256 checksum and the GPG signature of that checksum (`.zip.sha256` and `.zip.sha256.asc`, attached to the same release) against the public key published in this repository (`filesecuresuite2.0.asc`, fingerprint `0FD9 7EB8 55F7 C5BB 1048 D424 F204 94B9 FAB5 3C10`). Step-by-step commands are in the [README](README.md#verifying-the-download). If you prefer not to trust a binary at all, run the app from source or build the executable yourself with PyInstaller (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

## Known Limitations

- No digital signatures, sender authentication, or non-repudiation
- No built-in key server, web of trust, or certificate authority — public keys must be authenticated out of band
- Legacy FSS1 support exists purely for reading old files; do not rely on it for new data
