# File Secure Suite — Container Format Specification

This document describes the exact byte layout of File Secure Suite's encrypted containers, as implemented in `fss_core_1_1_0.py`. It covers the current **FSS2** format and the **legacy FSS1** format (read-only, kept for backward compatibility).

All multi-byte integers are **big-endian**. A container may be stored as raw binary bytes (e.g. `.aes`, `.rsa` files) or as Base64 text with the raw bytes encoded (e.g. `.aes.b64`, `.rsa.b64`, or pasted Text-mode output); Base64 input has all whitespace stripped before decoding.

## FSS2 (current format)

### Header

The header is a fixed 14-byte structure, defined as the Python `struct` format `>4sBBBBIH`:

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 4 | `magic` | bytes | Always `b'FSS2'` |
| 4 | 1 | `version` | uint8 | Always `2` |
| 5 | 1 | `algorithm` | uint8 | `1` = password (AES-256-GCM); `2` = public-key hybrid (RSA-4096-OAEP + AES-256-GCM) |
| 6 | 1 | `payload_type` | uint8 | `0` = text; `1` = file |
| 7 | 1 | `kdf` | uint8 | `1` = PBKDF2-HMAC-SHA256 (algorithm 1); `0` = none / not applicable (algorithm 2) |
| 8 | 4 | `iterations` | uint32 | `600000` for algorithm 1; `0` for algorithm 2 |
| 12 | 2 | `key_length` | uint16 | Length in bytes of the RSA-wrapped AES key that follows; `0` for algorithm 1, `512`–`1024` for algorithm 2 (RSA-4096 through RSA-8192 moduli) |

### Body

Immediately after the 14-byte header:

| Offset (from header start) | Size | Field | Meaning |
|---|---|---|---|
| 14 | 16 | `salt` | For algorithm 1: the PBKDF2 salt. For algorithm 2: **unused random filler**, kept only so both algorithms share one fixed layout — the AES session key is delivered via `wrapped`, not derived from this field. |
| 30 | 12 | `nonce` | Random AES-GCM nonce, unique per encryption |
| 42 | `key_length` (0 or 512–1024) | `wrapped` | Empty for algorithm 1. For algorithm 2: the random 256-bit AES session key, encrypted with the recipient's RSA-4096 public key using RSA-OAEP (MGF1, SHA-256, no label). |
| 42 + `key_length` | remainder | `ciphertext` | AES-256-GCM output: encrypted payload immediately followed by the 16-byte GCM authentication tag |

### Authenticated data

The entire prefix — header **and** `salt` **and** `nonce` **and** `wrapped` (i.e. every byte before `ciphertext`) — is passed to AES-256-GCM as associated authenticated data. Any modification to the header, salt, nonce, or wrapped key causes GCM authentication to fail on decryption, exactly like a modification to the ciphertext itself.

### Plaintext layout

- `payload_type = 0` (text): the plaintext is the UTF-8-encoded text as-is.
- `payload_type = 1` (file): the plaintext is `<original filename, UTF-8, 1–255 bytes> + 0x00 + <file content>`. The filename is recovered by splitting the decrypted plaintext on the first `0x00` byte.

### Size limits enforced on decode

- Encoded (Base64 or raw) input: at most `4 * ceil((MAX_FILE_SIZE + 4096 + 2) / 3)` bytes
- Decoded container: between 32 bytes (`MIN_ENCRYPTED_SIZE`) and `MAX_FILE_SIZE + 4096` bytes (`MAX_ENCRYPTED_SIZE`)
- Plaintext: up to 1 MiB for text, up to 1 GiB + 256 bytes for files

### Worked example (algorithm 1, password mode)

```
bytes 0-3    : "FSS2"
byte  4      : 0x02
byte  5      : 0x01              (algorithm = password)
byte  6      : 0x00 or 0x01      (payload_type)
byte  7      : 0x01              (kdf = PBKDF2)
bytes 8-11   : 0x00092700        (iterations = 600000)
bytes 12-13  : 0x0000            (key_length = 0, no wrapped key)
bytes 14-29  : <16-byte PBKDF2 salt>
bytes 30-41  : <12-byte GCM nonce>
bytes 42-...  : <AES-256-GCM ciphertext + 16-byte tag>
```

### Worked example (algorithm 2, RSA hybrid mode, RSA-4096)

```
bytes 0-3    : "FSS2"
byte  4      : 0x02
byte  5      : 0x02              (algorithm = RSA hybrid)
byte  6      : 0x00 or 0x01      (payload_type)
byte  7      : 0x00              (kdf = none)
bytes 8-11   : 0x00000000        (iterations = 0)
bytes 12-13  : 0x0200            (key_length = 512 bytes for a 4096-bit RSA modulus)
bytes 14-29  : <16 random filler bytes, unused>
bytes 30-41  : <12-byte GCM nonce>
bytes 42-553 : <512-byte RSA-OAEP-wrapped AES-256 key>
bytes 554-...: <AES-256-GCM ciphertext + 16-byte tag>
```

## FSS1 (legacy format — decrypt-only)

FSS1 predates the fixed-width header above and is no longer produced by File Secure Suite; it is documented here only to support decrypting files created by earlier releases.

### Password mode (FSS1)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `b'FSS1'` |
| 4 | 1 | Version (`1`) |
| 5 | 4 | `hash_length` (uint32, always `32`) |
| 9 | 32 | SHA-256 digest of the plaintext (integrity check, verified after decryption) |
| 41 | 16 | PBKDF2 salt |
| 57 | 12 | AES-GCM nonce |
| 69 | remainder | AES-256-GCM ciphertext + 16-byte tag (no associated data) |

### RSA hybrid mode (FSS1)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `b'FSS1'` |
| 4 | 1 | Version (`1`) |
| 5 | 4 | `hash_length` (uint32, always `32`) |
| 9 | 32 | SHA-256 digest of the plaintext |
| 41 | 2 | `key_len` (uint16, RSA-wrapped key length in bytes; must be 100–1024) |
| 43 | `key_len` | RSA-OAEP-wrapped AES-256 key |
| 43+`key_len` | 16 | Salt (unused by the AES step; retained for layout compatibility) |
| 59+`key_len` | 12 | AES-GCM nonce |
| 71+`key_len` | remainder | AES-256-GCM ciphertext + 16-byte tag (no associated data) |

In both FSS1 variants, the plaintext is `<filename> + 0x00 + <content>` and integrity is checked by comparing a plain SHA-256 hash of the decrypted plaintext against the stored digest — **not** as an AEAD associated-data mechanism (FSS1's AES-GCM call carries no associated data). FSS2 supersedes this with header/salt/nonce/key authentication built directly into the AEAD call.

**Migrating a file from FSS1 to FSS2:** there is no direct binary conversion between the two formats. A file encrypted as FSS1 must be decrypted with its original password or private key, and the resulting plaintext then re-encrypted, which produces a new FSS2 container. See [`GUIDE.md`](DOCUMENTATION.md#131-migrating-an-old-fss1-file-to-fss2).

## Key file formats (unrelated to the container, but required to use it)

- Public key: PEM, `SubjectPublicKeyInfo`, RSA, 4096–8192 bits
- Private key: PEM, `PKCS#8`, RSA, 4096–8192 bits, optionally encrypted with a password (`BestAvailableEncryption`)
- Key fingerprint: SHA-256 of the DER-encoded `SubjectPublicKeyInfo` of the public half — identical whether computed from the public key file or derived from the matching private key
