# File Secure Suite

**File Secure Suite** is a free, open-source desktop application for encrypting files and text — with a password or with RSA-4096 public-key cryptography. It runs entirely on your machine: no accounts, no cloud, no telemetry, no network calls.

> Secret is what you hide. Private is what you choose to reveal. Privacy is the power to selectively reveal oneself to the world. You don't need something to hide to need privacy.
>
> — Inspired by Eric Hughes, *A Cypherpunk's Manifesto*, 1993

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## Why File Secure Suite

File Secure Suite exists to protect privacy — for private conversations, sensitive documents, and personal data. It is a neutral tool, like a lock or a pen: what you do with it is entirely up to you. It is anonymous by design (a key identifies only itself, never a verified real-world identity) and it has no signing, authentication, or identity-verification features of any kind — it only encrypts and decrypts.

## Key Features

- **File encryption**, password-based (AES-256-GCM) or public-key (RSA-4096 hybrid), with drag-and-drop batches of up to 5 files (1 GiB combined)
- **Text / Chat mode** for encrypting messages or pasted text to copy into any chat app, with the same password or public-key options; nothing is saved unless you choose **Save text…**
- **Key Management**: RSA-4096 key generation, password-protected private-key backup, public-key export (including as a QR code), and SHA-256 key fingerprints
- **Audit log** of file and text operations (metadata only — filenames and outcomes, never plaintext or keys) with a live filter
- **FSS2 authenticated container format**, plus read-only support for decrypting legacy FSS1 files from earlier releases — decrypt with the old password/key, then re-encrypt to adopt FSS2
- Non-blocking weak-password warnings, one-shot password fields that clear themselves after use, and a self-clearing clipboard (15 seconds) after copying decrypted text
- Cross-platform: Windows, Linux, macOS

## Download (Windows)

The easiest way to try File Secure Suite on Windows 10 or 11 (64-bit) is the ready-to-run, single-file executable: no Python and no installation needed.

1. Download `filesecuresuite_2_0_0.zip` from the [Releases](https://github.com/marianopeluso/FileSecureSuite/releases) page. It contains `FileSecureSuite_2_0_0.exe` and the author's GPG public key (`filesecuresuite2.0.asc`).
2. *(Recommended)* Verify the download — see [Verifying the download](#verifying-the-download) below.
3. Unzip it and double-click the `.exe`. The app creates its `keys`, `texts`, `files`, `backup`, and `logs` folders right beside the `.exe`, so keep it in a folder of its own (or on a USB drive).

> **The executable is not code-signed with a Windows certificate.** Windows SmartScreen or your antivirus may warn that the publisher is unknown, and executables built with PyInstaller are sometimes flagged as false positives. This is why each release ships a SHA-256 checksum signed with the author's GPG key, and why the full source code is in this repository: you can verify the download, or run the app from source and build the executable yourself.

### Verifying the download

Each release contains three files: `filesecuresuite_2_0_0.zip`, `filesecuresuite_2_0_0.zip.sha256` (its SHA-256 checksum), and `filesecuresuite_2_0_0.zip.sha256.asc` (a detached GPG signature of the checksum file).

The author's public key is published in this repository as [`filesecuresuite2.0.asc`](filesecuresuite2.0.asc) — use *that* copy, not the one inside the zip, because a tampered zip could carry a tampered key. Its fingerprint is:

```
0FD9 7EB8 55F7 C5BB 1048 D424 F204 94B9 FAB5 3C10
```

```powershell
# 1. Check that the zip matches the published checksum (the two hashes must be identical)
(Get-FileHash filesecuresuite_2_0_0.zip -Algorithm SHA256).Hash
Get-Content filesecuresuite_2_0_0.zip.sha256

# 2. Check that the checksum file was signed by the author (requires GnuPG)
gpg --import filesecuresuite2.0.asc
gpg --fingerprint mariano@peluso.me                # must show the fingerprint above
gpg --verify filesecuresuite_2_0_0.zip.sha256.asc filesecuresuite_2_0_0.zip.sha256
```

GnuPG will print "Good signature from Mariano Peluso" and, unless you have certified the key yourself, a warning that the key is not trusted — that warning is expected; what matters is that the fingerprint matches.

## Quick Start (from source)

```bash
git clone https://github.com/marianopeluso/FileSecureSuite.git
cd FileSecureSuite
pip install -r requirements.txt
python FileSecureSuite_2_0_0.py
```

`fss_core_1_1_0.py` must stay in the same directory as `FileSecureSuite_2_0_0.py` — it is the cryptographic engine the GUI imports.

## Requirements (running from source)

The Windows executable needs none of this. To run the Python source you need:

- Python 3.9 or later
- [PySide6](https://pypi.org/project/PySide6/) — GUI framework
- [cryptography](https://pypi.org/project/cryptography/) — AES-GCM, RSA-OAEP, PBKDF2
- [pyperclip](https://pypi.org/project/pyperclip/) *(optional)* — enables the self-clearing clipboard when copying decrypted text; without it, copy/paste still works manually

See [`requirements.txt`](requirements.txt).

## Platform & Portability

File Secure Suite runs on **Windows, Linux, and macOS** desktops with Python 3.9+ and a graphical environment — PySide6 is a desktop GUI framework, so it does not run on phones, tablets, or headless/embedded devices. It is distributed as Python source, plus a single-file **Windows executable** (see [Download](#download-windows)) that needs no Python installed. There is no installer: for Linux and macOS, run it from source.

It needs no installation (beyond the dependencies above when running from source, or nothing at all with the Windows executable) and keeps no system-wide state: you can run it from **any folder, including a USB flash drive**, and carry it between computers. Each copy creates its own `keys`, `texts`, `files`, `backup`, and `logs` folders right beside the application files — beside the `.exe` when you use the executable (see [`DOCUMENTATION.md`](docs/DOCUMENTATION.md#14-files-folders-and-local-data)) — so if several people each run their own copy, on their own PC or from their own USB drive, their keys, encrypted files, saved text, and audit logs stay completely separate. There is no shared server, account, or central database of any kind.

## Usage

Launch the app and choose a panel from the sidebar:

- **File** — encrypt or decrypt one or more files with a password or an RSA key pair
- **Text** — encrypt/decrypt text or chat messages, for pasting into email, chat apps, etc.
- **Key Generation** — create a new RSA-4096 key pair, optionally password-protected
- **Key Management** — back up, export, and fingerprint your existing keys
- **Audit Log** — review metadata about past encrypt/decrypt operations on this machine

## Security

- **AES-256-GCM** for password-based encryption, key derived via **PBKDF2-HMAC-SHA256** with 600,000 iterations and a random 16-byte salt
- **RSA-4096 with OAEP** (SHA-256) for public-key encryption, wrapping a random AES-256 key (hybrid encryption)
- Keys are standard **PKCS#8** (private) / **SubjectPublicKeyInfo** (public) PEM, OpenSSL-compatible
- The authenticated **FSS2** container format (see [`FORMAT_SPECIFICATIONS.md`](docs/FORMAT_SPECIFICATIONS.md)) — decryption of legacy **FSS1** files is still supported for backward compatibility, but FSS1 is never used to encrypt new data
- Per-file size cap (1 GiB) and a dynamic available-RAM check before every operation
- Symlinks and Windows reparse points are rejected on any path the app writes to or reads from
- No signing, no identity verification, no key escrow, no backdoor, and no network access of any kind

Full details, threat model notes, and how to report a vulnerability are in [`SECURITY.md`](SECURITY.md). For an in-depth, beginner-friendly explanation of password vs. public-key encryption, key management, the full interface panel-by-panel, and how File Secure Suite compares to OpenPGP/OpenSSL/SSH, see [`DOCUMENTATION.md`](docs/DOCUMENTATION.md).

## File Format

Encrypted output uses the `FSS2` container: a fixed binary header (magic, version, algorithm, payload type, KDF parameters) followed by the salt/nonce, an optional RSA-wrapped AES key, and the AES-256-GCM ciphertext with its authentication tag. The exact byte layout is documented in [`FORMAT_SPECIFICATIONS.md`](docs/FORMAT_SPECIFICATIONS.md).

## A Note on Responsible Use

File Secure Suite is a neutral tool: it can be used well or poorly, and that choice belongs entirely to the person using it. It exists to protect privacy, not to enable harm. Please use it responsibly and lawfully, and extend that same respect to others' privacy. As open-source software, it is provided as-is, without warranty, and its author accepts no liability for how others choose to use it.

## Contributing

Contributions, bug reports, and suggestions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Released under the [MIT License](LICENSE).

## Support the Project

If File Secure Suite is useful to you, you can support its development with a Lightning Network donation:

```
lnurl1dp68gurn8ghj7ampd3kx2ar0veekzar0wd5xjtnrdakj7tnhv4kxctttdehhwm30d3h82unvwqhk6ctjd9skummcxu6qs3rtcq
```

Issues and ideas: [GitHub Issues](https://github.com/marianopeluso/FileSecureSuite/issues) · [Discussions](https://github.com/marianopeluso/FileSecureSuite/discussions)

## Release History

See [`CHANGELOG.md`](CHANGELOG.md).
