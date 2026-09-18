# FileSecureSuite v1.0.5

Enterprise-grade file encryption with AES-256-GCM and RSA-4096.

![Version](https://img.shields.io/badge/version-1.0.5-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Status](https://img.shields.io/badge/status-stable-green.svg)

---

## Why FileSecureSuite?

Encryption should be frictionless. Most people need to encrypt files and texts for ad-hoc secure sharing via email or chat—but existing solutions were built for different problems.

**The Challenge:**
Initially, we explored OpenSSL for encryption. It's mature and widely used, but it has a critical limitation: **RSA key size directly constrains file size**. Encrypting large files (beyond a few MB) with OpenSSL keys becomes impractical. **GPG** solves this but is designed around permanent key management, trust networks, and identity verification—concepts that add overhead for simpler use cases.

**Our Solution:**
FileSecureSuite uses **hybrid encryption**, optimized for:

- **Throwaway keys** - Generate a key for a single conversation, then discard it. No persistent key management burden.
- **Large file support** - Hybrid encryption (AES-256-GCM + RSA-4096) scales to any file size limited only by available RAM, not key size.
- **OpenSSL key compatibility** - You can use OpenSSL-generated RSA keys with FileSecureSuite for encryption. However, encrypted files are in **FSS1 format** (FileSecureSuite's published standard), which requires FileSecureSuite or a compatible implementation to decrypt.
- **Speed** - Encrypt a file in seconds, without setup complexity. Create keys on the fly.
- **Privacy** - Keys don't linger in your system. Communicate securely without maintaining infrastructure.
- **Simplicity** - Drag & drop encryption on Windows, intuitive workflows on all platforms. No learning curve.
- **Archive protection** - Encrypt sensitive files at rest without needing signatures or trust networks.

### Open Format Specification

To ensure files encrypted today remain decryptable in the future—whether FileSecureSuite exists or not—we've published **complete encryption specifications** documenting all parameters, format details, and test vectors. This enables independent implementations in any language and guarantees long-term interoperability.

### Not Trying to Replace, Just Different

FileSecureSuite doesn't aim to be a replacement for GPG or OpenSSL. It's a purpose-built tool for a specific workflow: **quick, temporary, easy encryption for everyday file sharing and storage**. 

If you need digital signatures, long-term key infrastructure, or trusted communication networks—GPG is the right choice. If you need to securely share a document in 30 seconds without complexity—FileSecureSuite is built for that.

### Flexible Encryption for Every Scenario

FileSecureSuite doesn't lock you into one approach. Choose what fits your need:

- **Password-only encryption** - Encrypt a file/text with a simple password using AES-256-GCM. Share the file/text and password separately. Perfect for quick, one-off exchanges.
- **Throwaway key pairs** - Generate a temporary RSA key pair, share the public key, encrypt the file/text, then discard the key after communication. No password needed, no lingering infrastructure.
- **Long-term key protection** - Create an RSA keypair, protect it with a strong password, and use it to encrypt your archive files. One secure key manages all your sensitive data without complexity.

Same tool, different modes—you decide the right security model for each situation.

### Key Principles

- **User-first design** - Encryption operations should feel as natural as sharing a file
- **Open format specification** - All encryption parameters published for future interoperability and independent implementations
- **Cross-platform** - Seamless experience on Windows, Linux, and macOS
- **Self-contained** - Everything you need is integrated—no external tool juggling
- **Future-proof** - Security enhancements planned without breaking backward compatibility

---

## Features

- **AES-256-GCM Encryption** - Military-grade symmetric encryption with authentication
- **RSA-4096 Key Exchange** - Robust asymmetric encryption for key distribution
- **Key Management System** - Secure key backup and public key export with fingerprinting
- **Cross-Platform** - Windows, macOS, and Linux support
- **Secure Key Derivation** - PBKDF2 with configurable iterations and enhanced validation
- **Interactive CLI** - User-friendly terminal interface with emoji indicators
- **HMAC Verification** - Integrity checking for all encrypted data
- **Multi-Environment Support** - Works on Desktop, Headless, Remote Desktop
- **Complete Filename Preservation** - Original filenames retained during encryption
- **Comprehensive Audit Logging** - Enterprise-grade operation tracking with compliance fields

---

## What's New in v1.0.5

✅ **Key Management System** - New submenu for secure key backup and public key export  
✅ **Enhanced Audit Logging** - New fields for key operations and fingerprinting  
✅ **Improved Security** - Stricter key password validation (12+ chars with complexity)  
✅ **Better UX** - Dedicated submenus for Encrypt/Decrypt and Key Management  
✅ **Selective Backup** - Choose which keys to backup or backup all at once  
✅ **Optional Dependencies** - QR code and progress bars now gracefully optional  
✅ **PBKDF2 Update** - Increased to 600,000 iterations (OpenSSL 3.0 default)  

[See full changelog](CHANGELOG.md)

---

## Quick Start

### Installation

```bash
# Windows
python -m pip install -r requirements.txt
python FileSecureSuite_1_0_5.py

# macOS / Linux
python3 -m pip install -r requirements.txt
python3 FileSecureSuite_1_0_5.py
```

### Automated Installers

**Windows:**
```cmd
install_filesecure_windows.bat
```

**Linux:**
```bash
bash install_filesecure_linux.sh
```

**macOS:**
```bash
bash install_filesecure_macos.sh
```

---

## Requirements

- **Python 3.8** or higher
- **pip** (Python package manager)
- Internet connection (for first-time installation)

### Dependencies

Core dependency (required):
- `cryptography>=41.0.0` - Encryption primitives

Optional dependencies (graceful fallback if missing):
- `qrcode[pil]>=8.0` - QR code generation
- `colorama>=0.4.6` - Colored terminal output
- `pyperclip>=1.8.2` - Clipboard operations

Removed dependencies (no longer required):
- `tqdm` - Functionality maintained with native Python

---

## Usage

Launch the application:

```bash
python3 FileSecureSuite_1_0_5.py
```

### Main Menu Options

1. **Generate RSA-4096 Key Pair** - Create new encryption keys
2. **Encrypt** - Secure files or text with AES-256-GCM or RSA-4096
3. **Decrypt** - Restore encrypted files with integrity verification
4. **Key Management** - Backup keys and export public keys
5. **View Audit Log** - Track encryption operations for compliance
6. **Credits** - Support information and QR code
7. **Exit** - Close the application

### Key Management Features

- **Backup Keys** - Secure backup of RSA key pairs
  - Backup all keys at once
  - Selectively backup specific keys by number
  
- **Export Public Key** - Extract public key from private key
  - Automatic fingerprint calculation
  - Compliance audit logging
  - Password-protected key support

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Windows 10/11 | ✅ Full Support | Native terminal support |
| Linux Desktop | ✅ Full Support | All desktop environments |
| macOS | ✅ Full Support | Intel & Apple Silicon |
| Kali Linux (Headless) | ✅ Full Support | SSH terminal compatible |
| Remote Desktop | ✅ Full Support | Auto-detects environment |

---

## Security

- Uses NIST-approved cryptographic algorithms
- No plaintext key storage
- Secure random salt generation
- File permissions restricted to owner only
- HMAC-based integrity verification
- Cross-platform compatibility tested
- Complete audit logging of all operations
- Key password validation with complexity requirements
- Exponential backoff on failed password attempts
- Secure key fingerprinting for verification

See [SECURITY.md](SECURITY.md) for detailed security information.

---

## Installation Guide

Detailed setup instructions available in:
- [INSTALLATION_INSTRUCTIONS.md](INSTALLATION_INSTRUCTIONS.md)
- [WINDOWS_PYTHON_INSTALLATION_GUIDE.md](WINDOWS_PYTHON_INSTALLATION_GUIDE.md)
- [README_INSTALLERS.md](README_INSTALLERS.md)

---

## Troubleshooting

### Python Not Found (Windows)
1. Download Python: https://www.python.org/downloads/
2. During installation, **CHECK "Add Python to PATH"**
3. Restart Command Prompt
4. Try again

### Python Not Found (Linux)
```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip python3-venv -y

# Fedora
sudo dnf install python3 python3-pip -y

# Arch
sudo pacman -S python python-pip -y
```

### pip Not Found
```bash
python -m pip install cryptography  # Windows
python3 -m pip install cryptography  # Linux/macOS
```

### Encrypted Files Not Decrypting
- Ensure correct encryption format (.aes, .rsa, or .aes.b64, .rsa.b64)
- Verify correct password or private key
- Check audit log for operation history
- Use Key Management to verify key fingerprints match

### Missing Optional Features
- **No colored output?** Install colorama: `pip install colorama`
- **No QR codes?** Install qrcode: `pip install qrcode[pil]`
- **No clipboard?** Install pyperclip: `pip install pyperclip`

All features gracefully degrade if optional dependencies are missing.

---

## File Format

### Encrypted File Naming
- Original filename is preserved and included in the encrypted filename
- Format: `encrypted_<original_filename>_<timestamp>_<random>.aes|.rsa`
- Base64 versions also supported: `.aes.b64`, `.rsa.b64`

### Supported Encryption Methods
- **AES-256-GCM** - Password-based symmetric encryption
- **RSA-4096** - Asymmetric encryption with optional key password
- **Hybrid Mode** - RSA key exchange with AES data encryption

---

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## Support

- **Issues:** https://github.com/marianopeluso/FileSecureSuite/issues
- **Discussions:** https://github.com/marianopeluso/FileSecureSuite/discussions
- **Security:** See [SECURITY.md](SECURITY.md) for reporting vulnerabilities
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

---

## Release History

### v1.0.5 (2025-12-02)
- ✅ Key Management System with secure backup
- ✅ Enhanced audit logging with fingerprinting
- ✅ Improved security with stricter password validation
- ✅ Better user interface with submenus
- ✅ Optional dependencies with graceful fallback

### v1.0.4 (2025-11-17)
- ✅ Fixed filename truncation during encryption
- ✅ Improved user interface flow
- ✅ Better batch processing support

### v1.0.3 (2025-11-16)
- ✅ ASCII QR code display improvements

### v1.0.2 (2025-11-14)
- ✅ Cross-platform QR viewer fixes

### v1.0.1 (2025-11-13)
- ✅ Line ending and encoding fixes

### v1.0.0 (2025-11-13)
- ✅ Initial release with core encryption features

---

**FileSecureSuite v1.0.5** - Enterprise encryption for everyone  
*Last Updated: 2025-12-02*
