# Changelog

All notable changes to File Secure Suite are documented here. Dates use the ISO 8601 format (YYYY-MM-DD). *(Fill in the exact release dates before publishing — placeholders below are marked `TBD`.)*

## [2.0.0] - TBD

File Secure Suite 2.0.0 is a full rewrite: from a command-line menu tool to a native desktop GUI (PySide6), with a new authenticated container format. It replaces v1.0.5 as the current release.

### Added
- New cross-platform desktop GUI (Windows, Linux, macOS) replacing the old CLI menu interface
- Batch file encryption/decryption: up to 5 files at a time, up to 1 GiB combined, via drag-and-drop
- Text/Chat mode: encrypt or decrypt text/messages for pasting into any chat or email app, kept in memory, with an explicit **Save text…** button (nothing is written to disk automatically)
- Key Management panel: RSA-4096 key backup, public-key export (including as a QR code), and SHA-256 key fingerprint display
- Audit log with a live filter/search box, now also recording failed decrypt attempts (metadata only — no plaintext or key material)
- Results of file operations, key generation, and public-key export are saved automatically in the app's own folders (`files`, `keys`, `backup`); originals are never modified
- Key generation offers password protection for the private key by default, and asks for confirmation before creating an unprotected key
- Ready-to-run single-file **Windows executable** (built with PyInstaller), published as a zip on the Releases page, with a SHA-256 checksum and a detached GPG signature
- New authenticated **FSS2** container format (see `FORMAT_SPECIFICATIONS.md`)
- Non-blocking "weak password" warning (heuristic) shown during password entry, without blocking acceptance
- Self-clearing clipboard: text copied after decryption is cleared automatically after 15 seconds
- Persistent on-screen warnings that lost passwords/keys cannot be recovered (no backdoor, no master key)
- "About" panel with a responsible-use disclaimer and Lightning Network donation option

### Changed
- Default container format for new encryption is now **FSS2** (previously FSS1)
- Combined AES password policy: 12–128 characters, rejects highly repetitive passwords; RSA key-protection passwords additionally require an uppercase letter, a lowercase letter, a digit, and a symbol
- The 1 GiB size limit now applies to the **combined total** of a batch, not to each file individually
- Available-RAM safety margin raised from 3x to 5x the operation size, based on real memory profiling
- RSA public/private key encoding unchanged (PKCS#8 / SubjectPublicKeyInfo PEM, OpenSSL-compatible) but now generated and managed entirely from the GUI
- QR code generation now uses an embedded, trimmed copy of the Nayuki QR Code generator (MIT-licensed) instead of the external `qrcode` package
- Minimum supported Python version raised to 3.9+

### Removed
- External `qrcode` and `colorama` dependencies (no longer needed)
- Unused portions of the embedded QR generator's public API (binary-mode, ECI and Kanji segment support), which the app never calls

### Security
- FSS1 decryption is kept for backward compatibility with files created by earlier releases; it is never used to encrypt new data
- Release executable is distributed with a SHA-256 checksum signed with the author's GPG key (the executable itself is not code-signed with a Windows certificate)
- All file paths the app reads from or writes to reject symlinks and Windows reparse points
- No signing, verification, or identity-authentication functionality — File Secure Suite remains encryption-only and anonymous by design (a key identifies only itself, never a real-world identity)

### Fixed
- Numerous interface issues from internal testing: missing word-wrap on several labels, layout regressions in multi-button rows, and clipboard/audit-log edge cases

## [1.0.5] - TBD (previously published)

- Command-line, menu-driven interface
- AES-256 password-based file and text encryption using the legacy FSS1 container
- Optional `colorama` (terminal coloring) and `qrcode`/`pyperclip` dependencies

---

*Internal development between these two releases went through many intermediate build numbers (GUI 1.1 → 1.5.x, core 1.0.5 → 1.1.0) that were never published individually. This changelog summarizes the net, user-visible differences between the two published releases rather than listing every internal build.*
