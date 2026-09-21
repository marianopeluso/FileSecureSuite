# File Secure Suite — Documentation

**Applies to:** File Secure Suite GUI 2.0.0 and Core 1.1.0

This document is the complete reference for File Secure Suite: why it exists, how its interface works panel by panel, how its cryptography works, and how it compares to other tools. For a short project overview and installation steps, see [`README.md`](README.md). For the exact byte-level container format, see [`FORMAT_SPECIFICATIONS.md`](FORMAT_SPECIFICATIONS.md). For the security policy and vulnerability reporting, see [`SECURITY.md`](SECURITY.md).

No previous cryptography experience is required. Readers who are new can start at Chapter 1 and read in order. More experienced readers can jump straight to Chapter 6 onward for the algorithms, container format, and operational-security details.

> **Important:** encryption cannot protect an endpoint that is already compromised. Malware, keyloggers, screen capture tools, clipboard monitors, an unlocked computer, or an attacker with access to plaintext can bypass the protection described here.

## Table of Contents

1. [Why File Secure Suite](#1-why-file-secure-suite)
2. [Quick Comparison: Password Mode vs. Public-Key Mode](#2-quick-comparison-password-mode-vs-public-key-mode)
3. [Beginner Path: Why Create Keys?](#3-beginner-path-why-create-keys)
4. [Interface Overview](#4-interface-overview)
5. [Compatibility with OpenPGP, PGP, GnuPG, OpenSSL, and SSH](#5-compatibility-with-openpgp-pgp-gnupg-openssl-and-ssh)
6. [Core Concepts](#6-core-concepts)
7. [Password-Based Encryption](#7-password-based-encryption)
8. [Public-Key Hybrid Encryption](#8-public-key-hybrid-encryption)
9. [Public Key, Private Key, and Key Password](#9-public-key-private-key-and-key-password)
10. [Fingerprints and Key Verification](#10-fingerprints-and-key-verification)
11. [Text Workflow](#11-text-workflow)
12. [File Workflow](#12-file-workflow)
13. [The FSS2 Container Format](#13-the-fss2-container-format)
14. [Files, Folders, and Local Data](#14-files-folders-and-local-data)
15. [Limits and Operational Characteristics](#15-limits-and-operational-characteristics)
16. [Recommended Operating Practice](#16-recommended-operating-practice)
17. [Choosing the Correct Mode](#17-choosing-the-correct-mode)
18. [Failure Interpretation](#18-failure-interpretation)
19. [Official References](#19-official-references)

---

## 1. Why File Secure Suite

### 1.1 Philosophy

> Secret is what you hide. Private is what you choose to reveal. Privacy is the power to selectively reveal oneself to the world. You don't need something to hide to need privacy.
>
> — Inspired by Eric Hughes, *A Cypherpunk's Manifesto*, 1993

File Secure Suite exists to protect privacy — for private conversations, sensitive documents, and personal data — not to enable harm.

File Secure Suite is a neutral tool, like a lock or a pen: it can be used well or poorly, and that choice belongs entirely to the person using it. Please use it responsibly and lawfully, and extend that same respect to others' privacy. As open-source software, it is provided as-is, without warranty, and its author accepts no liability for how others choose to use it.

It is **anonymous by design**: a key identifies only itself, never a verified real-world identity. It has no signing, authentication, or identity-verification features of any kind — it only encrypts and decrypts.

### 1.2 Design Goal: Encryption for Ordinary Communication

File Secure Suite is designed to reduce the operational friction of using encryption in ordinary chat and email conversations. Its intended workflow is:

1. create a key pair without building a long-term identity or certificate hierarchy;
2. exchange the public key through the communication channel already in use;
3. verify its SHA-256 fingerprint through an independent trusted channel;
4. copy and paste encrypted Base64 text into chat or email, or attach an encrypted file;
5. load the corresponding private key to decrypt received content;
6. replace or clear keys when the conversation or recipient changes.

Keys may be created for one person, one project, one conversation, or one file exchange. This is called a **conversation-scoped** or **purpose-scoped** key pair in this guide. It reduces dependence on a permanent identity and limits organizational coupling between unrelated exchanges.

For a two-way RSA-encrypted conversation, each participant normally creates a key pair:

- Alice encrypts messages to Bob with Bob's public key;
- Bob decrypts them with Bob's private key;
- Bob encrypts replies with Alice's public key;
- Alice decrypts them with Alice's private key.

A single recipient key pair is enough for a one-way submission workflow, where many people encrypt for one recipient and do not require encrypted replies.

#### Identity-neutral is not anonymous

The PEM key itself does not require a real name, email address, certificate authority, public key server, or OpenPGP User ID. The descriptive name used during generation is a local filename label, not a cryptographically verified identity.

This makes a key pair **identity-neutral**, but it does not make the communication anonymous. Chat and email providers may still observe account identities, sender and recipient addresses, IP information, timestamps, message sizes, attachments, and other metadata. File names, local audit entries, saved text files, backups, and the way a public key is delivered may also reveal identity or context.

File Secure Suite protects content; it is not an anonymity network and does not hide transport metadata.

#### Short-lived keys and their limits

Creating a separate key pair for a sensitive conversation can reduce the impact of a later compromise because unrelated conversations need not use the same private key. It also introduces additional responsibilities:

- every new public key must be authenticated to prevent substitution;
- the private key must be retained until every required message or file has been received, decrypted, and verified;
- deleting a key too early makes its encrypted containers permanently unreadable;
- copies may remain in backups, synchronized folders, email attachments, temporary storage, or operating-system caches;
- secure deletion from modern storage cannot be assumed merely because a file was removed.

Conversation-scoped RSA keys do **not** provide protocol-level forward secrecy. If an attacker records an encrypted FSS2 container and later obtains its private key, the attacker can decrypt that container. True forward secrecy normally requires an interactive protocol with ephemeral key agreement and automatic key evolution or ratcheting.

### 1.3 Key Features

- **File encryption**, password-based (AES-256-GCM) or public-key (RSA-4096 hybrid), with drag-and-drop batches of up to 5 files (1 GiB combined)
- **Text / Chat mode** for encrypting messages or pasted text to copy into any chat app, with the same password or public-key options
- **Key Management**: RSA-4096 key generation, password-protected private-key backup, public-key export (including as a QR code), and SHA-256 key fingerprints
- **Audit log** of file and text operations (metadata only — filenames and outcomes, never plaintext or keys) with a live filter
- **FSS2 authenticated container format**, plus read-only support for decrypting legacy FSS1 files — decrypt with the old password/key, then re-encrypt to adopt FSS2
- Non-blocking weak-password warnings, one-shot password fields that clear themselves after use, and a self-clearing clipboard (15 seconds) after copying decrypted text
- **Portable and self-contained**: no installation (a ready-to-run single-file Windows executable is available on the Releases page; otherwise only its Python dependencies), no system-wide state — run it from any folder or a USB drive, and each copy's keys, files, and logs stay entirely separate from any other copy
- Cross-platform desktop: Windows, Linux, macOS (Python 3.9+ when running from source — not needed for the Windows executable — and a graphical environment; not for phones, tablets, or headless/embedded devices)

## 2. Quick Comparison: Password Mode vs. Public-Key Mode

| Property | Password mode | Public-key mode |
|---|---|---|
| Main primitive | AES-256-GCM | RSA-4096-OAEP plus AES-256-GCM |
| Secret required to encrypt | A password | No secret; the recipient's public key |
| Secret required to decrypt | The same password | The matching private key |
| Suitable for | Personal storage or parties that already share a secret securely | Sending protected data to a recipient without sharing a decryption secret |
| Main operational risk | Weak, reused, intercepted, or forgotten password | Lost, stolen, substituted, or incorrectly identified private/public key |
| Can many people encrypt for one recipient? | Only if all know the password | Yes; anyone with the authentic public key can encrypt |
| Does it prove who sent the data? | No | No |
| What must be backed up? | The password, using a secure method | The private key and, if used, its protection password |

Both modes provide **authenticated encryption**: a modified, incomplete, or corrupted encrypted container fails authentication instead of producing silently altered plaintext.

## 3. Beginner Path: Why Create Keys?

Imagine that Bob wants anyone in his work group to be able to send him a sealed message, but he does not want to give everyone the secret needed to open it.

Bob creates two related files:

- a **public key**, which acts like an open padlock that Bob may give to Alice and other senders;
- a **private key**, which acts like the only key that opens that padlock and must remain with Bob.

Alice encrypts a message with Bob's public key. After encryption, Alice cannot reverse the operation with that public key. Bob opens the message with his matching private key.

```text
BOB                                      ALICE
creates a key pair                       receives Bob's public key
   |                                             |
   +-- public key ------------------------------>+-- encrypts for Bob
   |
   +-- private key stays with Bob <-------------- encrypted message
             |
             +-- decrypts the message
```

This solves a problem that password encryption does not solve: Bob does not have to reveal a shared decryption password to every sender. It does not prove that Alice was the sender; that would require a digital signature system.

### 3.1 Create Your First Key Pair

1. Open **Key Generation**.
2. Enter a descriptive name that identifies the owner or purpose, not a secret.
3. Enable private-key password protection unless there is a specific operational reason not to.
4. Enter and confirm a unique password, then generate the pair.
5. Open the `keys` folder and identify the three generated files.

The generated files have different purposes:

| Generated file | Purpose | May be shared? |
|---|---|---|
| `*_public.pem` | Encrypts data for the owner | Yes, after recipients verify its fingerprint |
| `*_private.pem` | Decrypts data encrypted for that pair | **No** |
| `*_info.txt` | Records the name, creation time, filenames, and full public fingerprint | It contains no private key, but treat its metadata according to context |

After generation, perform a recovery test:

1. encrypt a harmless test message with the new public key;
2. decrypt it with the private key;
3. close and reopen the application;
4. repeat the decryption by loading the saved private key and entering its password;
5. create a secure backup of the private key and test that copy as well — the **Key Management** panel can export/back up an existing key pair and show its fingerprint at any time.

Only after this test should the pair be used for important data.

### 3.2 When a New Key Pair Is Useful

Create a new pair when you need a new identity, recipient, project boundary, security role, or replacement for a key that may have been exposed. Separate pairs reduce the amount of data affected if one private key is compromised.

Creating a new pair does not automatically re-encrypt old data. Keep the old private key while any container encrypted for it may still be needed. If a private key is suspected of compromise, stop distributing its public key, create and authenticate a replacement pair, and re-encrypt retained data where practical.

## 4. Interface Overview

File Secure Suite has six panels, reached from the sidebar: **File**, **Text**, **Key Generation**, **Key Management**, **Audit Log**, and **About**.

### 4.1 File Panel

Encrypts or decrypts a **batch of up to 5 files**, combined size up to 1 GiB, with one shared password or key pair per batch.

- **Encrypt / Decrypt** toggle at the top; files loaded on one side do not carry over to the other — switching from Encrypt to Decrypt and back keeps each side's own file list.
- **Method**: Password (AES-256-GCM) or public key (RSA-4096 hybrid). For RSA: the recipient's public key when encrypting, your private key plus its optional password when decrypting.
- **Drag and drop** files onto the drop zone, or use the file picker. Loading a 6th file, or one that would push the combined total over 1 GiB, is rejected with a message; the first 5 (or the total up to 1 GiB) are kept.
- A persistent amber warning is always visible: *"If you forget the password or lose the private key, the data cannot be recovered — there is no backdoor or master key."*
- **Results are saved automatically** in the `files` folder beside the application; your original files are never modified. Optionally, **Export Base64 copy** writes a Base64 version of the result, mainly for email, chat, or text-only fields.
- **Result view**: after each operation a result strip shows the outcome with **Copy path**, **Open folder**, and **Clear result**. A batch of more than one file shows a per-file ✓/✗ summary. Files that were processed successfully are dropped from the list; a file that fails (wrong password/key, damaged data) stays in the list with a red reason, without blocking the others.
- **Clear all files** empties the file lists and result, but not the loaded password/key.
- **End session** empties both Encrypt and Decrypt file lists, the result, and all credentials (password, keys). It never touches files already saved to disk.

### 4.2 Text Panel

Encrypts or decrypts text or chat-style messages, for pasting into email, chat apps, or anywhere else — even a public channel, since only the password or private-key holder can read it.

- Same **Method** choice as the File panel (password or public key), with an explicit **"Key password (leave blank if unprotected)"** label on the RSA side.
- The same persistent "cannot be recovered" warning appears here too.
- The AES password (or loaded RSA keys) stays in place across multiple messages in the same session, unlike the File panel's one-shot password fields — convenient for a back-and-forth conversation.
- **Nothing is saved automatically.** Messages and results stay in memory. **Save text…** saves the result currently displayed; the dialog starts in the `texts` folder, and you can choose another one. The saved file is a complete record — starting text and result together, with labels and a timestamp — so it is readable text, not pure Base64. For that reason it cannot be reloaded with **Load encrypted Base64…**, which needs a file containing only the Base64 ciphertext (for example, text obtained from elsewhere).
- ⚠ **A saved text file is not encrypted.** Anyone who can read it can read the plaintext.
- **Copy encrypted text / Copy decrypted text**: copies to the clipboard, flashes "Copied", and — when a clipboard backend is available — the clipboard clears itself automatically 15 seconds later.
- A lightweight **Clear** button next to the result clears only what is shown on screen — nothing is deleted from disk and the session continues — useful for quickly comparing separate runs.
- **End session** clears the session history, input, result, and all credentials (chat password, RSA public/private keys, key password) — but never deletes a file you already saved.

### 4.3 Key Generation Panel

Generates a new RSA-4096 key pair.

- Enter a descriptive **name** (a local label, not a verified identity). **Protecting the private key with a password is on by default**; turning it off hides the password fields and asks for confirmation before an unprotected key is created.
- Key-protection passwords must be 12–128 characters and include an uppercase letter, a lowercase letter, a digit, and a symbol; the panel gives live pass/fail feedback as you type.
- Two persistent warnings remind you that lost keys/passwords cannot be recovered, and that the private-key file and its password should be kept in separate, secure places.
- The **result card** shows the pair's SHA-256 fingerprint, the paths of the saved files (private key, public key, key information, and a QR code PNG of the public key), with **Open folder** and **Save QR image as…**. The QR is saved automatically and contains the public key only.
- Only the most recent result is shown. It clears automatically when you leave the page, and can be cleared manually with **Clear** — this only affects what is displayed, never the files already written to the `keys` folder.

### 4.4 Key Management Panel

For working with keys you already generated, rather than creating new ones:

- **Export public key from private key**: load a private key (and its password, if protected) to extract the matching public key into the `backup` folder; the result shows its SHA-256 fingerprint.
- **Back up keys**: **Choose keys to back up…** lets you pick private or public `.pem` keys from the `keys` folder, review the selection (remove any with ✕), then confirm with **Back up selected keys**. Copies keep their protection and go to the `backup` folder beside the application, or to another folder you choose. Originals are never touched.
- **Open backup folder** for direct access to what has been exported or backed up so far.
- The page resets completely when you navigate away from it.

### 4.5 Audit Log Panel

A local, metadata-only record of past operations — never plaintext or key material.

- Logs both **successful and failed** encrypt/decrypt attempts (wrong password, wrong key, format problems, integrity check failures), with the method, filenames, fingerprints, hashes, status, and timestamp for each entry. A literal `|` character in any logged field is escaped so it cannot be mistaken for a field separator.
- A **live filter/search box** narrows the visible entries as you type, and the view auto-scrolls to the newest entry.
- **Refresh** and **Open logs folder** give direct access to the underlying `encryption_audit.log` file.

### 4.6 About Panel

Project information rather than a working tool:

- A summary of the cryptographic design (AES-256-GCM, RSA-4096 with OAEP, PBKDF2-SHA-256, FSS2 containers, PKCS#8 keys) and the current size limits.
- A **key features** list.
- **"A note on responsible use"** — the same disclaimer summarized in [Chapter 1](#1-why-file-secure-suite): File Secure Suite is a neutral tool, provided as-is, and its author accepts no liability for how others use it.
- The Cypherpunk's Manifesto quote and attribution.
- **Support the project**: a Lightning Network donation QR code and address, with a one-click "Copy Lightning address" button.

## 5. Compatibility with OpenPGP, PGP, GnuPG, OpenSSL, and SSH

### 5.1 The Short Answer

File Secure Suite is **cryptographically related** to OpenPGP and uses key encodings supported by OpenSSL, but its encrypted FSS2 containers are **not directly format-compatible** with either OpenPGP messages or standard OpenSSL command output.

| Component | Compatibility |
|---|---|
| FSS public key | Standard PEM SubjectPublicKeyInfo; readable by OpenSSL tools and libraries |
| FSS private key | Standard PKCS#8 PEM; readable by OpenSSL-compatible tools when the key password is supplied if needed |
| FSS2 encrypted text/file | Custom authenticated container; not an OpenPGP packet stream and not an `openssl enc` file |
| OpenPGP public/secret key | OpenPGP packet/certificate format; not the same object as a standalone FSS PEM key |
| OpenPGP encrypted message | Not directly decryptable by File Secure Suite |
| Standard OpenSSL ciphertext | Not directly decryptable by File Secure Suite unless it independently follows the complete FSS2 format and parameters |

Sharing the same underlying algorithm name does not guarantee interoperability. Two systems must also agree on key encoding, padding, password derivation, nonce handling, authenticated data, metadata, binary layout, and text representation.

### 5.2 OpenPGP and PGP

PGP is a family of products and historical technology. **OpenPGP** is the interoperable message and key format standardized in RFC 9580. **GnuPG/GPG** is a widely used implementation of OpenPGP.

OpenPGP already uses hybrid encryption: it creates a one-time symmetric session key for the message and encrypts that session key for one or more recipients. Therefore, hybrid encryption is not a File Secure Suite invention and is not the reason to reject OpenPGP. It is the normal efficient design for public-key encryption of real messages and files.

OpenPGP additionally supports features that File Secure Suite does not currently implement, including:

- interoperable OpenPGP packet formats;
- multiple recipients in one encrypted message;
- digital signatures and sender authentication;
- User IDs, self-certification, subkeys, expiration, and revocation structures;
- mature keyrings and trust-management workflows;
- broad compatibility with existing OpenPGP software.

Use OpenPGP when those features, standardized interchange, long-term identity, signing, or compatibility with existing users are primary requirements.

File Secure Suite chooses a narrower model: independent PEM key files, direct fingerprint verification, one recipient per RSA container, no required identity, and a copy/paste-oriented interface. This can be easier for a short conversation or file exchange, but it transfers more responsibility to the participants to authenticate the public key and manage the private key correctly.

An FSS RSA key contains valid RSA material, but directly importing its standalone PEM file into an OpenPGP keyring does not turn it into a complete OpenPGP certificate. OpenPGP uses its own packet structures, identity bindings, self-signatures, capabilities, and related metadata. A deliberately designed conversion tool would need to create those structures and define their trust meaning; simple renaming or copy/paste is not conversion.

### 5.3 OpenSSL

OpenSSL is primarily a cryptographic toolkit, library, and command-line environment. It exposes primitives and key-processing functions from which many protocols and applications can be built. It is not one single conversation-oriented encrypted-message format.

File Secure Suite deliberately uses common OpenSSL-compatible PEM encodings for RSA keys:

- PKCS#8 PEM for private keys;
- SubjectPublicKeyInfo PEM for public keys.

This allows compatible tools to inspect or process the key material. It does not make FSS2 ciphertext an OpenSSL ciphertext format.

The common `openssl enc` command is especially not equivalent to FSS2. Current OpenSSL documentation states that `openssl enc` does not support authenticated modes such as GCM. OpenSSL libraries do provide AES-GCM and RSA-OAEP primitives through lower-level APIs, so a developer could implement FSS2 interoperability by reproducing the complete container specification and validation rules. That is implementation compatibility, not direct command-line compatibility.

Use OpenSSL when developing or diagnosing a protocol, converting supported key encodings, integrating cryptography into software, or following a separately defined standard. Use File Secure Suite when the desired workflow is a constrained local application for creating keys and exchanging FSS-formatted encrypted text or files.

### 5.4 Why File Secure Suite Still Uses Hybrid Encryption

The choice is not "OpenPGP or hybrid encryption." OpenPGP and File Secure Suite both use hybrid designs because RSA should not encrypt large messages directly.

File Secure Suite uses RSA-4096-OAEP to protect a fresh random AES-256 key, then AES-256-GCM to protect the content because this provides:

- efficient encryption of large text and files;
- a new random content-encryption key for every operation;
- public-key delivery without sharing a decryption secret;
- authenticated encryption of the payload and FSS2 header;
- a compact format suitable for binary files or Base64 copy/paste.

The distinctive project choice is the simplified, identity-neutral workflow and FSS2 container — not the general concept of hybrid encryption.

### 5.5 And Where Does SSH Fit?

SSH is a different category altogether: it secures a *live remote session* (a shell, a tunnel), not files or messages meant to be stored or sent elsewhere. It authenticates a user and/or host before opening that session, using its own OpenSSH key format (convertible to/from PKCS#8). It has no role in encrypting a file to attach to an email — that is the problem File Secure Suite, PGP, and (as a library) OpenSSL address, each with different trade-offs:

| | **OpenSSL** | **PGP / GnuPG** | **SSH** | **File Secure Suite** |
|---|---|---|---|---|
| **What it encrypts** | Generic data via `enc`/`pkeyutl`, TLS traffic — mainly a general-purpose cryptographic toolkit/library | Email and files, for offline exchange | The channel of a live remote session (shell, tunneling) — not files meant to be sent elsewhere | Text and files (batches of up to 5, combined up to 1 GiB), meant to be copied or sent elsewhere |
| **Encryption used** | Whatever the library supports (AES, RSA, ECC, …) — the engine many other tools, including FSS, are built on | Hybrid: symmetric for the payload + asymmetric for the session key (RSA or ECC) | Key exchange (e.g. Diffie-Hellman/ECDH) + real-time symmetric channel encryption | AES-256-GCM (password) or hybrid RSA-4096-OAEP + AES-256-GCM (public/private key) |
| **Identity / authentication** | Yes, via X.509 certificates and a CA trust chain | Yes, via a decentralized "web of trust" (no central CA) | Yes — its primary purpose: authenticating the user and/or host before opening the session | No — anonymous by design; keys identify only themselves, never a verified person |
| **Digital signatures** | Yes (signing/verifying documents, certificates) | Yes, native and central to typical use (signing email/files) | Yes, but only to authenticate the connection, not to sign external documents | No — encryption/decryption only, no signing capability |
| **Key format** | PKCS#8, X.509, and many others (the reference standard) | Proprietary OpenPGP format (keyring), often convertible today | Proprietary format (OpenSSH), convertible to/from PKCS#8 | PKCS#8 (private) / SubjectPublicKeyInfo (public) — OpenSSL-compatible |
| **Key distribution** | Manual, or via CA/certificates | Public key servers, web of trust, manual exchange | Manual (`authorized_keys`) or an SSH CA | Manual, out-of-band (users exchange public keys however they prefer) |
| **Typical use** | Library/engine underlying other tools; TLS certificate management | Encrypting/signing email and files for secure correspondence | Secure remote access to servers, tunneling | Encrypting a text or file to share (even publicly) while staying anonymous |

In short: OpenSSL is the low-level cryptographic engine that also sits underneath File Secure Suite (via Python's `cryptography` library, itself built on OpenSSL's `libcrypto`). PGP is the closest direct competitor for FSS's actual purpose — encrypting text/files for exchange — but adds signing and web-of-trust that FSS deliberately omits. SSH is an entirely different category: authenticating and encrypting *live sessions*, not content meant to be sent elsewhere. FSS carves out a narrow niche: anonymous encryption/decryption of text and files only, without PGP's identity/signing complexity.

### 5.6 Choosing Among Them

| Need | Better starting point |
|---|---|
| Quick FSS-to-FSS chat or file exchange with disposable, independently managed key files | File Secure Suite |
| Standardized exchange with existing PGP/GPG users | OpenPGP/GnuPG |
| Digital signatures, certification, key expiration, revocation, or multi-recipient messages | OpenPGP or another reviewed protocol that supplies those features |
| Library-level cryptographic development or key-format inspection | OpenSSL APIs and tools |
| Authenticating and encrypting a live remote session | SSH |
| Transport anonymity or metadata hiding | A dedicated anonymity system; none of these tools provides it by itself |

Choosing File Secure Suite means choosing its simple workflow and accepting its current interoperability and identity limitations. It should not be described as a replacement for every OpenPGP, OpenSSL, or SSH use case.

## 6. Core Concepts

### 6.1 Encryption, Authentication, and Identity

These are different security properties:

- **Confidentiality** prevents people without the required secret from reading the plaintext.
- **Integrity and authentication of the encrypted container** detect changes to the protected data and authenticated header.
- **Sender identity** proves who created or approved a message.

File Secure Suite provides confidentiality and authenticated encryption. It does **not** currently create digital signatures, certificates, or a proof of sender identity. A valid RSA-encrypted message proves only that the container can be opened by the matching private key; anyone who possesses the public key could have created it.

### 6.2 Symmetric and Asymmetric Cryptography

Symmetric encryption uses the same secret for encryption and decryption. In this suite, the user enters a password and the system derives a 256-bit AES key from it.

Asymmetric cryptography uses a mathematically related key pair:

- the **public key** is distributed to people who need to encrypt data for its owner;
- the **private key** is retained by the owner and is required for decryption.

RSA is not used to encrypt an entire file or message directly. It protects a randomly generated AES key, while AES-256-GCM encrypts the actual content. This is called **hybrid encryption**.

## 7. Password-Based Encryption

### 7.1 How It Works

For each encryption operation, the suite:

1. generates a fresh random 16-byte salt;
2. derives a 32-byte AES key from the password using PBKDF2-HMAC-SHA-256 with 600,000 iterations;
3. generates a fresh random 12-byte AES-GCM nonce;
4. encrypts the text or file payload with AES-256-GCM;
5. authenticates the FSS2 header together with the encrypted content.

The salt and nonce are stored in the encrypted container. They are not secrets and do not reveal the password. Their purpose is to make separate encryption operations unique, even when the same password and plaintext are used again.

### 7.2 What the Password Means

The password is the effective decryption secret. The original password is not stored in the container, but an attacker who obtains the encrypted data can attempt password guesses offline. PBKDF2 makes each guess more expensive; it cannot make a predictable password strong.

The suite accepts a unique password or passphrase between 12 and 128 characters and rejects highly repetitive values. Prefer a long, randomly generated password or a high-entropy passphrase that is not used for any other service.

### 7.3 Consequences of Password Mode

- Anyone who knows the password can both encrypt and decrypt.
- The password must be exchanged through a separate secure channel when multiple people use it.
- Changing the password does not modify existing encrypted containers. Existing data must be decrypted and encrypted again with the new password.
- If the password is forgotten, there is no recovery mechanism or back door.
- Reusing one password for many containers increases the impact of disclosure.

## 8. Public-Key Hybrid Encryption

### 8.1 How It Works

For each encryption operation, the suite:

1. generates a fresh random 256-bit AES key;
2. generates a fresh random 12-byte AES-GCM nonce;
3. encrypts the text or file payload with AES-256-GCM;
4. encrypts the temporary AES key with the recipient's RSA public key using RSA-OAEP with SHA-256 and MGF1-SHA-256;
5. stores the RSA-wrapped AES key and authenticated ciphertext in the FSS2 container.

During decryption, the matching RSA private key first recovers the temporary AES key. AES-256-GCM then authenticates and decrypts the content.

```text
Plaintext
   |
   |  random AES-256 key
   v
AES-256-GCM encryption --------------------> authenticated ciphertext
   |
   |  AES key wrapped with RSA-4096-OAEP
   v
FSS2 container = header + wrapped AES key + ciphertext

Matching RSA private key -> unwrap AES key -> authenticate -> plaintext
```

### 8.2 Why Hybrid Encryption Is Used

AES is efficient for large amounts of data. RSA is designed for small values and has strict input-size limits. Hybrid encryption combines AES performance with the public/private separation of RSA.

Calling this mode "RSA encryption" is convenient in the interface, but the content itself is encrypted with AES-256-GCM. RSA-4096 encrypts only the temporary AES key.

### 8.3 Consequences of Public-Key Mode

- The public key can be shared freely after its authenticity has been verified.
- The private key must never be shared.
- A sender does not need the private key and cannot decrypt the result using the public key.
- Every intended recipient normally needs a separate encrypted copy. One FSS2 container is associated with one RSA key pair.
- Losing the private key makes the corresponding encrypted data unrecoverable.
- Stealing the private key may expose all containers encrypted for that key, unless access to the key file is still blocked by a strong key-protection password.
- Replacing a public key during distribution can redirect future encrypted data to an attacker. Verify fingerprints before use.

### 8.4 What Protection Does the Key Pair Provide?

The key pair separates the ability to **send protected data** from the ability to **read it**. Possession of the public key grants encryption capability only. Possession of the private key grants decryption capability for containers created for that pair.

This separation protects against an interceptor who obtains the public key and encrypted messages but not the private key. It does not protect against:

- theft of the private key together with its password;
- malware reading the private key or plaintext while the computer is in use;
- substitution of the public key before its fingerprint is verified;
- plaintext copied to the clipboard, saved to text files, or left in recovered files;
- future cryptanalytic changes, including a cryptographically relevant quantum computer.

## 9. Public Key, Private Key, and Key Password

### 9.1 Public Key

The public key is stored as an interoperable PEM file using the SubjectPublicKeyInfo format. It is used only to encrypt for the key owner and to calculate the key fingerprint.

The public key:

- may be copied and distributed;
- cannot decrypt data;
- does not need a password;
- must still be authenticated, because an attacker could substitute a different public key.

### 9.2 Private Key

The private key is stored as a PKCS#8 PEM file. It is the sensitive half of the key pair and is required to decrypt RSA-mode containers.

The private key:

- must remain under the owner's control;
- should be backed up securely and separately from the main computer;
- should not be sent through chat, email, or ordinary cloud sharing;
- cannot be reconstructed from the public key;
- has no recovery path if every copy is lost.

The suite generates RSA keys at 4096 bits and rejects RSA keys below 4096 bits. It accepts usable RSA private or public keys up to 8192 bits when loading them.

### 9.3 Password Protecting the Private Key

A private-key password and a data-encryption password serve different purposes.

| Secret | What it protects | When it is required |
|---|---|---|
| Data-encryption password | The AES-encrypted text or file | When encrypting and decrypting in password mode |
| Private-key password | The private PEM file stored on disk | When loading that private key for RSA decryption or public-key export |

Protecting the private key with a password encrypts the PKCS#8 PEM file at rest. It does not replace the private key, change the recipient's public key, or add another password directly to every FSS2 container.

If an attacker steals an encrypted private-key file, the key password creates an additional barrier. Once the correct password unlocks the key in a running process, the private key can perform decryption. Use a strong, unique password and do not store it beside the key file.

For private-key protection, the suite requires 12–128 characters with at least one uppercase letter, one lowercase letter, one digit, and one supported special character.

### 9.4 Keys Loaded in the Application

Key creation saves the generated pair to disk but does not automatically place it into a permanent key list. In the Text and File panels, a loaded public or private key remains available to that panel until it is replaced, cleared, or the application closes.

The **Clear** control removes the selected key from the current interface state. It does not delete the PEM file. It also must not be treated as guaranteed forensic erasure of every temporary copy that may have existed in process or operating-system memory.

## 10. Fingerprints and Key Verification

The suite calculates a full SHA-256 fingerprint of the canonical public key in DER SubjectPublicKeyInfo form, shown in **Key Generation** and **Key Management** (which can also export it as a QR code). The public key and its matching private key produce the same public-key fingerprint.

Use the fingerprint to identify keys by cryptographic content rather than filename. Verify it through an independent trusted channel, for example a known voice call or an in-person comparison.

Do not rely only on:

- the PEM filename;
- the name written in a message;
- the channel used to receive the public key;
- a short fingerprint fragment when a full comparison is possible.

Renaming a key file does not alter its fingerprint. The generated `_info.txt` file records the full fingerprint and creation details, but it is descriptive metadata and not a certificate or digital signature.

## 11. Text Workflow

The Text panel keeps encryption and decryption available at the same time for chat-style use (see [4.2](#42-text-panel) for the full interface walkthrough).

### 11.1 Public-Key Conversation

1. Obtain and verify the other person's public key.
2. Load that public key in the encryption side.
3. Type or paste plaintext and encrypt it.
4. Copy the Base64 result into the external chat application.
5. Load your own private key in the decryption side.
6. Paste received encrypted text and decrypt it.
7. Change or clear either key whenever the conversation changes recipient or identity.

Each participant normally encrypts outgoing messages with the other participant's public key and decrypts incoming messages with their own private key.

### 11.2 Password Conversation

Both participants must already possess the same password. Exchange it separately from the encrypted messages. Anyone who learns it can read all compatible messages encrypted with it.

### 11.3 Base64 Is Not Encryption

Encrypted text is displayed as Base64 so it can be copied through text-only systems. Base64 only represents binary bytes as printable characters. Removing or decoding Base64 does not decrypt the protected content.

### 11.4 Saving Text Results

Nothing in the Text workflow is written to disk automatically. Use **Save text…** to save the result currently displayed; the dialog starts in the `texts` folder and you may choose any other location. The saved file is an ordinary `.txt` containing both the starting text and the result, with labels and a timestamp.

> **A saved text file is not encrypted.** Anyone who can read it can read the plaintext. Delete, move, or separately protect saved files when they are no longer required.

Because the saved file also contains readable text, it cannot be loaded back with **Load encrypted Base64…**; that button is for files containing only the Base64 ciphertext. Saving a file does not securely erase anything from storage, and **End session** never deletes files you already saved.

## 12. File Workflow

File Secure Suite encrypts or decrypts a **batch of up to 5 files** (combined size up to 1 GiB) with one shared password or key pair per batch (see [4.1](#41-file-panel) for the full interface walkthrough).

### 12.1 Encrypting with a Password

1. Select **File** and **Encrypt**.
2. Select **Password (AES-256-GCM)**.
3. Drag and drop one or more files (up to 5, combined up to 1 GiB) and enter the password twice.
4. Run encryption. The result is saved automatically in the `files` folder; a single file shows its path, fingerprint, and size/time, and a batch shows a per-file ✓/✗ summary. **Export Base64 copy** is optional.

### 12.2 Encrypting with a Public Key

1. Select **File** and **Encrypt**.
2. Select the RSA public-key method.
3. Choose the input file(s) and the verified recipient public key.
4. Run encryption. The generated `.rsa` output(s) are saved automatically in the `files` folder; **Export Base64 copy** optionally adds a `.rsa.b64` version.

### 12.3 Decrypting

The suite detects the method from the FSS container when possible. Password-mode data requires the original password. RSA-mode data requires the matching private key and, if that PEM is protected, its private-key password. In a batch, a file that fails (wrong password/key, damaged container) is reported in the summary without blocking the other files in the same batch.

The original filename is stored inside the encrypted payload and restored after decryption. However, the suggested encrypted output filename also includes the original name, so the filename itself may reveal information even though the file content is encrypted.

## 13. The FSS2 Container Format

New encryption operations create an authenticated FSS2 version 2 container. It records:

- the FSS2 identifier and format version;
- the encryption mode;
- whether the payload is text or a file;
- password-derivation parameters when applicable;
- random salt and nonce values;
- the RSA-wrapped AES key in public-key mode;
- the AES-GCM ciphertext and authentication tag.

The header is authenticated as AES-GCM associated data. Changing authenticated parameters or ciphertext causes decryption to fail.

The suite can decrypt legacy FSS1 containers for compatibility. New data should use FSS2. File Secure Suite containers are application formats; generic AES or RSA tools cannot decrypt them without reproducing the container layout and parameters. The exact byte layout of both formats is documented in [`FORMAT_SPECIFICATIONS.md`](FORMAT_SPECIFICATIONS.md).

### 13.1 Migrating an Old FSS1 File to FSS2

File Secure Suite has no in-place "upgrade" button, because upgrading means re-encrypting, which always requires the original password or private key. To move a file from the old format to the new one:

1. Decrypt the FSS1 file normally (the app detects the legacy format automatically and decrypts it like any other file).
2. Encrypt the resulting plaintext again, choosing the same or a different password/key pair — this produces a new FSS2 container.
3. Once you have verified the new FSS2 file decrypts correctly, securely delete the old FSS1 file and the intermediate plaintext copy if they are no longer needed.

There is no bulk/batch conversion tool; each file is migrated by decrypting and re-encrypting it individually.

## 14. Files, Folders, and Local Data

The suite creates its working folders beside the application files (beside the `.exe` when you use the Windows executable) — not in any shared system location. This is what makes it portable: run it from a USB drive or any folder on any of your computers, and every copy keeps its own keys, files, saved text, and audit log, entirely separate from any other copy or user.

| Folder | Contents | Confidentiality note |
|---|---|---|
| `keys` | Generated public/private PEM pairs, key information, and the public-key QR PNG | Private PEM files are sensitive; `_info.txt` is not secret key material |
| `texts` | Text you saved with **Save text…** (starting text and result together); nothing is written here automatically | Saved text files are plaintext; not encrypted |
| `files` | Encrypted outputs and recovered files | Recovered files are plaintext; encrypted filenames may reveal the original name |
| `backup` | Key backups and exported public keys | Treat private-key backups as highly sensitive |
| `logs` | Audit log | Metadata only, but may include filenames, methods, fingerprints, hashes, status, and errors |

The **Open folder** controls provide direct access to these locations. They do not change file permissions beyond the protections applied by the suite when creating its own files and directories.

## 15. Limits and Operational Characteristics

- Maximum plaintext file size: 1 GiB per operation, combined across a batch of up to 5 files.
- Maximum text size: 1 MiB.
- Maximum loaded key file size: 64 KiB.
- File encryption is memory based; available RAM can impose a lower practical limit (the app checks available memory before each operation, with a 5x safety margin).
- Text is encoded and decoded as UTF-8.
- Binary containers may be stored directly or represented as Base64.
- Existing encrypted data is not automatically re-encrypted when a password or key changes.
- There is no password recovery, private-key recovery, escrow, or administrator override.

### 15.1 How Long Would It Take to Break the Encryption?

There is no single honest answer such as "500 years." The result depends on what is being attacked:

- the AES key;
- the RSA private key;
- a human password;
- the operating system, backup, clipboard, or unlocked application;
- the public-key distribution process.

These attacks have radically different costs. In practice, attackers usually target the password, private-key file, computer, or user before attempting to break the mathematics.

#### AES-256

An ideal exhaustive search of a uniformly random AES-256 key has 2^256 possible keys and requires about 2^255 trials on average. As a deliberately unrealistic illustration, even a machine testing one quintillion (10^18) independent keys every second would need roughly 1.8 × 10^51 years on average. This figure explains the scale; it is not a prediction about a particular implementation or future discovery.

In password mode, however, the AES key is derived from a password. The practical protection therefore cannot exceed the unpredictability of that password. A human-chosen 12-character password can be vastly easier to guess than a random 256-bit AES key. PBKDF2 with 600,000 SHA-256 iterations slows guessing but does not rescue a common phrase, reused password, keyboard pattern, or leaked credential.

#### RSA-4096

RSA is attacked by factoring a large composite number, not by trying every 4096-bit string. The text "4096 bit" therefore must not be compared directly with "AES-256." NIST's published comparison points associate RSA-3072 with about 128 bits of classical security strength and RSA-7680 with about 192 bits. RSA-4096 lies between those reference sizes; the exact real-world work factor is model dependent.

No credible fixed completion time can be assigned to factoring a correctly generated RSA-4096 key with classical computers. It is considered outside practical classical attacks when correctly implemented, but the complete hybrid system is limited by its weakest component and by key handling.

#### Passwords and Protected Private Keys

A password attack can be far more realistic than breaking AES or factoring RSA. Its duration depends on:

- how the password was generated and its real entropy;
- whether it was reused or previously leaked;
- the attacker's hardware and software;
- the cost of the password-derivation or PEM-protection mechanism;
- the number and quality of guesses available from personal information.

Length and randomness matter more than merely satisfying composition rules. A password manager-generated value or a genuinely random multiword passphrase is preferable to a predictable word with a capital letter, number, and symbol appended.

#### Quantum-Computing Limitation

RSA-4096 is not post-quantum encryption. A sufficiently capable fault-tolerant quantum computer running an appropriate algorithm could make today's RSA unsafe. File Secure Suite (Core 1.1.0) does not implement a post-quantum key-encapsulation method. Data that must remain confidential for many years should account for "harvest now, decrypt later" risk and use a reviewed post-quantum or hybrid migration strategy.

AES-256 is generally given a larger margin against generic quantum search than AES-128, but that does not make the overall RSA/AES mode post-quantum: RSA remains the public-key component protecting the AES key.

### 15.2 Practical Interpretation

For a normal user, the useful question is not only "How long does the algorithm take to break?" but also:

1. Is the password genuinely unpredictable?
2. Is the public-key fingerprint verified?
3. Is the private key protected and backed up safely?
4. Is the computer free from malware?
5. Are plaintext files and saved text files handled securely?
6. Must the information remain secret into the post-quantum future?

Strong answers to these questions usually matter more than increasing a nominal key-size number.

## 16. Recommended Operating Practice

1. Generate a separate RSA key pair for each identity or security context.
2. Protect private keys with a unique high-entropy password.
3. Keep at least one verified offline backup of every required private key.
4. Keep private-key backups separate from their passwords.
5. Verify full public-key fingerprints through a second trusted channel.
6. Never send a private key to someone who only needs to encrypt for you.
7. Do not reuse data-encryption passwords across unrelated people or projects.
8. Treat decrypted files, saved plaintext, saved text files, clipboard contents, and audit metadata according to their sensitivity.
9. Test recovery from a backup before relying on the system for irreplaceable data.
10. Retain an older private key as long as data encrypted for it may still need to be decrypted.

## 17. Choosing the Correct Mode

Use **password mode** when:

- you are protecting your own local archive;
- all authorized users already share a strong secret securely;
- simple shared-secret operation is more important than separate sender and recipient capabilities.

Use **public-key mode** when:

- other people must encrypt data for you without receiving a decryption secret;
- you need to change or distribute encryption capability independently from the private decryption capability;
- you can verify public-key fingerprints and maintain reliable private-key backups.

Neither mode provides sender signatures. If sender identity, non-repudiation, or signed software distribution is required, a separate digital-signature workflow is needed.

## 18. Failure Interpretation

An authentication failure deliberately does not always distinguish among a wrong password, wrong private key, damaged container, or deliberate modification. Generic failure messages reduce the amount of information exposed to an attacker.

A failed operation does not prove that the original plaintext is damaged. Preserve the encrypted source and verify the password, key fingerprint, key password, and backup copies before taking corrective action.

---

File Secure Suite is a security tool, not a complete key-management infrastructure. Its cryptographic protection is only one part of a secure process that also includes authentic key distribution, endpoint security, backups, access control, and careful handling of plaintext.

## 19. Official References

- [NIST FIPS 197: Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-57 Part 1 Revision 5: Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST: What Is Post-Quantum Cryptography?](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography)
- [RFC 9580: OpenPGP](https://www.rfc-editor.org/rfc/rfc9580.html)
- [GnuPG Manual: OpenPGP Key Management](https://gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html)
- [OpenSSL documentation: `openssl enc`](https://docs.openssl.org/3.6/man1/openssl-enc/)
