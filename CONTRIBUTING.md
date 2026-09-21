# Contributing to File Secure Suite

Thanks for your interest in contributing. This is a small, single-maintainer open-source project, so please bear with response times — but bug reports, ideas, and pull requests are genuinely welcome.

## Before you start

- For a **security vulnerability**, do not open a public issue — see [`SECURITY.md`](SECURITY.md) for private reporting instructions.
- For anything else — bugs, feature ideas, questions — open a [GitHub Issue](https://github.com/marianopeluso/FileSecureSuite/issues) first, especially before starting significant work, so we can agree on the approach before you invest time in a pull request.

## Reporting a bug

Please include:

- Your OS and Python version, and the app version (shown at the bottom of the sidebar, e.g. `GUI 2.0.0 / Core 1.1.0`)
- Exact steps to reproduce
- What you expected vs. what happened
- Any error message or traceback (please redact filenames or paths if they're sensitive — never share a password, a private key, or its file)

## Proposing a feature

Open an issue describing the use case, not just the mechanism — what problem it solves and for whom. Given the project's scope (a focused, dependency-light encryption tool, not a full PGP/key-management suite), features that add significant complexity or new external dependencies will be discussed carefully before being accepted.

## Development setup

```bash
git clone https://github.com/marianopeluso/FileSecureSuite.git
cd FileSecureSuite
pip install -r requirements.txt
python FileSecureSuite_2_0_0.py
```

`fss_core_1_1_0.py` (the cryptographic engine) must stay in the same directory as the GUI file — the GUI imports it directly by module name.

## Code guidelines

- **Keep `fss_core_*.py` UI-free.** The core module must contain no GUI imports and no user-interface code — it is the security-critical surface, kept small and auditable on its own.
- **Never weaken a security default silently.** Any change to cryptographic parameters (KDF iterations, key sizes, algorithms, size limits) must be called out explicitly in the pull request description and, once merged, in `CHANGELOG.md` and (if relevant) `FORMAT_SPECIFICATIONS.md`.
- **Preserve backward-compatible decryption.** Existing FSS2 (and legacy FSS1) files must remain decryptable; if a change affects the container format, it must introduce a new, explicitly versioned format rather than altering FSS2 in place.
- Match the existing style: plain, explicit Python, no exotic dependencies, comments that explain *why* a security-relevant check exists (see `fss_core_1_1_0.py` for the tone to match).
- Run the module you changed through `python -m py_compile <file>` before submitting, and manually verify: at minimum, one encrypt/decrypt round trip per mode you touched (password and RSA), across a fresh RSA key pair if you touched key handling.

## Building the Windows executable

Releases use a single-file executable built with PyInstaller. In a clean virtual environment with the runtime dependencies installed:

```
pip install pyinstaller
pyinstaller --onefile --windowed FileSecureSuite_2_0_0.py
```

`fss_core_1_1_0.py` is picked up automatically because the GUI imports it; keep both files in the same folder. The result is `dist\FileSecureSuite_2_0_0.exe`. Do not commit build output (`build/`, `dist/`, `*.spec`, `*.exe`): executables go only on the Releases page (zipped together with the public key), with a SHA-256 checksum and GPG signature of the zip.

## Versioning

The project loosely follows [Semantic Versioning](https://semver.org/): the GUI (`FileSecureSuite_X_Y_Z.py`) and the core engine (`fss_core_X_Y_Z.py`) are versioned and released independently, since a GUI-only change doesn't require a new core file. Breaking changes to the container format or a major interface rewrite bump the major version (as happened for 1.0.5 → 2.0.0).

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep the PR focused on one change — small, reviewable PRs are much easier to merge than large ones.
3. Describe *what* changed and *why*, and call out any security-relevant implication explicitly.
4. Update `CHANGELOG.md`, and `FORMAT_SPECIFICATIONS.md` / `SECURITY.md` if the change touches the container format or the security model.
5. Be responsive to review feedback — this keeps things moving for both of us.

## License

By contributing, you agree that your contribution is licensed under the project's [MIT License](LICENSE).
