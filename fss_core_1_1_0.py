#!/usr/bin/env python3
"""File Secure Suite cryptographic engine.

Provides AES-256-GCM password encryption, RSA-4096 hybrid encryption,
FSS2 containers, legacy FSS1 decryption, key handling, fingerprinting,
and protected file I/O. The module contains no user-interface code.
"""

import os
import stat
import re
import struct
import secrets
import hashlib
import hmac
import threading
import time
import base64
import platform
from pathlib import Path
from typing import Tuple, Optional

CORE_VERSION = "1.1.0"

os.umask(0o077)  # Only owner can read/write files by default.

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False


IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'

PBKDF2_ITERATIONS = 600000  # Application policy; not an OpenSSL default
PBKDF2_HASH_ALGORITHM = hashes.SHA256()
AES_KEY_SIZE = 32  # 256 bits
RSA_KEY_SIZE = 4096
# AESGCM processes data in memory; enforce an absolute input limit.
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GiB
MAX_TEXT_SIZE = 1024 * 1024
MAX_KEY_SIZE = 64 * 1024
MAX_ENCRYPTED_SIZE = MAX_FILE_SIZE + 4096
MAX_ENCODED_SIZE = 4 * ((MAX_ENCRYPTED_SIZE + 2) // 3)
# Allow for simultaneous input, output, and optional Base64 buffers.
MEMORY_SAFETY_MARGIN = 5.0
FSS2_HEADER = struct.Struct('>4sBBBBIH')
_clipboard_value = None
_clipboard_lock = threading.Lock()
CLIPBOARD_CLEAR_TIMEOUT = 15
MIN_ENCRYPTED_SIZE = 32

def reject_links(path):
    """Reject symlinks and Windows reparse points in existing path components."""
    candidate = Path(os.path.abspath(path))
    for part in (candidate, *candidate.parents):
        try:
            info = os.lstat(part)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Symlinks and reparse points are not allowed for this operation')

def protect_path(path, create_file=False):
    """Apply owner-only permissions; fail closed if protection cannot be set.

    Windows uses a protected DACL granting full control only to the current
    process user and LocalSystem. Administrative takeover remains possible.
    """
    reject_links(path)
    if not IS_WINDOWS:
        if create_file:
            return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.chmod(path, 0o700 if os.path.isdir(path) else 0o600)
        return
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi.SetFileSecurityW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    sid_text = wintypes.LPWSTR()
    descriptor = ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value:
            raise ctypes.WinError(ctypes.get_last_error())
        info = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, info, needed.value, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        # TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first member is PSID.
        sid = ctypes.cast(info, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        inherit = 'OICI' if os.path.isdir(path) else ''
        sddl = f'D:P(A;{inherit};FA;;;{sid_text.value})(A;{inherit};FA;;;SY)'
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if create_file:
            # Apply the DACL at creation: no interval with inherited permissions.
            import msvcrt
            class SecurityAttributes(ctypes.Structure):
                _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p),
                            ('inherit_handle', wintypes.BOOL)]
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            handle = kernel.CreateFileW(str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            except Exception:
                kernel.CloseHandle(handle)
                raise
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)

def ensure_private_directory(path):
    reject_links(path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    protect_path(path)

def read_limited(path, limit):
    reject_links(path)
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError(f'Input must be a regular file no larger than {limit} bytes')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('Input changed or exceeds size limit')
        data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Input exceeds size limit')
        return data

def get_available_memory_bytes() -> Optional[int]:
    """Best-effort free-RAM probe. Returns None if it cannot be determined
    on this platform; callers must treat None as 'unknown', not 'zero'."""
    try:
        if IS_WINDOWS:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong),
                    ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', ctypes.c_uint64),
                    ('ullAvailPhys', ctypes.c_uint64),
                    ('ullTotalPageFile', ctypes.c_uint64),
                    ('ullAvailPageFile', ctypes.c_uint64),
                    ('ullTotalVirtual', ctypes.c_uint64),
                    ('ullAvailVirtual', ctypes.c_uint64),
                    ('ullAvailExtendedVirtual', ctypes.c_uint64),
                ]

            status = MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return None
            return int(status.ullAvailPhys)
        names = getattr(os, 'sysconf_names', {})
        if hasattr(os, 'sysconf') and 'SC_AVPHYS_PAGES' in names and 'SC_PAGE_SIZE' in names:
            pages = os.sysconf('SC_AVPHYS_PAGES')
            page_size = os.sysconf('SC_PAGE_SIZE')
            if pages >= 0 and page_size > 0:
                return int(pages) * int(page_size)
    except Exception:
        pass
    return None

def check_available_memory(required_bytes: int, margin: float = MEMORY_SAFETY_MARGIN):
    """Refuse only when we can positively confirm memory is insufficient.

    An in-memory operation on a file this size needs roughly `margin` times
    its size at once (source buffer, output buffer, optional base64 copy).
    If the free-RAM probe is unavailable on this platform, we proceed
    without blocking: an unverifiable guess is worse than no guess, and we
    would rather risk a rare, user-visible failure on an unsupported
    platform than reject valid operations we cannot actually check.
    """
    needed = int(required_bytes * margin)
    available = get_available_memory_bytes()
    if available is not None and available < needed:
        raise ValueError(
            f"Not enough free RAM for this operation: need ~{format_size(needed)} free "
            f"(file size x{margin:g} for safety), only {format_size(available)} available. "
            f"Close other applications or process a smaller file."
        )

def decode_container(raw):
    if len(raw) > MAX_ENCODED_SIZE:
        raise ValueError('Encoded input exceeds size limit')
    if raw.startswith((b'FSS1', b'FSS2')):
        data = raw
    else:
        compact = b''.join(raw.split())
        data = base64.b64decode(compact, validate=True)
    if not MIN_ENCRYPTED_SIZE <= len(data) <= MAX_ENCRYPTED_SIZE:
        raise ValueError('Encrypted input size is invalid')
    if not data.startswith((b'FSS1', b'FSS2')):
        raise ValueError('Unsupported encrypted file format')
    return data

def detect_payload_format(data, filename=''):
    if data.startswith(b'FSS2'):
        algorithm, _, _, _, _, _ = parse_v2(data)
        return 'aes' if algorithm == 1 else 'rsa'
    if not data.startswith(b'FSS1'):
        raise ValueError('Unsupported encrypted file format')
    name = filename.lower()
    if name.endswith(('.aes', '.aes.b64')):
        return 'aes'
    if name.endswith(('.rsa', '.rsa.b64')):
        return 'rsa'
    return None

def recover_file_payload(plaintext, encrypted_data, filepath):
    is_file = encrypted_data.startswith(b'FSS1') or encrypted_data[6] == 1
    if is_file:
        parts = plaintext.split(b'\x00', 1)
        if len(parts) == 2 and 0 < len(parts[0]) < 256:
            name = output_basename(parts[0].decode('utf-8', errors='replace'))
            return name or 'file', parts[1]
        if encrypted_data.startswith(b'FSS2'):
            raise ValueError('Invalid encrypted file metadata')
    return ('text.txt' if encrypted_data.startswith(b'FSS2') else
            sanitize_filename(os.path.basename(filepath))[:160] or 'file'), plaintext

def detect_encryption_format(file_path: str) -> Optional[str]:
    try:
        data = decode_container(read_limited(file_path, MAX_ENCODED_SIZE))
        return detect_payload_format(data, file_path)
    except (OSError, ValueError):
        return None

def clear_clipboard_after(timeout: int, expected: Optional[str] = None):
    time.sleep(timeout)
    clear_owned_clipboard(expected)

def copy_sensitive_text(text) -> bool:
    """Copy text to the clipboard, self-clearing after CLIPBOARD_CLEAR_TIMEOUT
    seconds. Returns True on success, False if there is no way to reach the
    system clipboard from here - no `pyperclip` installed, or (common on a
    bare/headless Linux box) no clipboard backend such as xclip/xsel/
    wl-clipboard present for it to use. Callers must treat False as a normal,
    expected outcome and fall back to telling the user how to select/copy the
    text by hand, not as an error to surface as a stack trace."""
    global _clipboard_value
    if not HAS_PYPERCLIP:
        return False
    try:
        with _clipboard_lock:
            pyperclip.copy(text)
            _clipboard_value = text
        threading.Thread(target=clear_clipboard_after,
                         args=(CLIPBOARD_CLEAR_TIMEOUT, text), daemon=True).start()
        return True
    except Exception:
        return False

def clear_owned_clipboard(expected=None):
    global _clipboard_value
    with _clipboard_lock:
        value = _clipboard_value if expected is None else expected
        if value is None or not HAS_PYPERCLIP:
            return
        try:
            if pyperclip.paste() == value:
                pyperclip.copy('')
            if _clipboard_value == value:
                _clipboard_value = None
        except Exception:
            pass

def validate_password_strength(password: str) -> Tuple[bool, str]:
    if not password or not 12 <= len(password) <= 128:
        return False, 'Use a unique password or passphrase of 12–128 characters.'
    if len(set(password)) < 5:
        return False, 'Password is too repetitive.'
    return True, 'Password length accepted; use a unique, unpredictable passphrase.'

def estimate_password_weakness(password: str) -> bool:
    """Coarse, dependency-free heuristic for a password that clears the
    minimum length/diversity bar in validate_password_strength() but is
    still easy to guess: too few distinct characters for its length, a
    short repeating cycle ('123123123123'), or a long run of consecutive
    character codes ('abcdefgh', '87654321').

    This does not reject anything by itself - callers keep accepting the
    password and only use this to decide whether to show a non-blocking
    'this looks weak' warning. It is not a real entropy estimate and will
    miss plenty of weak passwords (e.g. dictionary words, keyboard walks
    like 'qwerty'); it only catches the common repetitive/sequential cases.
    """
    if not password:
        return False
    length = len(password)
    unique = len(set(password))

    if unique <= max(5, length // 3):
        return True

    for period in range(1, length // 2 + 1):
        repeated = (password[:period] * (length // period + 1))[:length]
        if repeated == password:
            return True

    run = best_run = 1
    for i in range(1, length):
        delta = ord(password[i]) - ord(password[i - 1])
        run = run + 1 if delta in (1, -1) else 1
        best_run = max(best_run, run)
    if best_run >= 5:
        return True

    return False

def validate_password_strength_key(password: str) -> Tuple[bool, str]:
    """Stricter validation for RSA key protection (12+ chars, number, uppercase, symbol required)"""
    if not password:
        return False, "Password cannot be empty"
    if len(password) < 12:
        return False, "Key password too short (minimum 12 characters)"
    if len(password) > 128:
        return False, "Password too long (maximum 128 characters)"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    if not has_upper:
        return False, "Key password must contain uppercase letter (A-Z)"
    if not has_lower:
        return False, "Key password must contain lowercase letter (a-z)"
    if not has_digit:
        return False, "Key password must contain digit (0-9)"
    if not has_special:
        return False, "Key password must contain special character (!@#$%^&*...)"

    return True, "Key password strength: STRONG ✅"

def safe_display(value: str) -> str:
    """Escape terminal controls without modifying saved/copied plaintext."""
    return ''.join(c if c.isprintable() or c in '\n\t' else '\\x%02x' % ord(c)
                   for c in value).replace('\r', '\\r')

def sanitize_filename(filepath: str) -> str:
    basename = os.path.basename(filepath)
    basename = basename.replace('/', '_').replace('\\', '_').replace('..', '_')
    basename = ''.join(c if ord(c) >= 32 and ord(c) < 127 and c not in '<>:"|?*' else '_'
                       for c in basename)
    return basename

def output_basename(name: str) -> str:
    """Keep ordinary Unicode filenames; strip paths and Windows-unsafe characters."""
    name = name.replace('\\', '/').rsplit('/', 1)[-1]
    name = ''.join(c if c.isprintable() and c not in '<>:"/\\|?*' else '_' for c in name)
    name = name.strip().rstrip('.') or 'file'
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {f'{p}{n}' for p in ('COM', 'LPT') for n in range(1, 10)}
    if name.split('.')[0].upper() in reserved:
        name = '_' + name
    return name

def get_unique_filename(base_name: str, extension: str = "") -> str:
    base_name = sanitize_filename(base_name)[:80] or 'file'
    extension = sanitize_filename(extension)[:160] if extension else ''
    suffix = '.' + extension.lstrip('.') if extension else ''
    return f'{base_name}_{secrets.token_hex(16)}{suffix}'

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0.0 to 8.0 for bytes)"""
    if not data:
        return 0.0
    from math import log2
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * log2(p)
    return entropy

def get_key_base_name(keyname: str, public_fingerprint: str, token: str) -> str:
    """Shared base name for a generated key pair's private/public/info files.

    This is a human-readable label only: nothing in this program re-parses
    it later to identify a key (decryption always reads the key's actual
    content and recomputes its fingerprint). If you rename the .pem files
    afterwards, this shared name is not kept in sync automatically - the
    full fingerprint written inside the matching _info.txt is what lets you
    re-associate files by content rather than by name.
    """
    short_fingerprint = public_fingerprint[:12].upper()
    return f"{sanitize_filename(keyname)[:80]}_{short_fingerprint}_{token}"

def get_key_filename(base_name: str, is_public: bool) -> str:
    return f"{base_name}_{'public' if is_public else 'private'}.pem"

def get_key_info_filename(base_name: str) -> str:
    return f"{base_name}_info.txt"

def format_size(bytes_size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} TB"

def verify_hash_constant_time(stored_hash_hex: str, computed_hash_hex: str) -> bool:
    stored_bytes = bytes.fromhex(stored_hash_hex)
    computed_bytes = bytes.fromhex(computed_hash_hex)
    return hmac.compare_digest(stored_bytes, computed_bytes)

def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

def aes_encrypt_with_hash(data: bytes, password: str, file_hash: str,
                          payload_type: int = 0) -> bytes:
    """Compatibility signature: FSS2 never stores the supplied plaintext hash."""
    return encrypt_v2(data, password=password, payload_type=payload_type)

def require_rsa_key(key):
    if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        raise ValueError('An RSA key is required')
    if not 4096 <= key.key_size <= 8192:
        raise ValueError('RSA key must be 4096 to 8192 bits; weak keys are rejected')

def looks_like_private_key_pem(key_pem: str) -> bool:
    """Cheap upfront format check: does this look like *any* private key
    PEM at all (regardless of algorithm or encryption)? Lets the UI reject
    an obviously wrong file - most commonly, the public key was given by
    mistake - immediately, before even asking for a password, instead of
    only discovering the mistake after that extra prompt.
    """
    return bool(re.search(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----', key_pem))

class KeyFormatError(ValueError):
    """Safe-to-display error: the supplied key file is not usable as-is
    (wrong key type, wrong PEM, password needed/not needed/incorrect).

    Raised only while loading and type-checking the key, before any
    ciphertext is touched - so it never reveals anything about *why* an
    actual decryption attempt failed. Genuine decrypt failures (OAEP
    unwrap, GCM authentication) must keep raising a plain, generic
    ValueError instead, to avoid giving an attacker a distinguishing
    oracle between "wrong key" and "tampered data".

    retry_password: True if re-entering a different password for the SAME
    key file could plausibly fix this (missing/incorrect password). False
    if the key file itself is the problem (wrong type, wrong key entirely,
    malformed PEM, mismatched size) - no password will fix that.
    """
    def __init__(self, message: str, retry_password: bool = True):
        super().__init__(message)
        self.retry_password = retry_password

def encrypt_v2(data, password=None, public_key_pem=None, payload_type=0):
    if payload_type not in (0, 1):
        raise ValueError('Invalid payload type')
    limit = MAX_TEXT_SIZE if payload_type == 0 else MAX_FILE_SIZE + 256
    if len(data) > limit:
        raise ValueError('Plaintext exceeds size limit')
    nonce = os.urandom(12)
    if public_key_pem is None:
        valid, message = validate_password_strength(password)
        if not valid:
            raise ValueError(message)
        algorithm, kdf, iterations = 1, 1, PBKDF2_ITERATIONS
        key, salt = derive_key_from_password(password)
        wrapped = b''
    else:
        if len(public_key_pem.encode('utf-8')) > MAX_KEY_SIZE:
            raise ValueError('Key exceeds size limit')
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        require_rsa_key(public_key)
        algorithm, kdf, iterations = 2, 0, 0
        salt, key = os.urandom(16), os.urandom(32)
        wrapped = public_key.encrypt(key, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    header = FSS2_HEADER.pack(b'FSS2', 2, algorithm, payload_type, kdf, iterations, len(wrapped))
    header += salt + nonce + wrapped
    return header + AESGCM(key).encrypt(nonce, data, header)

def parse_v2(data):
    if not FSS2_HEADER.size + 28 + 16 <= len(data) <= MAX_ENCRYPTED_SIZE:
        raise ValueError('Invalid FSS2 size')
    magic, version, algorithm, payload_type, kdf, iterations, key_length = FSS2_HEADER.unpack_from(data)
    if magic != b'FSS2' or version != 2 or payload_type not in (0, 1):
        raise ValueError('Unsupported FSS2 header')
    if algorithm == 1:
        if kdf != 1 or iterations != PBKDF2_ITERATIONS or key_length != 0:
            raise ValueError('Unsupported FSS2 password parameters')
    elif algorithm == 2:
        if kdf != 0 or iterations != 0 or not 512 <= key_length <= 1024:
            raise ValueError('Invalid FSS2 RSA parameters')
    else:
        raise ValueError('Unsupported FSS2 algorithm')
    end = FSS2_HEADER.size + 28 + key_length
    limit = MAX_TEXT_SIZE if payload_type == 0 else MAX_FILE_SIZE + 256
    if not 16 <= len(data) - end <= limit + 16:
        raise ValueError('Invalid FSS2 payload size')
    start = FSS2_HEADER.size
    return algorithm, data[:end], data[start:start+16], data[start+16:start+28], data[start+28:end], data[end:]

def aes_decrypt_with_hash(encrypted_data: bytes, password: str) -> Tuple[bytes, str]:
    if len(encrypted_data) > MAX_ENCRYPTED_SIZE:
        raise ValueError('Encrypted input exceeds size limit')
    if encrypted_data.startswith(b'FSS1'):
        return _legacy_aes_decrypt_with_hash(encrypted_data, password)
    algorithm, header, salt, nonce, wrapped, ciphertext = parse_v2(encrypted_data)
    if algorithm != 1:
        raise ValueError('RSA container supplied to AES decryption')
    key, _ = derive_key_from_password(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception:
        raise ValueError('Wrong password or damaged encrypted data') from None
    return plaintext, hashlib.sha256(plaintext).hexdigest()

def rsa_decrypt_hybrid_with_hash(encrypted_data: bytes, private_key_pem: str,
                                 private_key_password: Optional[str] = None,
                                 private_key_file: Optional[str] = None) -> Tuple[bytes, str]:
    if len(encrypted_data) > MAX_ENCRYPTED_SIZE or len(private_key_pem.encode('utf-8')) > MAX_KEY_SIZE:
        raise ValueError('Encrypted input or key exceeds size limit')
    if encrypted_data.startswith(b'FSS1'):
        return _legacy_rsa_decrypt_hybrid_with_hash(encrypted_data, private_key_pem,
                                                  private_key_password, private_key_file)
    algorithm, header, salt, nonce, wrapped, ciphertext = parse_v2(encrypted_data)
    if algorithm != 2:
        raise ValueError('AES container supplied to RSA decryption')

    # Step 1: load and type-check the key. Every failure here is about the
    # *file you supplied*, not about the ciphertext, so it is safe to
    # explain plainly - it cannot help an attacker distinguish a correct
    # key from an incorrect one for a given encrypted file.
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'),
            private_key_password.encode('utf-8') if private_key_password else None)
    except TypeError as e:
        message = str(e)
        if 'not given' in message or 'is encrypted' in message:
            raise KeyFormatError('This private key is password-protected; a password is required.',
                                 retry_password=True) from None
        if 'not encrypted' in message:
            raise KeyFormatError('This private key has no password; leave the password field empty.',
                                 retry_password=True) from None
        raise KeyFormatError(f'Could not load the private key: {message}', retry_password=False) from None
    except ValueError as e:
        message = str(e)
        if private_key_password and ('incorrect' in message.lower() or 'bad decrypt' in message.lower()):
            raise KeyFormatError('Incorrect password for this private key.', retry_password=True) from None
        raise KeyFormatError(
            'The supplied file is not a usable RSA private key '
            '(wrong file, wrong key type, or malformed PEM).', retry_password=False) from None

    try:
        require_rsa_key(private_key)
    except ValueError as e:
        raise KeyFormatError(str(e), retry_password=False) from None

    if len(wrapped) != (private_key.key_size + 7) // 8:
        raise KeyFormatError(
            f'This private key ({private_key.key_size}-bit) does not match the key '
            f'used to encrypt this file (expected a {len(wrapped) * 8}-bit key).',
            retry_password=False)

    # Step 2: the actual cryptographic decryption. From here on, every
    # failure stays one generic message - this is the boundary an attacker
    # could otherwise probe (wrong key vs. tampered/corrupted ciphertext),
    # so no more detail is given no matter what specifically went wrong.
    try:
        key = private_key.decrypt(wrapped, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception:
        raise ValueError('Wrong key/password or damaged encrypted data') from None
    return plaintext, hashlib.sha256(plaintext).hexdigest()

def _legacy_aes_decrypt_with_hash(encrypted_data: bytes, password: str) -> Tuple[bytes, str]:
    """
    Decrypt AES-256-GCM encrypted data with hash verification.
    Reads the legacy FSS1 PBKDF2-based container.

    NOTE: Returned plaintext is sensitive and references should be released
    after use. Releasing Python references does not guarantee memory erasure.
    """
    if len(encrypted_data) < MIN_ENCRYPTED_SIZE:
        raise ValueError("Invalid encrypted data (too short)")

    if not encrypted_data.startswith(b"FSS1"):
        raise ValueError("Invalid file format - not a File Secure Suite v1 file")

    version = encrypted_data[4]
    if version not in [1]:
        raise ValueError(f"Unsupported version: {version}. This version uses PBKDF2 encryption.")

    hash_length = struct.unpack('>I', encrypted_data[5:9])[0]
    if hash_length != 32:
        raise ValueError(f"Invalid hash length: {hash_length}")

    min_required = 5 + 4 + hash_length + 16 + 12 + 16
    if len(encrypted_data) < min_required:
        raise ValueError(f"Invalid format (got {len(encrypted_data)} bytes, need {min_required})")

    hash_bytes = encrypted_data[9:9+hash_length]
    hash_hex = hash_bytes.hex()
    salt = encrypted_data[9+hash_length:9+hash_length+16]
    nonce = encrypted_data[9+hash_length+16:9+hash_length+28]
    ciphertext = encrypted_data[9+hash_length+28:]

    key, _ = derive_key_from_password(password, salt)

    cipher = AESGCM(key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

    if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), hash_hex):
        raise ValueError('Legacy payload integrity check failed')
    return plaintext, hash_hex

def rsa_encrypt_hybrid_with_hash(data: bytes, public_key_pem: str, file_hash: str,
                                 payload_type: int = 0) -> bytes:
    return encrypt_v2(data, public_key_pem=public_key_pem, payload_type=payload_type)

def _legacy_rsa_decrypt_hybrid_with_hash(encrypted_data: bytes, private_key_pem: str,
                                 private_key_password: Optional[str] = None,
                                 private_key_file: Optional[str] = None) -> Tuple[bytes, str]:
    if len(encrypted_data) < MIN_ENCRYPTED_SIZE:
        raise ValueError("Invalid encrypted data (too short)")

    if not encrypted_data.startswith(b"FSS1"):
        raise ValueError("Invalid file format - not a File Secure Suite v1 file")

    version = encrypted_data[4]
    if version != 1:
        raise ValueError(f"Unsupported version: {version}")

    hash_length = struct.unpack('>I', encrypted_data[5:9])[0]
    if hash_length != 32:
        raise ValueError(f"Invalid hash length: {hash_length}")

    try:
        key_len = int.from_bytes(encrypted_data[9+hash_length:9+hash_length+2], 'big')
    except (struct.error, IndexError):
        raise ValueError("Cannot read key length")

    if key_len < 100 or key_len > 1024:
        raise ValueError(f"Invalid RSA key size: {key_len}")

    min_required = 5 + 4 + hash_length + 2 + key_len + 16 + 12 + 16
    if len(encrypted_data) < min_required:
        raise ValueError(f"Invalid format (got {len(encrypted_data)} bytes, need {min_required})")

    hash_bytes = encrypted_data[9:9+hash_length]
    hash_hex = hash_bytes.hex()
    encrypted_aes_key = encrypted_data[9+hash_length+2:9+hash_length+2+key_len]
    salt = encrypted_data[9+hash_length+2+key_len:9+hash_length+2+key_len+16]
    nonce = encrypted_data[9+hash_length+2+key_len+16:9+hash_length+2+key_len+28]
    ciphertext = encrypted_data[9+hash_length+2+key_len+28:]

    try:
        if private_key_password:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                private_key_password.encode('utf-8')
            )
        else:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                None
            )

        require_rsa_key(private_key)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {str(e)}")

    cipher = AESGCM(aes_key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"AES decryption failed: {str(e)}")

    if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), hash_hex):
        raise ValueError('Legacy payload integrity check failed')
    return plaintext, hash_hex

def generate_rsa_keypair(password: Optional[str] = None) -> Tuple[str, str]:
    """Return a PKCS#8 RSA-4096 private key and its public key in PEM form."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    public_key = private_key.public_key()
    encryption_algo = (serialization.BestAvailableEncryption(password.encode('utf-8'))
                        if password else serialization.NoEncryption())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo,
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    return private_pem, public_pem

def validate_rsa_key(key_pem: str, is_public: bool = True, key_password: Optional[str] = None) -> bool:
    try:
        if len(key_pem.encode('utf-8')) > MAX_KEY_SIZE:
            return False
        key = (serialization.load_pem_public_key(key_pem.encode()) if is_public else
               serialization.load_pem_private_key(key_pem.encode(), key_password.encode() if key_password else None))
        require_rsa_key(key)
        return True
    except (ValueError, TypeError):
        return False

def calculate_key_fingerprint(key_pem: str, is_public: bool = True,
                              key_password: Optional[str] = None) -> str:
    """Full SHA-256 of public SubjectPublicKeyInfo DER, for either key half.

    Filenames, PEM whitespace and private-key password protection do not enter
    the digest. Protected private keys must be unlocked to derive their public
    part. This identifies a key, not the real-world identity of its owner.
    """
    encoded = key_pem.encode('utf-8')
    if len(encoded) > MAX_KEY_SIZE:
        raise ValueError('Key exceeds size limit')
    if is_public:
        public_key = serialization.load_pem_public_key(encoded)
    else:
        private_key = serialization.load_pem_private_key(
            encoded, key_password.encode('utf-8') if key_password else None)
        require_rsa_key(private_key)
        public_key = private_key.public_key()
    require_rsa_key(public_key)
    canonical = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(canonical).hexdigest()


# Clear clipboard content owned by this process on exit.
import atexit
atexit.register(clear_owned_clipboard)
