"""
aes_tool.py
Core crypto utilities for AES-256-GCM file encryption/decryption with a password.
- Uses Scrypt (memory-hard) to derive a 256-bit key from a password and random salt.
- Uses AES-GCM (authenticated encryption) to provide confidentiality + integrity.
- File format: [MAGIC(8)][VERSION(1)][SALT(16)][NONCE(12)][CIPHERTEXT+TAG(...)]
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----- File format constants -----
MAGIC = b"AESTOOL1"     # 8 bytes: file signature to detect our format
VERSION = 1             # 1 byte: allows future format changes
SALT_SIZE = 16          # bytes
NONCE_SIZE = 12         # bytes (AES-GCM standard)
KEY_LEN = 32            # 32 bytes = 256-bit key

# ----- Key derivation -----
def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from a user password and salt using Scrypt.
    Scrypt parameters chosen for good security on typical machines.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=2**14,     # CPU/memory cost
        r=8,         # block size
        p=1          # parallelization
    )
    return kdf.derive(password.encode("utf-8"))

# ----- Header helpers -----
def _write_header(fh, salt: bytes, nonce: bytes) -> None:
    fh.write(MAGIC)
    fh.write(bytes([VERSION]))
    fh.write(salt)
    fh.write(nonce)

def _read_header(fh) -> Tuple[bytes, bytes]:
    magic = fh.read(len(MAGIC))
    if magic != MAGIC:
        raise ValueError("Not an AESTOOL file (magic mismatch).")
    version_byte = fh.read(1)
    if not version_byte or version_byte[0] != VERSION:
        raise ValueError("Unsupported file version.")
    salt = fh.read(SALT_SIZE)
    nonce = fh.read(NONCE_SIZE)
    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
        raise ValueError("Corrupted header.")
    return salt, nonce

# ----- Public API -----
def encrypt_file(input_path: str | Path, password: str, output_path: str | Path | None = None,
                 overwrite: bool = False) -> Path:
    """
    Encrypt a file using AES-256-GCM.
    Returns the output file path.
    """
    inp = Path(input_path).expanduser()
    if not inp.is_file():
        raise FileNotFoundError(f"Input file not found: {inp}")

    # Default output: append .enc
    out = Path(output_path).expanduser() if output_path else inp.with_suffix(inp.suffix + ".enc")
    if out.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {out} (use overwrite=True)")

    # Read plaintext (simple implementation; fine for typical files)
    plaintext = inp.read_bytes()

    # Generate salt/nonce and derive key
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)

    # AES-GCM encryption; associated_data could store metadata if desired
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce=nonce, data=plaintext, associated_data=None)

    with open(out, "wb") as fh:
        _write_header(fh, salt, nonce)
        fh.write(ciphertext)

    return out

def decrypt_file(input_path: str | Path, password: str, output_path: str | Path | None = None,
                 overwrite: bool = False) -> Path:
    """
    Decrypt a file produced by encrypt_file. Raises ValueError on wrong password
    or tampered data (GCM authentication failure). Returns the output file path.
    """
    enc = Path(input_path).expanduser()
    if not enc.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {enc}")

    with open(enc, "rb") as fh:
        salt, nonce = _read_header(fh)
        ciphertext = fh.read()

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=None)
    except Exception as e:
        # Wrong password or data corrupted -> GCM tag check fails here
        raise ValueError("Decryption failed: wrong password or file is corrupted.") from e

    # Default output: strip trailing .enc if present, else add .dec
    if output_path:
        out = Path(output_path).expanduser()
    else:
        out = enc.with_suffix(enc.suffix[:-4]) if enc.suffix.endswith("enc") else enc.with_suffix(enc.suffix + ".dec")

    if out.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {out} (use overwrite=True)")

    out.write_bytes(plaintext)
    return out
