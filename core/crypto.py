"""
Cryptographic Engine
Provides:
- PBKDF2-HMAC-SHA256 per-user key derivation (600,000 iterations)
- AES-256-GCM authenticated encryption and decryption
- Chunked streaming for large files with progress callbacks and low memory overhead
- Magic header verification and truncation resistance
"""

import os
import struct
import hashlib
from typing import Callable, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core.memory import SecureBuffer, zero_memory

MAGIC_HEADER_BYTES = b"SMM1"     # For in-memory encrypted blobs / text
MAGIC_HEADER_FILE = b"SMMF1"    # For streaming encrypted files
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB per chunk
PBKDF2_ITERATIONS = 600_000     # OWASP recommended minimum for PBKDF2-HMAC-SHA256


def generate_salt(length: int = 32) -> bytes:
    """Generates cryptographically strong random salt."""
    return os.urandom(length)


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> SecureBuffer:
    """
    Derives a 256-bit (32-byte) key from the given password and salt.
    The returned key is stored in a locked SecureBuffer.
    """
    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32
    )
    buf = SecureBuffer(raw_key)
    # Clear raw_key from local scope
    del raw_key
    return buf


def encrypt_bytes(data: bytes, key_buffer: SecureBuffer) -> bytes:
    """
    Encrypts in-memory data using AES-256-GCM.
    Returns: MAGIC_HEADER_BYTES (4 bytes) + Nonce (12 bytes) + Ciphertext + Tag (16 bytes).
    """
    key_bytes = key_buffer.get_bytes()
    try:
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return MAGIC_HEADER_BYTES + nonce + ciphertext
    finally:
        del key_bytes


def decrypt_bytes(encrypted_data: bytes, key_buffer: SecureBuffer) -> bytes:
    """
    Decrypts an in-memory AES-256-GCM payload.
    Verifies header and authenticates integrity.
    """
    if len(encrypted_data) < len(MAGIC_HEADER_BYTES) + 12 + 16:
        raise ValueError("Encrypted data is too short or corrupted.")

    header = encrypted_data[:len(MAGIC_HEADER_BYTES)]
    if header != MAGIC_HEADER_BYTES:
        raise ValueError("Invalid format: magic header mismatch.")

    nonce = encrypted_data[len(MAGIC_HEADER_BYTES):len(MAGIC_HEADER_BYTES) + 12]
    ciphertext = encrypted_data[len(MAGIC_HEADER_BYTES) + 12:]

    key_bytes = key_buffer.get_bytes()
    try:
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    finally:
        del key_bytes


def encrypt_file_stream(
    src_path: str,
    dst_path: str,
    key_buffer: SecureBuffer,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> None:
    """
    Encrypts a file in streaming chunks using AES-256-GCM.
    Keeps memory usage strictly bounded, preventing RAM exhaustion on large files.
    """
    total_size = os.path.getsize(src_path)
    processed_size = 0
    key_bytes = key_buffer.get_bytes()

    try:
        aesgcm = AESGCM(key_bytes)
        file_salt = os.urandom(16)

        with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
            # Write Header: Magic (5B) + Salt (16B) + Chunk size (4B)
            fout.write(MAGIC_HEADER_FILE)
            fout.write(file_salt)
            fout.write(struct.pack(">I", chunk_size))

            chunk_index = 0
            while True:
                chunk = fin.read(chunk_size)
                is_last = len(chunk) < chunk_size

                # Unique nonce per chunk
                nonce = os.urandom(12)
                # Additional authenticated data includes chunk index and is_last flag
                aad = struct.pack(">IB", chunk_index, 1 if is_last else 0)
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, aad)

                # Write Chunk: Nonce (12B) + Encrypted length (4B) + Flag (1B) + Encrypted chunk
                fout.write(nonce)
                fout.write(struct.pack(">IB", len(encrypted_chunk), 1 if is_last else 0))
                fout.write(encrypted_chunk)

                processed_size += len(chunk)
                if progress_callback:
                    progress_callback(processed_size, total_size)

                chunk_index += 1
                if is_last:
                    break
    finally:
        del key_bytes


def decrypt_file_stream(
    src_path: str,
    dst_path: str,
    key_buffer: SecureBuffer,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> None:
    """
    Decrypts a streaming AES-256-GCM encrypted file.
    Verifies authentication tag of each chunk and guards against truncation attacks.
    """
    total_size = os.path.getsize(src_path)
    processed_size = 0
    key_bytes = key_buffer.get_bytes()

    try:
        aesgcm = AESGCM(key_bytes)

        with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
            # Read Header
            magic = fin.read(len(MAGIC_HEADER_FILE))
            if magic != MAGIC_HEADER_FILE:
                raise ValueError("Not a valid encrypted vault file (invalid magic header).")

            file_salt = fin.read(16)
            chunk_size_bytes = fin.read(4)
            if len(chunk_size_bytes) < 4:
                raise ValueError("Corrupted encrypted file header.")
            chunk_size = struct.unpack(">I", chunk_size_bytes)[0]

            processed_size += len(MAGIC_HEADER_FILE) + 16 + 4

            chunk_index = 0
            while True:
                nonce = fin.read(12)
                if not nonce:
                    # Premature EOF without last chunk flag
                    raise ValueError("File appears truncated or corrupted.")

                meta = fin.read(5)
                if len(meta) < 5:
                    raise ValueError("Corrupted chunk metadata.")
                enc_len, is_last_flag = struct.unpack(">IB", meta)

                encrypted_chunk = fin.read(enc_len)
                if len(encrypted_chunk) < enc_len:
                    raise ValueError("Incomplete chunk data.")

                aad = struct.pack(">IB", chunk_index, is_last_flag)
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, aad)
                fout.write(decrypted_chunk)

                processed_size += 12 + 5 + enc_len
                if progress_callback:
                    progress_callback(processed_size, total_size)

                chunk_index += 1
                if is_last_flag == 1:
                    break
    finally:
        del key_bytes
