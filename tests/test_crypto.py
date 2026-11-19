import os
import pytest
from core.crypto import (
    generate_salt,
    derive_key,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_file_stream,
    decrypt_file_stream
)
from core.memory import SecureBuffer, zero_memory


def test_memory_buffer_zeroing():
    data = bytearray(b"super_secret_test_key_12345678")
    buf = SecureBuffer(data)
    assert buf.get_bytes() == b"super_secret_test_key_12345678"
    buf.wipe()
    assert buf.wiped is True
    with pytest.raises(ValueError):
        buf.get_bytes()


def test_encrypt_decrypt_bytes():
    salt = generate_salt()
    key = derive_key("SecurePassword999!", salt, iterations=10_000)
    plain = b"This is a test of confidential text encryption."
    ciphertext = encrypt_bytes(plain, key)
    assert ciphertext != plain
    decrypted = decrypt_bytes(ciphertext, key)
    assert decrypted == plain


def test_streaming_file_encryption(tmp_path):
    salt = generate_salt()
    key = derive_key("MyComplexPassphrase!123", salt, iterations=10_000)

    src_file = tmp_path / "test_data.bin"
    enc_file = tmp_path / "test_data.bin.enc"
    dec_file = tmp_path / "test_data.recovered.bin"

    # Write 300 KB of random test data (multiple 64KB chunks)
    original_data = os.urandom(300 * 1024)
    src_file.write_bytes(original_data)

    encrypt_file_stream(str(src_file), str(enc_file), key)
    assert enc_file.exists()
    assert enc_file.stat().st_size > len(original_data)

    decrypt_file_stream(str(enc_file), str(dec_file), key)
    assert dec_file.exists()
    assert dec_file.read_bytes() == original_data
