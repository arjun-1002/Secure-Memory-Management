import os
from core.memory import SecureBuffer, zero_memory, IS_WINDOWS, lock_memory_region, unlock_memory_region
from core.shredder import secure_shred_file
from core.auth import validate_password_strength


def test_virtual_lock_and_buffer_zeroing():
    secret_bytes = b"SensitiveMasterKey2026!#"
    buf = SecureBuffer(secret_bytes)

    if IS_WINDOWS:
        assert buf.locked is True

    raw_before = buf.get_bytes()
    assert raw_before == secret_bytes

    # Wipe buffer
    buf.wipe()
    assert buf.wiped is True
    assert buf.locked is False


def test_secure_shredder(tmp_path):
    target_file = tmp_path / "delete_me.txt"
    target_file.write_text("Extremely sensitive plaintext information that must be purged.")

    assert target_file.exists()
    ok, msg = secure_shred_file(str(target_file), passes=3)
    assert ok is True
    assert not target_file.exists()


def test_password_policy():
    # Too short
    ok, _ = validate_password_strength("Short1!")
    assert not ok

    # No uppercase
    ok, _ = validate_password_strength("nouppercase123!")
    assert not ok

    # No number
    ok, _ = validate_password_strength("NoNumberSpecial!")
    assert not ok

    # Valid
    ok, _ = validate_password_strength("ValidPassw0rd!#")
    assert ok
