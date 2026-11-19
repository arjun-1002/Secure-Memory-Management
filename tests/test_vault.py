import os
import pytest
from db.database import Database
from core.crypto import generate_salt, derive_key
from core.vault import VaultManager
from core.auth import hash_password, verify_password, generate_totp_secret, verify_totp, pyotp


def test_vault_full_workflow(tmp_path):
    db_file = tmp_path / "test_vault.db"
    db = Database(str(db_file))
    vault_root = tmp_path / "storage"
    vault = VaultManager(db, str(vault_root))

    # 1. User registration & 2FA
    username = "alice"
    pwd = "AliceStrongPassword123!"
    pwd_hash = hash_password(pwd)
    salt = generate_salt()
    totp_sec = generate_totp_secret()

    user_id = db.create_user(username, pwd_hash, salt, totp_sec)
    assert user_id is not None

    # Verify credentials & TOTP
    user_rec = db.get_user_by_username(username)
    assert user_rec is not None
    assert verify_password(user_rec["password_hash"], pwd) is True

    curr_token = pyotp.TOTP(totp_sec).now()
    assert verify_totp(totp_sec, curr_token) is True

    # 2. Key derivation
    key = derive_key(pwd, salt, iterations=5000)

    # 3. Create confidential note
    note_res = vault.create_and_store_note(
        user_id=user_id,
        username=username,
        title="Secret_Note.txt",
        content="This is top secret classified intelligence.",
        key_buffer=key
    )
    assert note_res["id"] is not None

    # Read back note
    note_content = vault.read_note_content(user_id, username, note_res["id"], key)
    assert note_content == "This is top secret classified intelligence."

    # 4. Encrypt external file
    orig_file = tmp_path / "document.pdf"
    orig_file.write_bytes(b"%PDF-1.4 simulated binary data 1234567890" * 100)

    enc_res = vault.encrypt_and_store_file(
        user_id=user_id,
        username=username,
        src_path=str(orig_file),
        key_buffer=key,
        shred_original=False
    )
    assert enc_res["id"] is not None

    # 5. Export decrypted file
    export_dir = tmp_path / "exported"
    out_path = vault.decrypt_and_export_file(
        user_id=user_id,
        username=username,
        file_id=enc_res["id"],
        destination_dir=str(export_dir),
        key_buffer=key
    )
    assert os.path.exists(out_path)
    assert open(out_path, "rb").read() == orig_file.read_bytes()

    # 6. Audit logs
    logs = db.get_audit_logs(user_id)
    assert len(logs) >= 3
    action_types = [l["action"] for l in logs]
    assert "REGISTER" in action_types
    assert "CREATE_NOTE" in action_types
    assert "ENCRYPT_FILE" in action_types
    assert "DECRYPT_EXPORT" in action_types

    # 7. Shred vault file
    assert vault.delete_vault_file(user_id, username, enc_res["id"]) is True
    assert db.get_vault_file(user_id, enc_res["id"]) is None
