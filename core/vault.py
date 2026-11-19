"""
Vault Operations Engine
Coordinates encrypted file storage, secure note creation, file decryption/export,
and secure shredding with audit logging.
"""

import os
import uuid
import re
from typing import Optional, Callable, Dict, Any, List
from core.crypto import (
    encrypt_file_stream,
    decrypt_file_stream,
    encrypt_bytes,
    decrypt_bytes,
    SecureBuffer
)
from core.shredder import secure_shred_file
from db.database import Database

VAULT_STORAGE_DIR = "vault_storage"


def sanitize_filename(filename: str) -> str:
    """Sanitizes filename against path traversal and dangerous characters."""
    clean = os.path.basename(filename).strip()
    # Strip any directory separators or null bytes
    clean = re.sub(r'[\/\\:\*\?"<>\|\x00]', '_', clean)
    return clean if clean else "unnamed_file"


class VaultManager:
    def __init__(self, db: Database, storage_root: str = VAULT_STORAGE_DIR):
        self.db = db
        self.storage_root = storage_root
        os.makedirs(self.storage_root, exist_ok=True)

    def _get_user_storage_path(self, username: str) -> str:
        user_path = os.path.join(self.storage_root, username)
        os.makedirs(user_path, exist_ok=True)
        return user_path

    def encrypt_and_store_file(
        self,
        user_id: int,
        username: str,
        src_path: str,
        key_buffer: SecureBuffer,
        shred_original: bool = False,
        progress_cb: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Encrypts an arbitrary file using streaming AES-256-GCM and stores it in the vault.
        Optionally shreds original source file with multi-pass wipe.
        """
        if not os.path.isfile(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        original_name = sanitize_filename(src_path)
        original_size = os.path.getsize(src_path)

        storage_id = uuid.uuid4().hex + ".enc"
        user_dir = self._get_user_storage_path(username)
        dst_path = os.path.join(user_dir, storage_id)

        try:
            encrypt_file_stream(src_path, dst_path, key_buffer, progress_callback=progress_cb)
            encrypted_size = os.path.getsize(dst_path)

            file_id = self.db.add_vault_file(
                user_id=user_id,
                storage_name=storage_id,
                original_name=original_name,
                original_size=original_size,
                encrypted_size=encrypted_size,
                is_text_note=False
            )

            shred_msg = ""
            if shred_original:
                ok, shred_msg = secure_shred_file(src_path)
                if not ok:
                    shred_msg = f" (Original shred error: {shred_msg})"
                else:
                    shred_msg = " (Original file securely shredded)"

            self.db.log_event(
                user_id, username, "ENCRYPT_FILE",
                f"Encrypted '{original_name}' ({original_size} bytes){shred_msg}",
                "SUCCESS"
            )

            return {
                "id": file_id,
                "name": original_name,
                "size": original_size,
                "encrypted_size": encrypted_size,
                "shredded": shred_original
            }
        except Exception as e:
            if os.path.exists(dst_path):
                try:
                    os.remove(dst_path)
                except Exception:
                    pass
            self.db.log_event(user_id, username, "ENCRYPT_FILE", f"Failed for '{original_name}': {e}", "FAILURE")
            raise

    def create_and_store_note(
        self,
        user_id: int,
        username: str,
        title: str,
        content: str,
        key_buffer: SecureBuffer
    ) -> Dict[str, Any]:
        """
        Encrypts and stores a confidential text note.
        """
        clean_title = sanitize_filename(title)
        if not clean_title.endswith(".txt"):
            clean_title += ".txt"

        data = content.encode("utf-8")
        encrypted_data = encrypt_bytes(data, key_buffer)

        storage_id = uuid.uuid4().hex + ".enc"
        user_dir = self._get_user_storage_path(username)
        dst_path = os.path.join(user_dir, storage_id)

        with open(dst_path, "wb") as f:
            f.write(encrypted_data)

        file_id = self.db.add_vault_file(
            user_id=user_id,
            storage_name=storage_id,
            original_name=clean_title,
            original_size=len(data),
            encrypted_size=len(encrypted_data),
            is_text_note=True
        )

        self.db.log_event(
            user_id, username, "CREATE_NOTE",
            f"Created encrypted note '{clean_title}'",
            "SUCCESS"
        )

        return {
            "id": file_id,
            "name": clean_title,
            "size": len(data)
        }

    def read_note_content(
        self,
        user_id: int,
        username: str,
        file_id: int,
        key_buffer: SecureBuffer
    ) -> str:
        """
        Decrypts an encrypted text note directly into memory.
        """
        rec = self.db.get_vault_file(user_id, file_id)
        if not rec:
            raise FileNotFoundError("Note record not found")

        storage_path = os.path.join(self._get_user_storage_path(username), rec["storage_name"])
        if not os.path.exists(storage_path):
            raise FileNotFoundError("Encrypted note file missing from storage")

        with open(storage_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_bytes = decrypt_bytes(encrypted_data, key_buffer)
        self.db.log_event(user_id, username, "READ_NOTE", f"Read note '{rec['original_name']}'", "SUCCESS")
        return decrypted_bytes.decode("utf-8", errors="replace")

    def decrypt_and_export_file(
        self,
        user_id: int,
        username: str,
        file_id: int,
        destination_dir: str,
        key_buffer: SecureBuffer,
        progress_cb: Optional[Callable[[int, int], None]] = None
    ) -> str:
        """
        Decrypts a vault file and writes it to the designated destination directory.
        """
        rec = self.db.get_vault_file(user_id, file_id)
        if not rec:
            raise FileNotFoundError("File record not found in database.")

        storage_path = os.path.join(self._get_user_storage_path(username), rec["storage_name"])
        if not os.path.exists(storage_path):
            raise FileNotFoundError("Encrypted vault file not found on disk.")

        os.makedirs(destination_dir, exist_ok=True)
        out_path = os.path.join(destination_dir, rec["original_name"])

        # Prevent overwriting without notification by appending suffix if exists
        base, ext = os.path.splitext(out_path)
        counter = 1
        while os.path.exists(out_path):
            out_path = f"{base}_{counter}{ext}"
            counter += 1

        try:
            if rec["is_text_note"]:
                with open(storage_path, "rb") as fin:
                    enc_data = fin.read()
                plain = decrypt_bytes(enc_data, key_buffer)
                with open(out_path, "wb") as fout:
                    fout.write(plain)
            else:
                decrypt_file_stream(storage_path, out_path, key_buffer, progress_callback=progress_cb)

            self.db.log_event(
                user_id, username, "DECRYPT_EXPORT",
                f"Exported '{rec['original_name']}' to '{out_path}'",
                "SUCCESS"
            )
            return out_path
        except Exception as e:
            self.db.log_event(
                user_id, username, "DECRYPT_EXPORT",
                f"Failed export for '{rec['original_name']}': {e}",
                "FAILURE"
            )
            raise

    def delete_vault_file(self, user_id: int, username: str, file_id: int) -> bool:
        """
        Securely shreds the encrypted file on disk and removes it from the database.
        """
        rec = self.db.get_vault_file(user_id, file_id)
        if not rec:
            return False

        storage_path = os.path.join(self._get_user_storage_path(username), rec["storage_name"])
        if os.path.exists(storage_path):
            secure_shred_file(storage_path, passes=2)

        ok = self.db.delete_vault_file(user_id, file_id)
        if ok:
            self.db.log_event(
                user_id, username, "SHRED_VAULT_FILE",
                f"Shredded '{rec['original_name']}' from vault",
                "SUCCESS"
            )
        return ok
