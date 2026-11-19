"""
Database Layer for Secure Memory Manager
Manages SQLite database with WAL mode, parameterized queries, and audit logging.
"""

import sqlite3
import os
import datetime
from typing import Optional, Dict, Any, List

DB_PATH = "vault.db"


class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for fast concurrent operations and data integrity
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    totp_secret TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT
                )
            """)

            # Vault files metadata
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    storage_name TEXT NOT NULL UNIQUE,
                    original_name TEXT NOT NULL,
                    original_size INTEGER NOT NULL,
                    encrypted_size INTEGER NOT NULL,
                    is_text_note INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

            # Audit logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            conn.commit()

    # User operations
    def create_user(
        self,
        username: str,
        password_hash: str,
        salt: bytes,
        totp_secret: str
    ) -> Optional[int]:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, salt, totp_secret, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (username.strip(), password_hash, salt, totp_secret, now)
                )
                conn.commit()
                user_id = cursor.lastrowid
                self.log_event(user_id, username, "REGISTER", "User registered with 2FA", "SUCCESS")
                return user_id
        except sqlite3.IntegrityError:
            return None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (username.strip(),)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def update_login_success(self, user_id: int, username: str):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users
                SET last_login = ?, failed_attempts = 0, locked_until = NULL
                WHERE id = ?
                """,
                (now, user_id)
            )
            conn.commit()
        self.log_event(user_id, username, "LOGIN", "Login successful", "SUCCESS")

    def record_login_failure(self, username: str):
        user = self.get_user_by_username(username)
        if not user:
            self.log_event(None, username, "LOGIN_FAILED", "Unknown username attempt", "FAILURE")
            return

        user_id = user["id"]
        attempts = user["failed_attempts"] + 1
        locked_until = None

        if attempts >= 5:
            # Lock account for 15 minutes
            lock_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
            locked_until = lock_time.isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users
                SET failed_attempts = ?, locked_until = ?
                WHERE id = ?
                """,
                (attempts, locked_until, user_id)
            )
            conn.commit()

        self.log_event(
            user_id, username, "LOGIN_FAILED",
            f"Failed login attempt #{attempts}" + (" (Account Locked)" if locked_until else ""),
            "FAILURE"
        )

    # Vault Files operations
    def add_vault_file(
        self,
        user_id: int,
        storage_name: str,
        original_name: str,
        original_size: int,
        encrypted_size: int,
        is_text_note: bool = False
    ) -> int:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO vault_files (
                    user_id, storage_name, original_name, original_size, encrypted_size, is_text_note, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, storage_name, original_name, original_size, encrypted_size, 1 if is_text_note else 0, now)
            )
            conn.commit()
            return cursor.lastrowid

    def list_vault_files(self, user_id: int) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, storage_name, original_name, original_size, encrypted_size, is_text_note, created_at
                FROM vault_files
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_vault_file(self, user_id: int, file_id: int) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM vault_files WHERE user_id = ? AND id = ?",
                (user_id, file_id)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def delete_vault_file(self, user_id: int, file_id: int) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM vault_files WHERE user_id = ? AND id = ?",
                (user_id, file_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    # Audit log operations
    def log_event(
        self,
        user_id: Optional[int],
        username: Optional[str],
        action: str,
        details: str,
        status: str = "SUCCESS"
    ):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_logs (user_id, username, action, details, timestamp, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, username, action, details, now, status)
                )
                conn.commit()
        except Exception:
            pass

    def get_audit_logs(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT action, details, timestamp, status
                FROM audit_logs
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (user_id, limit)
            )
            return [dict(row) for row in cursor.fetchall()]
