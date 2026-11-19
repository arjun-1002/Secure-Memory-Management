"""
Modern Login View with Password & TOTP 2FA Verification
"""

import customtkinter as ctk
import datetime
from tkinter import messagebox
from core.auth import verify_password, verify_totp
from core.crypto import derive_key
from db.database import Database
from gui.theme import THEME, FONT_FAMILY


class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, db: Database, on_login_success, on_go_to_register):
        super().__init__(parent, fg_color=THEME["surface"], corner_radius=16)
        self.db = db
        self.on_login_success = on_login_success
        self.on_go_to_register = on_go_to_register

        self._build_ui()

    def _build_ui(self):
        # Header
        title_label = ctk.CTkLabel(
            self,
            text="🔐 Secure Memory Manager",
            font=(FONT_FAMILY, 22, "bold"),
            text_color=THEME["text"]
        )
        title_label.pack(pady=(30, 4))

        subtitle = ctk.CTkLabel(
            self,
            text="AES-256-GCM • Argon2 • RAM VirtualLock",
            font=(FONT_FAMILY, 12),
            text_color=THEME["secondary"]
        )
        subtitle.pack(pady=(0, 25))

        # Username
        self.user_entry = ctk.CTkEntry(
            self,
            placeholder_text="Username",
            width=320,
            height=42,
            font=(FONT_FAMILY, 13)
        )
        self.user_entry.pack(pady=8)

        # Password
        self.pwd_entry = ctk.CTkEntry(
            self,
            placeholder_text="Password",
            show="*",
            width=320,
            height=42,
            font=(FONT_FAMILY, 13)
        )
        self.pwd_entry.pack(pady=8)

        # 2FA TOTP Code
        self.totp_entry = ctk.CTkEntry(
            self,
            placeholder_text="6-digit Authenticator Code (2FA)",
            width=320,
            height=42,
            font=(FONT_FAMILY, 13),
            justify="center"
        )
        self.totp_entry.pack(pady=8)

        # Status / Error Label
        self.error_label = ctk.CTkLabel(
            self,
            text="",
            font=(FONT_FAMILY, 11),
            text_color=THEME["danger"]
        )
        self.error_label.pack(pady=4)

        # Login Button
        login_btn = ctk.CTkButton(
            self,
            text="Unlock Vault",
            font=(FONT_FAMILY, 14, "bold"),
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            width=320,
            height=44,
            command=self._do_login
        )
        login_btn.pack(pady=12)

        # Register Option
        register_btn = ctk.CTkButton(
            self,
            text="Don't have an account? Register",
            font=(FONT_FAMILY, 12),
            fg_color="transparent",
            text_color=THEME["secondary"],
            hover_color=THEME["card"],
            width=320,
            height=32,
            command=self.on_go_to_register
        )
        register_btn.pack(pady=(0, 25))

    def _do_login(self):
        username = self.user_entry.get().strip()
        pwd = self.pwd_entry.get()
        token = self.totp_entry.get().strip()

        self.error_label.configure(text="")

        if not username or not pwd or not token:
            self.error_label.configure(text="Please enter username, password, and 2FA code.")
            return

        user = self.db.get_user_by_username(username)
        if not user:
            self.db.record_login_failure(username)
            self.error_label.configure(text="Invalid credentials or 2FA code.")
            return

        # Check account lockout
        if user.get("locked_until"):
            try:
                locked_time = datetime.datetime.fromisoformat(user["locked_until"])
                now = datetime.datetime.now(datetime.timezone.utc)
                if now < locked_time:
                    remaining = int((locked_time - now).total_seconds() / 60)
                    self.error_label.configure(text=f"Account locked due to failed attempts. Try again in {remaining} min.")
                    return
            except Exception:
                pass

        # Verify password with Argon2
        if not verify_password(user["password_hash"], pwd):
            self.db.record_login_failure(username)
            self.error_label.configure(text="Invalid credentials or 2FA code.")
            return

        # Verify TOTP 2FA
        if not verify_totp(user["totp_secret"], token):
            self.db.record_login_failure(username)
            self.error_label.configure(text="Invalid 2FA Authenticator code.")
            return

        # Success: Derive user-specific cryptographic key
        try:
            # PBKDF2 key derivation using user's unique salt stored in DB
            key_buffer = derive_key(pwd, user["salt"])
            self.db.update_login_success(user["id"], username)

            # Clear UI fields
            self.pwd_entry.delete(0, "end")
            self.totp_entry.delete(0, "end")

            self.on_login_success(user, key_buffer)
        except Exception as e:
            self.error_label.configure(text=f"Login error: {str(e)}")
