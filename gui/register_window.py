"""
Modern User Registration View with Interactive 2FA Setup & QR Code
"""

import customtkinter as ctk
from tkinter import messagebox
from PIL import Image
from core.auth import (
    validate_password_strength,
    generate_totp_secret,
    get_totp_uri,
    generate_qr_image,
    verify_totp,
    hash_password
)
from core.crypto import generate_salt
from db.database import Database
from gui.theme import THEME, FONT_FAMILY


class RegisterFrame(ctk.CTkFrame):
    def __init__(self, parent, db: Database, on_back_to_login):
        super().__init__(parent, fg_color=THEME["surface"], corner_radius=16)
        self.db = db
        self.on_back_to_login = on_back_to_login

        self.pending_secret = None
        self.pending_username = None
        self.pending_password = None

        self._build_step1_ui()

    def _build_step1_ui(self):
        for widget in self.winfo_children():
            widget.destroy()

        # Title
        title_label = ctk.CTkLabel(
            self,
            text="🔐 Create Secure Account",
            font=(FONT_FAMILY, 22, "bold"),
            text_color=THEME["text"]
        )
        title_label.pack(pady=(25, 5))

        subtitle = ctk.CTkLabel(
            self,
            text="Zero-knowledge encrypted memory & file vault",
            font=(FONT_FAMILY, 12),
            text_color=THEME["text_muted"]
        )
        subtitle.pack(pady=(0, 20))

        # Username
        self.user_entry = ctk.CTkEntry(
            self,
            placeholder_text="Choose a Username",
            width=320,
            height=42,
            font=(FONT_FAMILY, 13)
        )
        self.user_entry.pack(pady=8)

        # Password
        self.pwd_entry = ctk.CTkEntry(
            self,
            placeholder_text="Enter Password (min 8 chars, 1 upper, 1 num, 1 sym)",
            show="*",
            width=320,
            height=42,
            font=(FONT_FAMILY, 13)
        )
        self.pwd_entry.pack(pady=8)
        self.pwd_entry.bind("<KeyRelease>", self._check_strength)

        # Confirm Password
        self.confirm_entry = ctk.CTkEntry(
            self,
            placeholder_text="Confirm Password",
            show="*",
            width=320,
            height=42,
            font=(FONT_FAMILY, 13)
        )
        self.confirm_entry.pack(pady=8)

        # Strength label
        self.strength_label = ctk.CTkLabel(
            self,
            text="",
            font=(FONT_FAMILY, 11),
            text_color=THEME["text_muted"]
        )
        self.strength_label.pack(pady=4)

        # Continue Button
        next_btn = ctk.CTkButton(
            self,
            text="Next: Setup 2FA (Authenticator)",
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            width=320,
            height=44,
            command=self._proceed_to_2fa
        )
        next_btn.pack(pady=15)

        # Back to Login
        back_btn = ctk.CTkButton(
            self,
            text="← Back to Login",
            font=(FONT_FAMILY, 12),
            fg_color="transparent",
            text_color=THEME["secondary"],
            hover_color=THEME["card"],
            width=320,
            height=32,
            command=self.on_back_to_login
        )
        back_btn.pack(pady=(0, 20))

    def _check_strength(self, event=None):
        pwd = self.pwd_entry.get()
        if not pwd:
            self.strength_label.configure(text="")
            return
        ok, msg = validate_password_strength(pwd)
        if ok:
            self.strength_label.configure(text="✓ Password meets security requirements", text_color=THEME["success"])
        else:
            self.strength_label.configure(text=f"✗ {msg}", text_color=THEME["warning"])

    def _proceed_to_2fa(self):
        username = self.user_entry.get().strip()
        pwd = self.pwd_entry.get()
        confirm = self.confirm_entry.get()

        if not username:
            messagebox.showerror("Validation Error", "Username is required.")
            return

        if self.db.get_user_by_username(username):
            messagebox.showerror("User Exists", "This username is already taken. Please choose another.")
            return

        if pwd != confirm:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return

        ok, msg = validate_password_strength(pwd)
        if not ok:
            messagebox.showerror("Weak Password", msg)
            return

        self.pending_username = username
        self.pending_password = pwd
        self.pending_secret = generate_totp_secret()
        self._build_step2_2fa_ui()

    def _build_step2_2fa_ui(self):
        for widget in self.winfo_children():
            widget.destroy()

        # Step 2: 2FA Setup
        title_label = ctk.CTkLabel(
            self,
            text="📱 Step 2: Configure Authenticator",
            font=(FONT_FAMILY, 18, "bold"),
            text_color=THEME["text"]
        )
        title_label.pack(pady=(15, 2))

        desc = ctk.CTkLabel(
            self,
            text="Scan the QR code with Google Authenticator or Bitwarden:",
            font=(FONT_FAMILY, 11),
            text_color=THEME["text_muted"]
        )
        desc.pack(pady=(0, 10))

        # Generate QR
        uri = get_totp_uri(self.pending_username, self.pending_secret)
        pil_img = generate_qr_image(uri, box_size=4, border=2)
        ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(150, 150))

        qr_label = ctk.CTkLabel(self, image=ctk_img, text="")
        qr_label.pack(pady=5)

        # Manual Secret Entry
        secret_box = ctk.CTkLabel(
            self,
            text=f"Secret: {self.pending_secret}",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=THEME["secondary"]
        )
        secret_box.pack(pady=3)

        # Verification Entry
        self.totp_entry = ctk.CTkEntry(
            self,
            placeholder_text="Enter 6-digit code to verify",
            width=220,
            height=38,
            font=(FONT_FAMILY, 14, "bold"),
            justify="center"
        )
        self.totp_entry.pack(pady=10)

        # Complete Registration Button
        finish_btn = ctk.CTkButton(
            self,
            text="Verify & Finalize Registration",
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=THEME["success"],
            hover_color=THEME["success_hover"],
            width=260,
            height=42,
            command=self._verify_and_register
        )
        finish_btn.pack(pady=8)

        # Cancel / Back
        back_btn = ctk.CTkButton(
            self,
            text="Cancel",
            font=(FONT_FAMILY, 12),
            fg_color="transparent",
            text_color=THEME["text_muted"],
            hover_color=THEME["card"],
            width=100,
            height=28,
            command=self._build_step1_ui
        )
        back_btn.pack(pady=(0, 15))

    def _verify_and_register(self):
        token = self.totp_entry.get().strip()
        if not verify_totp(self.pending_secret, token):
            messagebox.showerror("2FA Error", "Invalid 6-digit verification code. Please check your authenticator app.")
            return

        # Securely hash password with Argon2id and create salt
        pwd_hash = hash_password(self.pending_password)
        salt = generate_salt(32)

        user_id = self.db.create_user(
            username=self.pending_username,
            password_hash=pwd_hash,
            salt=salt,
            totp_secret=self.pending_secret
        )

        if user_id:
            messagebox.showinfo("Success", "Account created successfully! You can now log in.")
            # Clear sensitive temporaries
            self.pending_password = None
            self.pending_secret = None
            self.on_back_to_login()
        else:
            messagebox.showerror("Error", "Failed to register user. Username might already exist.")
