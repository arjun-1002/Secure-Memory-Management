"""
Main Application Dashboard & Vault Explorer View
"""

import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from typing import Dict, Any, Optional
from core.crypto import SecureBuffer
from core.vault import VaultManager
from db.database import Database
from gui.theme import THEME, FONT_FAMILY


def format_size(size_bytes: int) -> str:
    """Formats bytes into human-readable sizes."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


class MainDashboard(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        db: Database,
        vault: VaultManager,
        user: Dict[str, Any],
        key_buffer: SecureBuffer,
        on_logout
    ):
        super().__init__(parent, fg_color=THEME["bg_dark"])
        self.db = db
        self.vault = vault
        self.user = user
        self.key_buffer = key_buffer
        self.on_logout = on_logout

        self.selected_note_id = None

        self._build_ui()
        self.refresh_vault_files()
        self.refresh_notes_list()
        self.refresh_audit_logs()

    def _build_ui(self):
        # 1. Top Navigation Bar
        top_bar = ctk.CTkFrame(self, fg_color=THEME["surface"], height=60, corner_radius=0)
        top_bar.pack(fill="x", side="top", padx=0, pady=0)

        # Brand / Logo
        brand_label = ctk.CTkLabel(
            top_bar,
            text="🔐 Secure Memory Manager",
            font=(FONT_FAMILY, 16, "bold"),
            text_color=THEME["text"]
        )
        brand_label.pack(side="left", padx=20, pady=12)

        # Security Status Pill
        lock_status = "🔒 RAM Locked (VirtualLock)" if self.key_buffer.locked else "🛡️ Secure Memory"
        status_pill = ctk.CTkLabel(
            top_bar,
            text=f"{lock_status}  •  AES-256-GCM",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=THEME["success"],
            fg_color=THEME["card"],
            corner_radius=12,
            padx=12,
            pady=4
        )
        status_pill.pack(side="left", padx=10, pady=12)

        # Logout & Wipe Memory Button
        logout_btn = ctk.CTkButton(
            top_bar,
            text="🚪 Logout & Wipe RAM",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=THEME["danger"],
            hover_color=THEME["danger_hover"],
            width=140,
            height=34,
            command=self._handle_logout
        )
        logout_btn.pack(side="right", padx=20, pady=12)

        # User Info
        user_label = ctk.CTkLabel(
            top_bar,
            text=f"User: {self.user['username']}",
            font=(FONT_FAMILY, 13),
            text_color=THEME["text_muted"]
        )
        user_label.pack(side="right", padx=15, pady=12)

        # 2. Main Tabview
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=THEME["surface"],
            segmented_button_fg_color=THEME["card"],
            segmented_button_selected_color=THEME["primary"],
            segmented_button_selected_hover_color=THEME["primary_hover"]
        )
        self.tabview.pack(fill="both", expand=True, padx=20, pady=15)

        self.tabview.add("📁 File Vault")
        self.tabview.add("📝 Secure Notes")
        self.tabview.add("📜 Audit Logs")
        self.tabview.add("🛡️ Memory & Security")

        self._build_vault_tab()
        self._build_notes_tab()
        self._build_audit_tab()
        self._build_security_tab()

        # 3. Bottom Progress Bar for Long Operations
        self.progress_frame = ctk.CTkFrame(self, fg_color=THEME["surface"], height=32, corner_radius=0)
        self.progress_frame.pack(fill="x", side="bottom")

        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, width=300, height=8)
        self.progress_bar.set(0)
        self.progress_bar.pack(side="left", padx=20, pady=10)

        self.progress_label = ctk.CTkLabel(
            self.progress_frame,
            text="Idle • Ready",
            font=(FONT_FAMILY, 11),
            text_color=THEME["text_muted"]
        )
        self.progress_label.pack(side="left", padx=10, pady=6)

    # ---------------- TAB 1: FILE VAULT ----------------
    def _build_vault_tab(self):
        tab = self.tabview.tab("📁 File Vault")

        # Action Toolbar
        toolbar = ctk.CTkFrame(tab, fg_color="transparent")
        toolbar.pack(fill="x", padx=10, pady=(10, 15))

        encrypt_btn = ctk.CTkButton(
            toolbar,
            text="📤 Encrypt New File",
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            height=38,
            command=self._on_encrypt_file
        )
        encrypt_btn.pack(side="left", padx=(0, 10))

        self.shred_orig_var = ctk.BooleanVar(value=False)
        shred_check = ctk.CTkCheckBox(
            toolbar,
            text="Shred original file after encryption",
            variable=self.shred_orig_var,
            font=(FONT_FAMILY, 12),
            text_color=THEME["text_muted"]
        )
        shred_check.pack(side="left", padx=10)

        refresh_btn = ctk.CTkButton(
            toolbar,
            text="🔄 Refresh",
            font=(FONT_FAMILY, 12),
            fg_color=THEME["card"],
            hover_color=THEME["card_hover"],
            width=80,
            height=38,
            command=self.refresh_vault_files
        )
        refresh_btn.pack(side="right")

        # Files Container
        self.files_scroll = ctk.CTkScrollableFrame(tab, fg_color=THEME["card"], corner_radius=8)
        self.files_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def refresh_vault_files(self):
        for w in self.files_scroll.winfo_children():
            w.destroy()

        files = self.db.list_vault_files(self.user["id"])
        # Filter only non-text-notes for the file vault
        file_list = [f for f in files if not f["is_text_note"]]

        if not file_list:
            empty_lbl = ctk.CTkLabel(
                self.files_scroll,
                text="No encrypted files in vault. Click 'Encrypt New File' to add files.",
                font=(FONT_FAMILY, 13),
                text_color=THEME["text_muted"]
            )
            empty_lbl.pack(pady=40)
            return

        for f in file_list:
            row = ctk.CTkFrame(self.files_scroll, fg_color=THEME["surface"], corner_radius=6)
            row.pack(fill="x", padx=5, pady=4)

            # Name & Info
            name_label = ctk.CTkLabel(
                row,
                text=f"📄 {f['original_name']}",
                font=(FONT_FAMILY, 13, "bold"),
                text_color=THEME["text"],
                anchor="w"
            )
            name_label.pack(side="left", padx=15, pady=10)

            size_label = ctk.CTkLabel(
                row,
                text=f"Size: {format_size(f['original_size'])}  •  Encrypted: {format_size(f['encrypted_size'])}",
                font=(FONT_FAMILY, 11),
                text_color=THEME["text_muted"]
            )
            size_label.pack(side="left", padx=10, pady=10)

            # Action Buttons
            file_id = f["id"]
            shred_btn = ctk.CTkButton(
                row,
                text="🗑️ Shred",
                font=(FONT_FAMILY, 11, "bold"),
                fg_color=THEME["danger"],
                hover_color=THEME["danger_hover"],
                width=70,
                height=30,
                command=lambda fid=file_id: self._shred_file(fid)
            )
            shred_btn.pack(side="right", padx=10, pady=10)

            export_btn = ctk.CTkButton(
                row,
                text="📥 Export Decrypted",
                font=(FONT_FAMILY, 11, "bold"),
                fg_color=THEME["success"],
                hover_color=THEME["success_hover"],
                width=120,
                height=30,
                command=lambda fid=file_id: self._export_file(fid)
            )
            export_btn.pack(side="right", padx=5, pady=10)

    def _on_encrypt_file(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Select File to Encrypt"
        )
        if not path:
            return

        shred_orig = self.shred_orig_var.get()
        if shred_orig:
            confirm = messagebox.askyesno(
                "Confirm Secure Shredding",
                f"Warning: Shredding will permanently overwrite and destroy the original file:\n\n{path}\n\nProceed?"
            )
            if not confirm:
                shred_orig = False

        self._set_progress(0, f"Encrypting {os.path.basename(path)}...")

        def run_encrypt():
            def cb(curr, total):
                if total > 0:
                    fraction = curr / total
                    self.after(0, lambda: self._set_progress(fraction, f"Encrypting... {int(fraction * 100)}%"))

            try:
                self.vault.encrypt_and_store_file(
                    user_id=self.user["id"],
                    username=self.user["username"],
                    src_path=path,
                    key_buffer=self.key_buffer,
                    shred_original=shred_orig,
                    progress_cb=cb
                )
                self.after(0, lambda: self._finish_encrypt_success(path, shred_orig))
            except Exception as e:
                self.after(0, lambda: self._show_error("Encryption Error", str(e)))

        threading.Thread(target=run_encrypt, daemon=True).start()

    def _finish_encrypt_success(self, path: str, shredded: bool):
        self._set_progress(1.0, "Ready")
        msg = f"Successfully encrypted '{os.path.basename(path)}'."
        if shredded:
            msg += "\nOriginal file was securely shredded."
        messagebox.showinfo("Success", msg)
        self.refresh_vault_files()
        self.refresh_audit_logs()

    def _export_file(self, file_id: int):
        dest_dir = filedialog.askdirectory(
            parent=self,
            title="Select Destination Folder for Decrypted File"
        )
        if not dest_dir:
            return

        self._set_progress(0, "Decrypting file...")

        def run_export():
            def cb(curr, total):
                if total > 0:
                    fraction = curr / total
                    self.after(0, lambda: self._set_progress(fraction, f"Decrypting... {int(fraction * 100)}%"))

            try:
                out_path = self.vault.decrypt_and_export_file(
                    user_id=self.user["id"],
                    username=self.user["username"],
                    file_id=file_id,
                    destination_dir=dest_dir,
                    key_buffer=self.key_buffer,
                    progress_cb=cb
                )
                self.after(0, lambda: self._finish_export_success(out_path))
            except Exception as e:
                self.after(0, lambda: self._show_error("Decryption Error", str(e)))

        threading.Thread(target=run_export, daemon=True).start()

    def _finish_export_success(self, out_path: str):
        self._set_progress(1.0, "Ready")
        messagebox.showinfo("Export Successful", f"Decrypted file saved to:\n{out_path}")
        self.refresh_audit_logs()

    def _shred_file(self, file_id: int):
        f = self.db.get_vault_file(self.user["id"], file_id)
        if not f:
            return

        confirm = messagebox.askyesno(
            "Confirm Vault Shred",
            f"Are you sure you want to permanently shred '{f['original_name']}' from the vault?\n\nThis cannot be undone."
        )
        if not confirm:
            return

        ok = self.vault.delete_vault_file(self.user["id"], self.user["username"], file_id)
        if ok:
            messagebox.showinfo("Shredded", "Vault file shredded and eliminated.")
            self.refresh_vault_files()
            self.refresh_audit_logs()
        else:
            messagebox.showerror("Error", "Could not shred file.")

    # ---------------- TAB 2: SECURE NOTES ----------------
    def _build_notes_tab(self):
        tab = self.tabview.tab("📝 Secure Notes")

        # Two-column layout
        left_panel = ctk.CTkFrame(tab, fg_color=THEME["card"], width=240, corner_radius=8)
        left_panel.pack(side="left", fill="y", padx=(10, 5), pady=10)

        right_panel = ctk.CTkFrame(tab, fg_color=THEME["card"], corner_radius=8)
        right_panel.pack(side="right", fill="both", expand=True, padx=(5, 10), pady=10)

        # Left panel controls
        new_note_btn = ctk.CTkButton(
            left_panel,
            text="+ New Secure Note",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            command=self._new_note_clicked
        )
        new_note_btn.pack(fill="x", padx=10, pady=10)

        self.notes_scroll = ctk.CTkScrollableFrame(left_panel, fg_color="transparent")
        self.notes_scroll.pack(fill="both", expand=True, padx=5, pady=(0, 5))

        # Right panel controls (Editor)
        self.note_title_entry = ctk.CTkEntry(
            right_panel,
            placeholder_text="Note Title (e.g. Passwords, API Keys, Journal)",
            font=(FONT_FAMILY, 14, "bold"),
            height=38
        )
        self.note_title_entry.pack(fill="x", padx=15, pady=(15, 10))

        self.note_textbox = ctk.CTkTextbox(
            right_panel,
            font=(FONT_FAMILY, 13),
            fg_color=THEME["surface"],
            text_color=THEME["text"],
            wrap="word"
        )
        self.note_textbox.pack(fill="both", expand=True, padx=15, pady=5)

        note_actions = ctk.CTkFrame(right_panel, fg_color="transparent")
        note_actions.pack(fill="x", padx=15, pady=10)

        save_note_btn = ctk.CTkButton(
            note_actions,
            text="💾 Save Encrypted Note",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=THEME["success"],
            hover_color=THEME["success_hover"],
            width=160,
            command=self._save_note
        )
        save_note_btn.pack(side="left")

        delete_note_btn = ctk.CTkButton(
            note_actions,
            text="🗑️ Delete Note",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=THEME["danger"],
            hover_color=THEME["danger_hover"],
            width=120,
            command=self._delete_current_note
        )
        delete_note_btn.pack(side="right")

    def refresh_notes_list(self):
        for w in self.notes_scroll.winfo_children():
            w.destroy()

        files = self.db.list_vault_files(self.user["id"])
        notes = [f for f in files if f["is_text_note"]]

        if not notes:
            lbl = ctk.CTkLabel(self.notes_scroll, text="No notes saved", font=(FONT_FAMILY, 11), text_color=THEME["text_muted"])
            lbl.pack(pady=20)
            return

        for n in notes:
            btn = ctk.CTkButton(
                self.notes_scroll,
                text=f"📝 {n['original_name']}",
                font=(FONT_FAMILY, 12),
                fg_color=THEME["surface"],
                hover_color=THEME["card_hover"],
                anchor="w",
                command=lambda nid=n["id"]: self._load_note(nid)
            )
            btn.pack(fill="x", pady=2)

    def _new_note_clicked(self):
        self.selected_note_id = None
        self.note_title_entry.delete(0, "end")
        self.note_textbox.delete("1.0", "end")

    def _load_note(self, file_id: int):
        try:
            self.selected_note_id = file_id
            rec = self.db.get_vault_file(self.user["id"], file_id)
            if not rec:
                return

            self.note_title_entry.delete(0, "end")
            self.note_title_entry.insert(0, rec["original_name"])

            content = self.vault.read_note_content(self.user["id"], self.user["username"], file_id, self.key_buffer)
            self.note_textbox.delete("1.0", "end")
            self.note_textbox.insert("1.0", content)
            self.refresh_audit_logs()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt note: {str(e)}")

    def _save_note(self):
        title = self.note_title_entry.get().strip()
        content = self.note_textbox.get("1.0", "end-1c")

        if not title:
            messagebox.showerror("Error", "Note title is required.")
            return

        try:
            # If editing existing note, remove the previous version first
            if self.selected_note_id:
                self.vault.delete_vault_file(self.user["id"], self.user["username"], self.selected_note_id)

            res = self.vault.create_and_store_note(
                user_id=self.user["id"],
                username=self.user["username"],
                title=title,
                content=content,
                key_buffer=self.key_buffer
            )
            self.selected_note_id = res["id"]
            messagebox.showinfo("Saved", "Encrypted note securely saved!")
            self.refresh_notes_list()
            self.refresh_audit_logs()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save note: {str(e)}")

    def _delete_current_note(self):
        if not self.selected_note_id:
            messagebox.showinfo("Info", "Select a note to delete.")
            return

        confirm = messagebox.askyesno("Confirm Delete", "Permanently shred this encrypted note?")
        if confirm:
            self.vault.delete_vault_file(self.user["id"], self.user["username"], self.selected_note_id)
            self._new_note_clicked()
            self.refresh_notes_list()
            self.refresh_audit_logs()

    # ---------------- TAB 3: AUDIT LOGS ----------------
    def _build_audit_tab(self):
        tab = self.tabview.tab("📜 Audit Logs")

        header = ctk.CTkFrame(tab, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(
            header,
            text="Chronological Cryptographic Audit Trail",
            font=(FONT_FAMILY, 14, "bold"),
            text_color=THEME["text"]
        ).pack(side="left")

        ctk.CTkButton(
            header,
            text="🔄 Refresh Logs",
            font=(FONT_FAMILY, 11),
            fg_color=THEME["card"],
            hover_color=THEME["card_hover"],
            width=100,
            command=self.refresh_audit_logs
        ).pack(side="right")

        self.audit_scroll = ctk.CTkScrollableFrame(tab, fg_color=THEME["card"], corner_radius=8)
        self.audit_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def refresh_audit_logs(self):
        for w in self.audit_scroll.winfo_children():
            w.destroy()

        logs = self.db.get_audit_logs(self.user["id"], limit=50)
        if not logs:
            ctk.CTkLabel(self.audit_scroll, text="No audit events yet.", font=(FONT_FAMILY, 12), text_color=THEME["text_muted"]).pack(pady=30)
            return

        for l in logs:
            row = ctk.CTkFrame(self.audit_scroll, fg_color=THEME["surface"], corner_radius=6)
            row.pack(fill="x", padx=5, pady=3)

            # Status Icon
            status_color = THEME["success"] if l["status"] == "SUCCESS" else THEME["danger"]
            icon = "✓" if l["status"] == "SUCCESS" else "✗"
            ctk.CTkLabel(row, text=icon, font=(FONT_FAMILY, 13, "bold"), text_color=status_color).pack(side="left", padx=(10, 5), pady=6)

            # Action tag
            ctk.CTkLabel(row, text=f"[{l['action']}]", font=(FONT_FAMILY, 11, "bold"), text_color=THEME["secondary"]).pack(side="left", padx=5)

            # Details
            ctk.CTkLabel(row, text=l["details"], font=(FONT_FAMILY, 12), text_color=THEME["text"]).pack(side="left", padx=10)

            # Timestamp
            ts = l["timestamp"][:19].replace("T", " ")
            ctk.CTkLabel(row, text=ts, font=(FONT_FAMILY, 10), text_color=THEME["text_muted"]).pack(side="right", padx=15)

    # ---------------- TAB 4: MEMORY & SECURITY ----------------
    def _build_security_tab(self):
        tab = self.tabview.tab("🛡️ Memory & Security")

        card = ctk.CTkFrame(tab, fg_color=THEME["card"], corner_radius=12)
        card.pack(fill="both", expand=True, padx=15, pady=15)

        title = ctk.CTkLabel(
            card,
            text="🛡️ Active Cryptographic & Memory Protections",
            font=(FONT_FAMILY, 16, "bold"),
            text_color=THEME["text"]
        )
        title.pack(anchor="w", padx=20, pady=(20, 15))

        specs = [
            ("🔐 Memory Locking (VirtualLock)", "ACTIVE" if self.key_buffer.locked else "FALLBACK",
             "Locks physical memory pages into RAM via Windows VirtualLock kernel API. Prevents operating system from swapping sensitive keys or plaintext to pagefile.sys or crash dumps."),
            ("🧹 Zero-Knowledge RAM Scrubbing", "ACTIVE",
             "All sensitive cryptographic keys and memory buffers are allocated as mutable memory regions and overwritten with zeros (memset) immediately upon session termination or file completion."),
            ("🔒 Authenticated Cipher", "AES-256-GCM",
             "Galois/Counter Mode with 96-bit random nonces per chunk and 128-bit authentication tags. Protects against bit-flipping and ciphertext manipulation attacks."),
            ("🔑 Key Derivation Function", "PBKDF2-HMAC-SHA256 (600,000 Rounds)",
             "Per-user 256-bit AES keys derived with unique cryptographically random 32-byte salts. Zero shared master keys on disk."),
            ("🛡️ Password Hashing", "Argon2id (Memory-Hard)",
             "State-of-the-art password hashing using 64MB memory, 3 iterations, 4 parallelism. Highly resistant to GPU and ASIC brute-forcing."),
            ("📱 Two-Factor Authentication", "RFC 6238 TOTP Standard",
             "Compatible with Google Authenticator, Microsoft Authenticator, Bitwarden, and Aegis.")
        ]

        for item, status, desc in specs:
            row = ctk.CTkFrame(card, fg_color=THEME["surface"], corner_radius=8)
            row.pack(fill="x", padx=20, pady=6)

            hdr = ctk.CTkFrame(row, fg_color="transparent")
            hdr.pack(fill="x", padx=12, pady=(8, 2))

            ctk.CTkLabel(hdr, text=item, font=(FONT_FAMILY, 13, "bold"), text_color=THEME["text"]).pack(side="left")
            ctk.CTkLabel(
                hdr,
                text=status,
                font=(FONT_FAMILY, 11, "bold"),
                text_color=THEME["success"] if "ACTIVE" in status or "AES" in status or "PBKDF2" in status or "Argon" in status or "RFC" in status else THEME["warning"],
                fg_color=THEME["card"],
                corner_radius=6,
                padx=8,
                pady=2
            ).pack(side="right")

            ctk.CTkLabel(
                row,
                text=desc,
                font=(FONT_FAMILY, 11),
                text_color=THEME["text_muted"],
                wraplength=650,
                justify="left"
            ).pack(anchor="w", padx=12, pady=(0, 8))

    # ---------------- HELPERS & LOGOUT ----------------
    def _set_progress(self, val: float, text: str):
        self.progress_bar.set(val)
        self.progress_label.configure(text=text)

    def _show_error(self, title: str, msg: str):
        self._set_progress(0, "Error")
        messagebox.showerror(title, msg)

    def _handle_logout(self):
        # Explicitly wipe encryption key from physical memory
        self.key_buffer.wipe()
        self.db.log_event(self.user["id"], self.user["username"], "LOGOUT", "User logged out; memory wiped", "SUCCESS")
        self.on_logout()
