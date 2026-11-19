"""
Secure Memory Manager
Main Application Entry Point
"""

import sys
import os
import customtkinter as ctk
from db.database import Database
from core.vault import VaultManager
from core.crypto import SecureBuffer
from gui.theme import THEME
from gui.login_window import LoginFrame
from gui.register_window import RegisterFrame
from gui.main_window import MainDashboard


class SecureMemoryApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("Secure Memory Manager — Zero-Knowledge Encrypted Vault")
        self.geometry("980x640")
        self.minsize(850, 550)
        self.configure(fg_color=THEME["bg_dark"])

        # Core Services
        self.db = Database("vault.db")
        self.vault = VaultManager(self.db, "vault_storage")

        # Session State
        self.active_user = None
        self.active_key_buffer: SecureBuffer = None

        # Content container
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)

        # Intercept window close to securely wipe memory
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Show initial login frame
        self.show_login()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_container()
        frame = LoginFrame(
            parent=self.container,
            db=self.db,
            on_login_success=self.on_login_success,
            on_go_to_register=self.show_register
        )
        frame.place(relx=0.5, rely=0.5, anchor="center")

    def show_register(self):
        self.clear_container()
        frame = RegisterFrame(
            parent=self.container,
            db=self.db,
            on_back_to_login=self.show_login
        )
        frame.place(relx=0.5, rely=0.5, anchor="center")

    def on_login_success(self, user, key_buffer: SecureBuffer):
        self.active_user = user
        self.active_key_buffer = key_buffer
        self.show_dashboard()

    def show_dashboard(self):
        self.clear_container()
        dashboard = MainDashboard(
            parent=self.container,
            db=self.db,
            vault=self.vault,
            user=self.active_user,
            key_buffer=self.active_key_buffer,
            on_logout=self.on_logout
        )
        dashboard.pack(fill="both", expand=True)

    def on_logout(self):
        if self.active_key_buffer and not self.active_key_buffer.wiped:
            self.active_key_buffer.wipe()
        self.active_key_buffer = None
        self.active_user = None
        self.show_login()

    def _on_close(self):
        # Securely wipe memory before terminating process
        if self.active_key_buffer and not self.active_key_buffer.wiped:
            self.active_key_buffer.wipe()
        self.destroy()


def main():
    app = SecureMemoryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
