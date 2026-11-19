# 🔐 Secure Memory Management & Encrypted Vault

An enterprise-grade, zero-knowledge desktop vault that combines **RAM memory protection (Windows VirtualLock)** with **AES-256-GCM authenticated encryption**, **Argon2id password hashing**, and **RFC 6238 TOTP two-factor authentication**.

---

## 🛡️ Core Security Architecture

### 1. True Memory Protection & Scrubbing (`core/memory.py`)
- **Memory Page Locking (`VirtualLock`):** Sensitive cryptographic keys and buffers are locked into physical RAM using the Windows `VirtualLock` kernel API. This prevents the OS from writing secrets to `pagefile.sys`, swap space, or crash dumps.
- **Zero-Knowledge RAM Scrubbing:** Sensitive keys, plaintexts, and credentials are kept in mutable `SecureBuffer` instances. When logging out, closing files, or exiting the application, memory regions are immediately overwritten with zeros via `ctypes.memset` to prevent memory scraping.

### 2. Authenticated Cryptography (`core/crypto.py`)
- **Per-User Key Derivation:** Keys are derived per-user using **PBKDF2-HMAC-SHA256 (600,000 iterations)** with a cryptographically secure 32-byte salt (`os.urandom(32)`). **No shared master key exists on disk.**
- **AES-256-GCM Streaming:** Files of any size (from MBs to multi-GBs) are encrypted and decrypted in authenticated 64 KB chunks with unique nonces and integrity tags, preventing RAM exhaustion and tampering attacks.

### 3. Password Hashing & True 2FA (`core/auth.py`)
- **Argon2id Hashing:** Passwords are never stored in plaintext or weak hashes. Uses memory-hard Argon2id (64 MB memory cost, 3 time iterations, 4 parallelism).
- **Standard TOTP 2FA (RFC 6238):** Scannable QR code setup compatible with Google Authenticator, Bitwarden, Microsoft Authenticator, and Aegis.
- **Brute-Force Account Protection:** Automatic progressive lockout after 5 consecutive failed login attempts.

### 4. Multi-Pass Secure File Shredder (`core/shredder.py`)
- Multi-pass overwrite (Pass 1: Cryptographic random bytes, Pass 2: `0xFF`, Pass 3: `0x00`) with filesystem `fsync` flushes and truncation before unlinking, preventing forensic undelete/recovery.

### 5. ACID Database & Cryptographic Audit Trail (`db/database.py`)
- Replaces flat JSON files with SQLite operating in **WAL (Write-Ahead Logging)** mode.
- Maintains an append-only cryptographic audit log tracking logins, encryptions, decryptions, and shreds.

---

## 📁 Project Structure

```text
├── core/
│   ├── memory.py         # SecureBuffer, VirtualLock, memory wiping (ctypes.memset)
│   ├── crypto.py         # AES-256-GCM streaming encryption & PBKDF2 key derivation
│   ├── auth.py           # Argon2id password hashing & RFC 6238 TOTP engine
│   ├── shredder.py       # Multi-pass secure file shredder
│   └── vault.py          # Vault operations (files & secure text notes)
├── db/
│   └── database.py       # SQLite WAL database & audit logging
├── gui/
│   ├── theme.py          # CustomTkinter styling & color palette
│   ├── login_window.py   # Modern login view with 2FA verification
│   ├── register_window.py# Registration with password strength & QR code 2FA
│   └── main_window.py    # Vault Explorer, Secure Notes editor, Audit Logs
├── tests/
│   ├── test_crypto.py    # Unit tests for encryption & key derivation
│   ├── test_memory.py    # Unit tests for VirtualLock & memory wiping
│   └── test_vault.py     # End-to-end integration tests
├── requirements.txt      # Dependency specification
├── main.py               # Application launcher
└── README.md             # Project documentation
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10+
- Windows 10/11 (for `VirtualLock` kernel memory locking) or Linux/macOS

### 1. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 2. Run the Application
```bash
python main.py
```

### 3. Run Test Suite
```bash
python -m pytest tests/
```

---

## 🖥️ Usage Guide

1. **Register an Account:**
   - Enter a username and strong password (min 8 characters, uppercase, lowercase, number, symbol).
   - Scan the generated QR code in your authenticator app (Google Authenticator, Bitwarden, etc.).
   - Enter the 6-digit verification code to finalize registration.
2. **Login:**
   - Enter your username, password, and the current 6-digit TOTP code.
   - Your per-user AES key is derived in RAM and locked into physical memory via `VirtualLock`.
3. **File Vault:**
   - Click **"📤 Encrypt New File"** to protect sensitive files. Optionally enable *"Shred original file after encryption"* for permanent disk sanitization.
   - Click **"📥 Export Decrypted"** to decrypt and save files to any designated folder.
   - Click **"🗑️ Shred"** to permanently wipe vault files using multi-pass sanitization.
4. **Secure Notes:**
   - Store API keys, passwords, and sensitive notes directly in the encrypted database.
5. **Logout & RAM Wipe:**
   - Click **"🚪 Logout & Wipe RAM"** to immediately zero-fill all cryptographic keys and memory buffers before terminating the session.
