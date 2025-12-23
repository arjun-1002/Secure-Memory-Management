🔐 Secure File Management System

A Python Tkinter app to securely manage files and text with encryption, user authentication, and OTP verification.

Features

📝 User Registration & Login with password hashing (SHA-256)

🔒 File Encryption & Decryption per user

✍️ Secure Text Creation with encrypted storage

🌙 Dark Themed GUI for easy use

🔑 OTP Verification for extra security

Installation
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
python -m venv venv       # optional
# activate environment
pip install cryptography
python main.py


Tkinter comes with Python; no extra install needed.

Usage

Register a new user

Login with username, password, and OTP

Encrypt files or text

Decrypt files and open them

Encrypted files → encrypted_files/<username>
Decrypted files → decrypted_files/

Technologies

Python 3.6+

Tkinter (GUI)

Cryptography (Fernet)

SHA-256 for password hashing
