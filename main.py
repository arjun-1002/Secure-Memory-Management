import json
import hashlib
import random
import os
from datetime import datetime
from cryptography.fernet import Fernet

USERS_FILE = "users.json"
FILES_DIR = "encrypted_files"
KEY_FILE = "secret.key"


# ---------- SETUP ----------
os.makedirs(FILES_DIR, exist_ok=True)

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f)

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    cipher = Fernet(f.read())


# ---------- AUTH ----------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def load_users():
    with open(USERS_FILE) as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def register_user(u, p):
    users = load_users()
    if u in users:
        return False
    users[u] = {"password": hash_password(p)}
    save_users(users)
    os.makedirs(os.path.join(FILES_DIR, u), exist_ok=True)
    return True

def login_user(u, p):
    users = load_users()
    return u in users and users[u]["password"] == hash_password(p)

def generate_otp():
    return random.randint(100000, 999999)


# ---------- SECURITY ----------
def buffer_overflow(data):
    return len(data) > 1024

def malware_scan(data):
    return any(x in data.lower() for x in ["virus", "malware", "trojan"])


# ---------- FILE OPS ----------
def user_dir(u):
    return os.path.join(FILES_DIR, u)

def list_files(u):
    return os.listdir(user_dir(u))

def save_text_file(u, fname, text):
    encrypted = cipher.encrypt(text.encode())
    with open(os.path.join(user_dir(u), fname), "wb") as f:
        f.write(encrypted)

def read_text_file(u, fname):
    with open(os.path.join(user_dir(u), fname), "rb") as f:
        data = cipher.decrypt(f.read())
    return data.decode()

def upload_file(u, path):
    if not os.path.exists(path):
        print("❌ File not found")
        return
    name = os.path.basename(path) + ".enc"
    with open(path, "rb") as f:
        encrypted = cipher.encrypt(f.read())
    with open(os.path.join(user_dir(u), name), "wb") as f:
        f.write(encrypted)
    print("🔒 File uploaded & encrypted")

def decrypt_file(u, fname):
    out_name = fname.replace(".enc", "")
    with open(os.path.join(user_dir(u), fname), "rb") as f:
        decrypted = cipher.decrypt(f.read())
    with open(out_name, "wb") as f:
        f.write(decrypted)
    print(f"✅ File decrypted and saved as {out_name}")

def metadata(u, fname):
    p = os.path.join(user_dir(u), fname)
    s = os.stat(p)
    return s.st_size, datetime.fromtimestamp(s.st_ctime)


# ---------- MAIN ----------
print("\n🔐 Secure File Management System")

while True:
    print("\n1. Register\n2. Login\n3. Exit")
    c = input("Choice: ")

    if c == "1":
        u = input("Username: ")
        p = input("Password: ")
        print("✅ Registered" if register_user(u, p) else "❌ User exists")

    elif c == "2":
        u = input("Username: ")
        p = input("Password: ")
        if not login_user(u, p):
            print("❌ Invalid login")
            continue

        otp = generate_otp()
        print("OTP:", otp)
        if int(input("Enter OTP: ")) != otp:
            print("❌ Wrong OTP")
            continue

        while True:
            print("""
1. Create encrypted text file
2. Read encrypted TEXT file
3. Decrypt & restore ANY file
4. View metadata
5. Upload & encrypt file
6. Logout
""")
            ch = input("Choose: ")

            if ch == "1":
                fn = input("Filename: ")
                text = input("Text: ")
                if buffer_overflow(text) or malware_scan(text):
                    print("⚠ Security threat detected")
                else:
                    save_text_file(u, fn, text)
                    print("🔒 Saved")

            elif ch == "2":
                print(list_files(u))
                fn = input("Text file name: ")
                try:
                    print(read_text_file(u, fn))
                except:
                    print("❌ Not a text file")

            elif ch == "3":
                print(list_files(u))
                fn = input("Encrypted file (.enc): ")
                decrypt_file(u, fn)

            elif ch == "4":
                print(list_files(u))
                fn = input("File: ")
                size, time = metadata(u, fn)
                print("Size:", size, "Created:", time)

            elif ch == "5":
                upload_file(u, input("Enter full file path: "))

            elif ch == "6":
                break

    elif c == "3":
        break
