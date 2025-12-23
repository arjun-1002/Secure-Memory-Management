import os
import json
import hashlib
import random
from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

# ---------------- CONFIG ----------------
USERS_FILE = "users.json"
FILES_DIR = "encrypted_files"
DECRYPTED_DIR = "decrypted_files"
KEY_FILE = "secret.key"

theme = {
    "BG": "#0f172a",
    "CARD": "#1e293b",
    "TEXT": "#e5e7eb",
    "PRIMARY": "#6366f1",
    "SUCCESS": "#22c55e",
    "DANGER": "#ef4444"
}

FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_BTN = ("Segoe UI", 11, "bold")

# ---------------- SETUP ----------------
os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f)

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    cipher = Fernet(f.read())

# ---------------- BACKEND ----------------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def load_users():
    with open(USERS_FILE) as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def ensure_user_dir(username):
    path = os.path.join(FILES_DIR, username)
    os.makedirs(path, exist_ok=True)
    return path

def register(username, password):
    users = load_users()
    if username in users:
        return False
    users[username] = {"password": hash_password(password)}
    save_users(users)
    ensure_user_dir(username)
    return True

def login(username, password):
    users = load_users()
    return username in users and users[username]["password"] == hash_password(password)

def encrypt_file(username, path):
    ensure_user_dir(username)
    name = os.path.basename(path) + ".enc"
    with open(path, "rb") as f:
        encrypted = cipher.encrypt(f.read())
    with open(os.path.join(FILES_DIR, username, name), "wb") as f:
        f.write(encrypted)

def encrypt_text(username, filename, text):
    ensure_user_dir(username)
    encrypted = cipher.encrypt(text.encode())
    with open(os.path.join(FILES_DIR, username, filename + ".enc"), "wb") as f:
        f.write(encrypted)

def decrypt_file(username, filename):
    ensure_user_dir(username)
    with open(os.path.join(FILES_DIR, username, filename), "rb") as f:
        data = cipher.decrypt(f.read())
    out = os.path.join(DECRYPTED_DIR, filename.replace(".enc", ""))
    with open(out, "wb") as f:
        f.write(data)
    return out

# ---------------- GUI BASE ----------------
root = Tk()
root.title("Secure File Management System")
root.geometry("600x450")
root.resizable(False, False)
root.configure(bg=theme["BG"])

current_user = None

def clear():
    for w in root.winfo_children():
        w.destroy()

def card():
    f = Frame(root, bg=theme["CARD"])
    f.place(relx=0.5, rely=0.5, anchor="center", width=420, height=380)
    return f

def title(parent, text):
    Label(parent, text=text, font=FONT_TITLE,
          bg=theme["CARD"], fg=theme["TEXT"]).pack(pady=15)

def btn(parent, text, color, cmd):
    Button(parent, text=text, command=cmd,
           bg=color, fg="white", font=FONT_BTN,
           width=28, height=2, bd=0).pack(pady=6)

# ---------------- LOGIN ----------------
def login_screen():
    clear()
    c = card()
    title(c, "🔐 Secure File System")

    content = Frame(c, bg=theme["CARD"])
    content.pack(pady=10)

    Label(content, text="Username", bg=theme["CARD"], fg=theme["TEXT"]).grid(row=0, column=0, sticky="w")
    u = Entry(content, width=32)
    u.grid(row=1, column=0, pady=5)

    Label(content, text="Password", bg=theme["CARD"], fg=theme["TEXT"]).grid(row=2, column=0, sticky="w")
    p = Entry(content, show="*", width=32)
    p.grid(row=3, column=0, pady=5)

    def do_login():
        global current_user
        if login(u.get(), p.get()):
            otp = random.randint(100000, 999999)

            otp_win = Toplevel(root)
            otp_win.title("OTP Verification")
            otp_win.geometry("300x220")
            otp_win.configure(bg=theme["CARD"])
            otp_win.resizable(False, False)

            Label(otp_win, text="Your OTP", bg=theme["CARD"], fg=theme["TEXT"]).pack(pady=10)
            Label(otp_win, text=str(otp), font=("Segoe UI", 18, "bold"),
                  bg=theme["CARD"], fg=theme["PRIMARY"]).pack()

            otp_entry = Entry(otp_win, width=20)
            otp_entry.pack(pady=10)

            def verify():
                nonlocal otp
                global current_user
                if otp_entry.get().isdigit() and int(otp_entry.get()) == otp:
                    current_user = u.get()
                    ensure_user_dir(current_user)
                    otp_win.destroy()
                    dashboard()
                else:
                    messagebox.showerror("Error", "Invalid OTP")

            Button(otp_win, text="Verify", bg=theme["PRIMARY"],
                   fg="white", font=FONT_BTN, command=verify).pack(pady=10)
        else:
            messagebox.showerror("Error", "Invalid credentials")

    btn(c, "Login", theme["PRIMARY"], do_login)
    btn(c, "Register", theme["SUCCESS"], register_screen)

# ---------------- REGISTER ----------------
def register_screen():
    clear()
    c = card()
    title(c, "📝 Register")

    content = Frame(c, bg=theme["CARD"])
    content.pack(pady=10)

    Label(content, text="Username", bg=theme["CARD"], fg=theme["TEXT"]).grid(row=0, column=0, sticky="w")
    u = Entry(content, width=32)
    u.grid(row=1, column=0, pady=5)

    Label(content, text="Password", bg=theme["CARD"], fg=theme["TEXT"]).grid(row=2, column=0, sticky="w")
    p = Entry(content, show="*", width=32)
    p.grid(row=3, column=0, pady=5)

    def do_register():
        if register(u.get(), p.get()):
            messagebox.showinfo("Success", "Registered successfully")
            login_screen()
        else:
            messagebox.showerror("Error", "User already exists")

    btn(c, "Register", theme["SUCCESS"], do_register)
    btn(c, "Back", theme["PRIMARY"], login_screen)

# ---------------- DASHBOARD ----------------
def dashboard():
    clear()
    c = card()
    title(c, f"👤 Welcome, {current_user}")

    btn(c, "📤 Upload & Encrypt File", theme["PRIMARY"], upload_file)
    btn(c, "📝 Create Secure Text", theme["PRIMARY"], create_text)
    btn(c, "🔓 Decrypt & Open File", theme["SUCCESS"], decrypt_gui)
    btn(c, "🚪 Logout", theme["DANGER"], logout)

def upload_file():
    path = filedialog.askopenfilename(parent=root)
    if path:
        encrypt_file(current_user, path)
        messagebox.showinfo("Success", "File encrypted")

def create_text():
    win = Toplevel(root)
    win.title("Secure Text")
    win.geometry("420x320")
    win.configure(bg=theme["CARD"])
    win.resizable(False, False)

    Label(win, text="Filename", bg=theme["CARD"], fg=theme["TEXT"]).pack(pady=5)
    fname = Entry(win, width=40)
    fname.pack(pady=5)

    txt = Text(win, height=8, bg="#1e293b", fg="#e5e7eb", insertbackground="white")
    txt.pack(pady=5)

    def save():
        if fname.get().strip():
            encrypt_text(current_user, fname.get().strip(), txt.get("1.0", END))
            messagebox.showinfo("Saved", "Encrypted text saved")
            win.destroy()
        else:
            messagebox.showerror("Error", "Filename required")

    Button(win, text="Save", bg=theme["PRIMARY"],
           fg="white", font=FONT_BTN, command=save).pack(pady=10)

def decrypt_gui():
    user_dir = ensure_user_dir(current_user)

    f = filedialog.askopenfilename(
        parent=root,
        initialdir=os.path.abspath(user_dir),
        title="Select Encrypted File",
        filetypes=[("Encrypted Files", "*.enc")]
    )

    if f:
        out = decrypt_file(current_user, os.path.basename(f))
        try:
            os.startfile(out)
        except:
            messagebox.showinfo("Decrypted", f"Saved at:\n{out}")

def logout():
    global current_user
    current_user = None
    login_screen()

# ---------------- START ----------------
login_screen()
root.mainloop()
