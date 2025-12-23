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

# Always dark theme
theme = {
    "BG": "#0f172a",
    "CARD": "#1e293b",
    "TEXT": "#e5e7eb",
    "PRIMARY": "#6366f1",
    "SUCCESS": "#22c55e",
    "DANGER": "#ef4444"
}

FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_LABEL = ("Segoe UI", 11)
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

def register(username, password):
    users = load_users()
    if username in users:
        return False
    users[username] = {"password": hash_password(password)}
    save_users(users)
    os.makedirs(os.path.join(FILES_DIR, username), exist_ok=True)
    return True

def login(username, password):
    users = load_users()
    return username in users and users[username]["password"] == hash_password(password)

def encrypt_file(username, path):
    name = os.path.basename(path) + ".enc"
    with open(path, "rb") as f:
        encrypted = cipher.encrypt(f.read())
    with open(os.path.join(FILES_DIR, username, name), "wb") as f:
        f.write(encrypted)

def encrypt_text(username, filename, text):
    encrypted = cipher.encrypt(text.encode())
    with open(os.path.join(FILES_DIR, username, filename + ".enc"), "wb") as f:
        f.write(encrypted)

def decrypt_file(username, filename):
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

current_user = None

def clear():
    for w in root.winfo_children():
        w.destroy()

def card():
    root.configure(bg=theme["BG"])
    f = Frame(root, bg=theme["CARD"])
    f.place(relx=0.5, rely=0.5, anchor="center", width=420, height=380)
    return f

def title(parent, text):
    Label(parent, text=text, font=FONT_TITLE,
          bg=theme["CARD"], fg=theme["TEXT"]).pack(pady=15)

def button(parent, text, color, cmd):
    Button(parent, text=text, command=cmd,
           bg=color, fg="white", font=FONT_BTN,
           width=28, height=2, bd=0).pack(pady=6)

# ---------------- LOGIN ----------------
def login_screen():
    clear()
    c = card()
    title(c, "🔐 Secure File System")

    Label(c, text="Username", bg=theme["CARD"], fg=theme["TEXT"]).pack(anchor="w", padx=40)
    u = Entry(c, width=30)
    u.pack(pady=4)

    Label(c, text="Password", bg=theme["CARD"], fg=theme["TEXT"]).pack(anchor="w", padx=40)
    p = Entry(c, show="*", width=30)
    p.pack(pady=4)

    def do_login():
        global current_user
        if login(u.get(), p.get()):
            otp = random.randint(100000, 999999)
            # OTP window
            otp_win = Toplevel(root)
            otp_win.title("OTP Verification")
            otp_win.geometry("300x200")
            otp_win.configure(bg=theme["CARD"])
            otp_win.resizable(False, False)

            Label(otp_win, text="Your OTP:", bg=theme["CARD"], fg=theme["TEXT"], font=FONT_LABEL).pack(pady=10)
            otp_label = Label(otp_win, text=str(otp), font=("Segoe UI", 18, "bold"),
                              bg=theme["CARD"], fg=theme["PRIMARY"])
            otp_label.pack(pady=5)

            Label(otp_win, text="Enter OTP below:", bg=theme["CARD"], fg=theme["TEXT"], font=FONT_LABEL).pack(pady=10)
            otp_entry = Entry(otp_win, width=20)
            otp_entry.pack(pady=5)

            def verify_otp():
                entered = otp_entry.get()
                if entered.isdigit() and int(entered) == otp:
                    otp_win.destroy()
                    global current_user
                    current_user = u.get()
                    dashboard()
                else:
                    messagebox.showerror("Error", "Invalid OTP")

            Button(otp_win, text="Verify", bg=theme["PRIMARY"], fg="white", font=FONT_BTN,
                   command=verify_otp).pack(pady=10)

        else:
            messagebox.showerror("Error", "Invalid credentials")

    button(c, "Login", theme["PRIMARY"], do_login)
    button(c, "Register", theme["SUCCESS"], register_screen)

# ---------------- REGISTER ----------------
def register_screen():
    clear()
    c = card()
    title(c, "📝 Register")

    Label(c, text="Username", bg=theme["CARD"], fg=theme["TEXT"]).pack(anchor="w", padx=40)
    u = Entry(c, width=30)
    u.pack(pady=4)

    Label(c, text="Password", bg=theme["CARD"], fg=theme["TEXT"]).pack(anchor="w", padx=40)
    p = Entry(c, show="*", width=30)
    p.pack(pady=4)

    def do_register():
        if register(u.get(), p.get()):
            messagebox.showinfo("Success", "Registered successfully")
            login_screen()
        else:
            messagebox.showerror("Error", "User exists")

    button(c, "Register", theme["SUCCESS"], do_register)
    button(c, "Back", theme["PRIMARY"], login_screen)

# ---------------- DASHBOARD ----------------
def dashboard():
    clear()
    c = card()
    title(c, f"👤 Welcome, {current_user}")

    button(c, "📤 Upload & Encrypt File", theme["PRIMARY"], upload_file)
    button(c, "📝 Create Secure Text", theme["PRIMARY"], create_text)
    button(c, "🔓 Decrypt & Open File", theme["SUCCESS"], decrypt_gui)
    button(c, "🚪 Logout", theme["DANGER"], logout)

def upload_file():
    path = filedialog.askopenfilename()
    if path:
        encrypt_file(current_user, path)
        messagebox.showinfo("Success", "File encrypted")

def create_text():
    win = Toplevel(root)
    win.title("Secure Text")
    win.geometry("400x300")
    win.configure(bg=theme["CARD"])
    win.resizable(False, False)

    Label(win, text="Filename", bg=theme["CARD"], fg=theme["TEXT"]).pack(pady=5)
    fname = Entry(win, width=40)
    fname.pack(pady=5)

    txt = Text(win, height=8, bg="#1e293b", fg="#e5e7eb")
    txt.pack(pady=5)

    def save_text():
        filename = fname.get().strip()
        content = txt.get("1.0", END)
        if filename:
            encrypt_text(current_user, filename, content)
            messagebox.showinfo("Success", f"File '{filename}.enc' saved!")
            win.destroy()  # Close window after saving
        else:
            messagebox.showerror("Error", "Please enter a filename.")

    Button(win, text="Save", command=save_text, bg=theme["PRIMARY"], fg="white", font=FONT_BTN).pack(pady=5)

def decrypt_gui():
    user_dir = os.path.join(FILES_DIR, current_user)
    os.makedirs(user_dir, exist_ok=True)  # Ensure folder exists
    user_dir = os.path.abspath(user_dir)

    f = filedialog.askopenfilename(initialdir=user_dir,
                                   title="Select a file to decrypt",
                                   filetypes=[("Encrypted Files", "*.enc")])
    if f:
        out = decrypt_file(current_user, os.path.basename(f))
        try:
            os.startfile(out)  # Windows only
        except Exception:
            messagebox.showinfo("Decrypted", f"File saved at: {out}")

def logout():
    global current_user
    current_user = None
    login_screen()

# ---------------- START ----------------
login_screen()
root.mainloop()
