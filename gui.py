# gui.py
from tkinter import *
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import os, base64
from auth import authenticate_user, register_user
from crypto_module import derive_key_from_password, encrypt_file, decrypt_file, secure_delete, reencrypt_file
from integrity import sha256_hash, add_metadata_entry, load_metadata, update_metadata_entry, find_entry_by_encpath

LOGGED_IN_USER = None

# ------------------- Color & Style Config -------------------
PRIMARY = "#1E3D59"      # dark navy
SECONDARY = "#00ADB5"    # teal blue
ACCENT = "#F8B400"       # golden yellow
BG = "#F1F6F9"           # soft gray background
TEXT = "#0A0A0A"

FONT_TITLE = ("Helvetica", 18, "bold")
FONT_LABEL = ("Helvetica", 11)
FONT_BUTTON = ("Helvetica", 10, "bold")

def style_button(btn, bg=SECONDARY):
    btn.config(
        bg=bg,
        fg="white",
        activebackground=ACCENT,
        activeforeground="black",
        relief=FLAT,
        bd=0,
        padx=10,
        pady=5,
        font=FONT_BUTTON,
        cursor="hand2"
    )

# ---------------- MAIN APP AFTER LOGIN ----------------
def open_main_app():
    root = Tk()
    root.title("Secure File Storage & Integrity Verification System")
    root.geometry("860x600")
    root.config(bg=BG)

    selected_file_var = StringVar()

    # Header Section
    header = Frame(root, bg=PRIMARY, height=80)
    header.pack(fill=X)
    Label(header, text="🔐 Secure File Storage System", bg=PRIMARY, fg="white", font=("Helvetica", 20, "bold")).pack(pady=20)

    Label(root, text=f"Logged in as: {LOGGED_IN_USER}", bg=BG, fg=TEXT, font=("Helvetica", 10, "italic")).pack(pady=(5, 10))

    # --- Frame for Buttons & Actions ---
    frame = Frame(root, bg=BG)
    frame.pack(pady=10)

    def log(msg):
        txt.insert(END, msg + "\n")
        txt.see(END)

    # --- Button Functions ---
    def select_file():
        path = filedialog.askopenfilename()
        if path:
            selected_file_var.set(path)
            lbl_selected.config(text=path)
            log(f"Selected file: {path}")

    def encrypt_with_password():
        path = selected_file_var.get()
        if not path:
            messagebox.showwarning("Warning", "Select a file first.")
            return
        password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
        if not password:
            return
        original_hash = sha256_hash(path)
        key, salt = derive_key_from_password(password)
        encpath = encrypt_file(path, key)
        salt_b64 = base64.b64encode(salt).decode()
        add_metadata_entry(path, original_hash, encpath, salt_b64, LOGGED_IN_USER)
        messagebox.showinfo("Success", f"Encrypted: {encpath}")
        log(f"Encrypted file created: {encpath}")

    def decrypt_with_password():
        encpath = filedialog.askopenfilename(title="Select encrypted file", filetypes=[("Encrypted files","*.enc")])
        if not encpath:
            return
        password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
        if not password:
            return
        md = load_metadata()
        entry = None
        for e in md['files']:
            if os.path.basename(e['encrypted_path']) == os.path.basename(encpath):
                entry = e
                break
        salt = entry['salt'] if entry else None
        try:
            key, _ = derive_key_from_password(password, salt)
            decpath = decrypt_file(encpath, key)
        except Exception as e:
            messagebox.showerror("Error", "Wrong password or corrupted file.")
            log(f"Decryption failed: {e}")
            return
        post_hash = sha256_hash(decpath)
        if entry and post_hash == entry['original_hash']:
            messagebox.showinfo("Integrity", "✅ File integrity verified successfully!")
            log("Integrity verified.")
        else:
            messagebox.showwarning("Integrity", "⚠️ File integrity FAILED!")
            log("Integrity check failed.")

    def show_metadata():
        md = load_metadata()
        msg = ""
        for e in md['files']:
            msg += f"\nFile: {e['filename']}\nUser: {e['user']}\nHash: {e['original_hash'][:20]}...\nTime: {e['timestamp']}\n"
        if not msg:
            msg = "No metadata entries found."
        messagebox.showinfo("Metadata Summary", msg)

    def secure_delete_button():
        encpath = filedialog.askopenfilename(title='Select encrypted file', filetypes=[("Encrypted files","*.enc")])
        if not encpath:
            return
        if not messagebox.askyesno("Confirm", f"Securely delete {encpath}?"):
            return
        try:
            secure_delete(encpath, passes=3)
        except Exception as e:
            messagebox.showerror("Error", f"Secure delete failed: {e}")
            log(f"Secure delete failed: {e}")
            return
        idx, entry = find_entry_by_encpath(encpath)
        if entry:
            md = load_metadata()
            md['files'].pop(idx)
            from integrity import save_metadata
            save_metadata(md)
        messagebox.showinfo("Deleted", "🗑️ File securely deleted (best-effort).")
        log(f"Securely deleted: {encpath}")

    def change_password_button():
        encpath = filedialog.askopenfilename(title='Select encrypted file', filetypes=[("Encrypted files","*.enc")])
        if not encpath:
            return
        old_pw = simpledialog.askstring("Old Password", "Enter current encryption password:", show='*')
        if not old_pw:
            return
        new_pw = simpledialog.askstring("New Password", "Enter new password:", show='*')
        if not new_pw:
            return
        if old_pw == new_pw:
            messagebox.showinfo("Info", "Old and new password are the same.")
            return
        try:
            new_encpath, new_salt = reencrypt_file(encpath, old_pw, new_pw, derive_key_from_password, decrypt_file, encrypt_file)
        except Exception as e:
            messagebox.showerror("Error", f"Password change failed: {e}")
            log(f"Password change failed: {e}")
            return
        new_salt_b64 = base64.b64encode(new_salt).decode()
        ok = update_metadata_entry(encpath, new_encrypted_path=new_encpath, new_salt_b64=new_salt_b64)
        if not ok:
            add_metadata_entry(os.path.basename(new_encpath), sha256_hash(new_encpath[:-4]), new_encpath, new_salt_b64, LOGGED_IN_USER)
        try:
            if os.path.abspath(encpath) != os.path.abspath(new_encpath):
                os.remove(encpath)
        except Exception:
            pass
        messagebox.showinfo("Success", "🔑 Password changed and file re-encrypted successfully.")
        log("Password changed successfully.")

    # --- File Selection & Label ---
    Button(frame, text="Select File", command=select_file, width=18).grid(row=0, column=0, padx=10, pady=8)
    lbl_selected = Label(frame, text="No file selected", bg=BG, fg=TEXT, font=FONT_LABEL)
    lbl_selected.grid(row=0, column=1, padx=10, pady=8)

    # --- Buttons Section ---
    btn_encrypt = Button(frame, text="Encrypt", command=encrypt_with_password)
    btn_decrypt = Button(frame, text="Decrypt", command=decrypt_with_password)
    btn_meta = Button(frame, text="Show Metadata", command=show_metadata)
    btn_delete = Button(frame, text="Secure Delete (.enc)", command=secure_delete_button)
    btn_change = Button(frame, text="Change File Password", command=change_password_button)

    buttons = [btn_encrypt, btn_decrypt, btn_meta, btn_delete, btn_change]
    for i, b in enumerate(buttons, start=1):
        b.grid(row=i, column=0, columnspan=2, pady=6, ipadx=5)
        style_button(b)

    # --- Log Box ---
    Label(root, text="System Log:", bg=BG, fg=PRIMARY, font=("Helvetica", 12, "bold")).pack(pady=(20, 5))
    txt = scrolledtext.ScrolledText(root, width=95, height=12, bg="white", fg="black", font=("Consolas", 9))
    txt.pack(padx=10, pady=10)

    root.mainloop()

# ---------------- LOGIN WINDOW ----------------
def open_login():
    global LOGGED_IN_USER
    login_win = Tk()
    login_win.title("User Authentication - Secure File Storage")
    login_win.geometry("420x260")
    login_win.config(bg=BG)

    Label(login_win, text="🔐 Secure File Storage Login", font=("Helvetica", 16, "bold"), bg=BG, fg=PRIMARY).pack(pady=15)

    frame = Frame(login_win, bg=BG)
    frame.pack()

    Label(frame, text="Username:", font=FONT_LABEL, bg=BG).grid(row=0, column=0, padx=5, pady=5)
    entry_user = Entry(frame, font=FONT_LABEL)
    entry_user.grid(row=0, column=1, padx=5, pady=5)

    Label(frame, text="Password:", font=FONT_LABEL, bg=BG).grid(row=1, column=0, padx=5, pady=5)
    entry_pass = Entry(frame, font=FONT_LABEL, show='*')
    entry_pass.grid(row=1, column=1, padx=5, pady=5)

    def login():
        user = entry_user.get().strip()
        pw = entry_pass.get().strip()
        if authenticate_user(user, pw):
            messagebox.showinfo("Login Successful", f"Welcome {user}!")
            global LOGGED_IN_USER
            LOGGED_IN_USER = user
            login_win.destroy()
            open_main_app()
        else:
            messagebox.showerror("Access Denied", "Invalid username or password!")

    def register():
        user = entry_user.get().strip()
        pw = entry_pass.get().strip()
        ok, msg = register_user(user, pw)
        messagebox.showinfo("Info", msg)

    Button(login_win, text="Login", command=login, width=10).pack(pady=10)
    Button(login_win, text="Register", command=register, width=10).pack()

    login_win.mainloop()

open_login()
