import os
import sys
import threading
import hashlib
import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

MAGIC_HEADER = b'CRYPTEX1'
PLACEHOLDER_LOG = "System Operative"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(path, password, log_func):
    try:
        data = open(path, 'rb').read()
        signature = hashlib.sha512(data).digest()
        salt, iv = os.urandom(16), os.urandom(16)
        key = derive_key(password.encode(), salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        pad = 16 - (len(data) % 16)
        data += bytes([pad]) * pad
        ct = encryptor.update(data) + encryptor.finalize()

        xor_k = hashlib.sha256(password.encode()).digest()
        xor_ct = bytes(b ^ xor_k[i % len(xor_k)] for i, b in enumerate(ct))

        out = path + ".cryptexone"
        with open(out, 'wb') as f:
            f.write(MAGIC_HEADER + salt + iv + signature + xor_ct)

        log_func(f"✅ Encrypted: {out}")
    except Exception as e:
        log_func(f"❌ Encryption error: {e}")

def decrypt_file(path, password, log_func):
    try:
        with open(path, 'rb') as f:
            magic = f.read(8)
            if magic != MAGIC_HEADER:
                log_func("❌ Unrecognized format")
                return
            salt, iv = f.read(16), f.read(16)
            sig = f.read(64)
            xor_ct = f.read()

        key = derive_key(password.encode(), salt)
        xor_k = hashlib.sha256(password.encode()).digest()
        ct = bytes(b ^ xor_k[i % len(xor_k)] for i, b in enumerate(xor_ct))

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        dec = cipher.decryptor().update(ct) + cipher.decryptor().finalize()

        pad = dec[-1]
        data = dec[:-pad]

        if hashlib.sha512(data).digest() != sig:
            log_func("❌ Integrity check failed")
            return

        out = path.replace(".cryptexone", ".decrypted")
        with open(out, 'wb') as f:
            f.write(data)
        log_func(f"✅ Decrypted: {out}")
    except Exception as e:
        log_func(f"❌ Decryption error: {e}")

class CryptexGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CryptexOne - LuisDev_ (version 1.0.0)")
        self.geometry("650x600")
        self.resizable(False, False)

        # Icona finestra (se esiste images/icon.ico)
        try:
            if os.path.exists("images/icon.ico"):
                self.iconbitmap("images/icon.ico")
        except Exception:
            pass

        # Logo (facoltativo)
        if os.path.exists("images/banner.png"):
            img = Image.open("images/banner.png").resize((400, 120))
            self._logo = ctk.CTkImage(light_image=img, size=(400, 120))
            ctk.CTkLabel(self, text="", image=self._logo, fg_color="transparent").pack(pady=10)

        container = ctk.CTkFrame(self, corner_radius=10)
        container.pack(padx=20, pady=10, fill="both", expand=True)

        # Entry File
        self.file_entry = ctk.CTkEntry(container, placeholder_text="Browse file with button", corner_radius=10, width=400, height=40)
        self.file_entry.pack(anchor="w", padx=20, pady=(20, 10), ipady=5)
        try:
            widget = self.file_entry._entry
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind('<<Drop>>', self._on_drop)
        except Exception:
            pass

        # Icona cartella
        folder_img = Image.open("images/folder.png").resize((30, 30))
        self._folder_icon = ctk.CTkImage(light_image=folder_img, size=(30, 30))

        browse_btn = ctk.CTkButton(container, text="Browse", image=self._folder_icon, command=self._browse, width=160, height=50)
        browse_btn.place(relx=0.7, rely=0.045)

        self.pw_entry = ctk.CTkEntry(container, placeholder_text="Enter password", show="*", corner_radius=10, width=600, height=40)
        self.pw_entry.pack(anchor="w", padx=20, pady=(0, 20), ipady=5)

        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(0, 10))

        # Bottoni
        enc_img = Image.open("images/enc.png").resize((30, 30))
        dec_img = Image.open("images/dec.png").resize((30, 30))
        self._enc_icon = ctk.CTkImage(light_image=enc_img, size=(30, 30))
        self._dec_icon = ctk.CTkImage(light_image=dec_img, size=(30, 30))

        btn_font = ("Segoe UI", 16, "bold")
        ctk.CTkButton(btn_frame, text="Encrypt", image=self._enc_icon, compound="left",
                      command=self._start_encrypt, corner_radius=10,
                      font=btn_font, width=200, height=60, fg_color="#4caf50").pack(side="left", expand=True, padx=10)
        ctk.CTkButton(btn_frame, text="Decrypt", image=self._dec_icon, compound="left",
                      command=self._decrypt, corner_radius=10,
                      font=btn_font, width=200, height=60, fg_color="#f44336").pack(side="left", expand=True, padx=10)

        self.progress = ctk.CTkProgressBar(container, width=540)

        self.log_box = ctk.CTkTextbox(container, corner_radius=10, height=150)
        self.log_box.pack(fill="both", padx=20, pady=(10, 20), expand=True)
        self.log_box.configure(state="normal")
        self.log_box.insert("0.0", PLACEHOLDER_LOG)
        self.log_box.configure(state="disabled")
        self.log_box.bind("<FocusIn>", self._clear_placeholder)
        self.log_box.bind("<FocusOut>", self._add_placeholder_if_empty)

        # Copyright
        ctk.CTkLabel(self, text="© 2025 CryptexOne - LuisDev_.",
                     font=("Segoe UI", 10), fg_color="transparent").pack(side="bottom", pady=5)

    def _clear_placeholder(self, _):
        self.log_box.configure(state="normal")
        if self.log_box.get("0.0", "end").strip() == PLACEHOLDER_LOG:
            self.log_box.delete("0.0", "end")

    def _add_placeholder_if_empty(self, _):
        if not self.log_box.get("0.0", "end").strip():
            self.log_box.insert("0.0", PLACEHOLDER_LOG)
            self.log_box.configure(state="disabled")

    def _log(self, msg: str):
        self.log_box.configure(state="normal")
        if self.log_box.get("0.0", "end").strip() == PLACEHOLDER_LOG:
            self.log_box.delete("0.0", "end")
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _on_drop(self, event):
        path = event.data.strip('{}')
        self.file_entry.delete(0, "end")
        self.file_entry.insert(0, path)
        self._log(f"⮕ Selected: {path}")

    def _browse(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)
            self._log(f"⮕ Selected: {path}")

    def _start_encrypt(self):
        f, pw = self.file_entry.get(), self.pw_entry.get()
        if not os.path.isfile(f):
            messagebox.showerror("Error", "Invalid file")
            return
        if not pw:
            messagebox.showerror("Error", "Empty password")
            return

        for child in self.children.values():
            if isinstance(child, ctk.CTkFrame):
                for b in child.winfo_children():
                    if isinstance(b, ctk.CTkButton):
                        b.configure(state="disabled")

        self.progress.set(0)
        self.progress.pack(pady=(0, 10))

        self._encrypt_thread = threading.Thread(target=self._encrypt_worker, args=(f, pw), daemon=True)
        self._encrypt_thread.start()
        self._update_progress()

    def _encrypt_worker(self, f, pw):
        encrypt_file(f, pw, self._log)

    def _update_progress(self):
        if self._encrypt_thread.is_alive():
            self.progress.set(min(self.progress.get() + 0.01, 0.95))
            self.after(50, self._update_progress)
        else:
            self.progress.set(1.0)
            self.after(500, self.progress.pack_forget)
            for child in self.children.values():
                if isinstance(child, ctk.CTkFrame):
                    for b in child.winfo_children():
                        if isinstance(b, ctk.CTkButton):
                            b.configure(state="normal")

    def _decrypt(self):
        f, pw = self.file_entry.get(), self.pw_entry.get()
        if not os.path.isfile(f):
            messagebox.showerror("Error", "Invalid file")
            return
        if not pw:
            messagebox.showerror("Error", "Empty password")
            return
        decrypt_file(f, pw, self._log)

if __name__ == "__main__":
    try:
        app = CryptexGUI()
        app.mainloop()
    except ImportError:
        print("Install dependencies: pip install customtkinter tkinterdnd2 pillow cryptography")
        input("Press ENTER to exit…")
        sys.exit(1)
