"""
gui.py
Tkinter GUI for a user-friendly AES-256-GCM file encrypt/decrypt tool.
Run: python gui.py
"""

import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
from aes_tool import encrypt_file, decrypt_file

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Encryption Tool (AES-256-GCM)")
        self.geometry("560x300")
        self.resizable(False, False)

        # Mode: encrypt/decrypt
        self.mode = tk.StringVar(value="encrypt")

        # Widgets
        tk.Label(self, text="Mode:").grid(row=0, column=0, sticky="w", padx=10, pady=(12, 4))
        tk.Radiobutton(self, text="Encrypt", variable=self.mode, value="encrypt",
                       command=self._toggle_confirm).grid(row=0, column=1, sticky="w")
        tk.Radiobutton(self, text="Decrypt", variable=self.mode, value="decrypt",
                       command=self._toggle_confirm).grid(row=0, column=2, sticky="w")

        # File choose
        tk.Label(self, text="File:").grid(row=1, column=0, sticky="w", padx=10, pady=6)
        self.file_var = tk.StringVar()
        tk.Entry(self, textvariable=self.file_var, width=55).grid(row=1, column=1, columnspan=2, sticky="w")
        tk.Button(self, text="Browse...", command=self._browse).grid(row=1, column=3, padx=10)

        # Output (optional)
        tk.Label(self, text="Output (optional):").grid(row=2, column=0, sticky="w", padx=10, pady=6)
        self.out_var = tk.StringVar()
        tk.Entry(self, textvariable=self.out_var, width=55).grid(row=2, column=1, columnspan=2, sticky="w")

        # Passwords
        tk.Label(self, text="Password:").grid(row=3, column=0, sticky="w", padx=10, pady=6)
        self.pw_var = tk.StringVar()
        tk.Entry(self, textvariable=self.pw_var, show="*", width=30).grid(row=3, column=1, sticky="w")

        tk.Label(self, text="Confirm:").grid(row=4, column=0, sticky="w", padx=10, pady=6)
        self.pw2_var = tk.StringVar()
        self.pw2_entry = tk.Entry(self, textvariable=self.pw2_var, show="*", width=30)
        self.pw2_entry.grid(row=4, column=1, sticky="w")

        # Run button and status
        tk.Button(self, text="Run", command=self._run_clicked, width=10).grid(row=5, column=1, pady=18, sticky="w")
        self.status = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self.status, fg="gray").grid(row=6, column=0, columnspan=4, padx=10, sticky="w")

        self.columnconfigure(1, weight=1)
        self._toggle_confirm()

    def _toggle_confirm(self):
        # Confirm field only needed for encryption
        if self.mode.get() == "encrypt":
            self.pw2_entry.configure(state="normal")
        else:
            self.pw2_entry.configure(state="disabled")

    def _browse(self):
        if self.mode.get() == "encrypt":
            path = filedialog.askopenfilename(title="Select file to encrypt")
        else:
            path = filedialog.askopenfilename(title="Select file to decrypt", filetypes=[("Encrypted", "*.enc"), ("All", "*.*")])
        if path:
            self.file_var.set(path)

    def _run_clicked(self):
        path = self.file_var.get().strip()
        if not path:
            messagebox.showwarning("Missing file", "Please choose a file.")
            return

        out = self.out_var.get().strip() or None
        pw = self.pw_var.get()

        if self.mode.get() == "encrypt":
            if pw != self.pw2_var.get():
                messagebox.showwarning("Password mismatch", "Password and Confirm do not match.")
                return
            worker = threading.Thread(target=self._do_encrypt, args=(path, pw, out), daemon=True)
        else:
            worker = threading.Thread(target=self._do_decrypt, args=(path, pw, out), daemon=True)

        self.status.set("Working...")
        worker.start()

    def _do_encrypt(self, path, pw, out):
        try:
            result = encrypt_file(path, pw, out)
            self.status.set(f"Encrypted -> {result}")
            messagebox.showinfo("Success", f"Encrypted to:\n{result}")
        except Exception as e:
            self.status.set("Error.")
            messagebox.showerror("Error", str(e))

    def _do_decrypt(self, path, pw, out):
        try:
            result = decrypt_file(path, pw, out)
            self.status.set(f"Decrypted -> {result}")
            messagebox.showinfo("Success", f"Decrypted to:\n{result}")
        except Exception as e:
            self.status.set("Error.")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    App().mainloop()
