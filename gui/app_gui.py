# gui/app_gui.py
import os
import threading
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
from PIL import Image

from core.aes_utils import encrypt_file, decrypt_file
from core.file_utils import *
from gui.password_dialog import *
from gui.theme import *

class SecureAESApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        try:
            self.iconbitmap("assets/secureaes.ico")
        except Exception as e:
            print("Icon load failed:", e)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.title("SecureAES — Cyber Neon GUI")
        self.geometry("1100x700")

        # File lists
        self.enc_files = []
        self.dec_files = []

        # Worker
        self._worker_thread = None
        self._stop_flag = False

        # Build UI
        self._build_ui()

    def _build_ui(self):
        # Logo
        try:
            logo_img = ctk.CTkImage(light_image=Image.open("assets/logo.png"), size=(90, 90))
            ctk.CTkLabel(self, image=logo_img, text="").pack(pady=(15,5))
        except Exception as e:
            print("Header logo load failed:", e)

        # Title
        ctk.CTkLabel(self, text="SecureAES", font=("Segoe UI",36,"bold"), text_color=NEON_BLUE).pack(pady=(5,5))
        ctk.CTkLabel(self, text="AES-256 Encryption/Decryption — Keep Your Files Safe", font=("Segoe UI",14)).pack(pady=(0,20))

        # Tabs
        self.tabs = ctk.CTkTabview(self, width=1050, height=580)
        self.tabs.pack(padx=20, pady=10)
        self.tabs.add("Encrypt")
        self.tabs.add("Decrypt")
        self._build_tab(self.tabs.tab("Encrypt"), "encrypt")
        self._build_tab(self.tabs.tab("Decrypt"), "decrypt")

    def _build_tab(self, parent, mode="encrypt"):
        files = self.enc_files if mode=="encrypt" else self.dec_files

        # Left frame (file list)
        left_frame = ctk.CTkFrame(parent)
        left_frame.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left_frame, text="Selected Files", font=("Segoe UI",14,"bold"), text_color=NEON_BLUE).grid(row=0, column=0, pady=(10,5), sticky="w")
        listbox = tk.Listbox(left_frame, selectmode="extended", bg="#0b1114", fg="white", selectbackground="#24303a", selectforeground="white", font=("Segoe UI",10))
        listbox.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        scrollbar = tk.Scrollbar(left_frame, orient="vertical", command=listbox.yview)
        scrollbar.grid(row=1, column=1, sticky="ns", pady=5)
        listbox.config(yscrollcommand=scrollbar.set)

        # Buttons
        btn_frame = ctk.CTkFrame(left_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5, padx=5, sticky="ew")
        btn_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(btn_frame, text="Add Files",command=lambda: (add_files(files, self), update_listbox(files, listbox))).grid(row=0, column=0, sticky="ew", pady=2)
        ctk.CTkButton(btn_frame, text="Remove Selected", command=lambda: (remove_selected(files, listbox), update_listbox(files, listbox))).grid(row=1, column=0, sticky="ew", pady=2)
        ctk.CTkButton(btn_frame, text="Clear All", command=lambda: (clear_all(files), update_listbox(files, listbox))).grid(row=2, column=0, sticky="ew", pady=2)

        # Right frame (options)
        right_frame = ctk.CTkFrame(parent, width=520, height=550)
        right_frame.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")
        right_frame.grid_propagate(False)
        ctk.CTkLabel(right_frame, text=f"{mode.capitalize()} Options", font=("Segoe UI",18,"bold"), text_color=NEON_BLUE).pack(pady=(10,5))

        # Password box (from password_dialog.py)
        pwd_var, pwd_entry = create_password_box(right_frame)

        del_var = ctk.BooleanVar(value=False)
        del_text = "Delete original files after encryption" if mode=="encrypt" else "Delete encrypted files after decryption"
        ctk.CTkCheckBox(right_frame, text=del_text, variable=del_var).pack(padx=20, anchor="w", pady=5)

        # Start button (ENCRYPT / DECRYPT)
        start_btn = ctk.CTkButton(
            right_frame, text=mode.capitalize(),
            fg_color=BTN_GREEN if mode=="encrypt" else BTN_RED,
            command=lambda: self._start_process(mode, files, pwd_var, del_var, progressbar, log_widget)
        )
        start_btn.pack(padx=20, pady=10, fill="x")

        # Progress bar and log
        progressbar = ctk.CTkProgressBar(right_frame, width=480)
        progressbar.pack(padx=20, pady=5, fill="x")

        log_widget = ctk.CTkTextbox(right_frame, width=480, height=350)
        log_widget.pack(padx=20, pady=10)
        log_widget.configure(state="disabled")


    # ---- worker ----
    def _start_process(self, mode, files, pwd_var, del_var, progressbar, log_widget):
        if not files:
            messagebox.showwarning("No files", "Please add files to process.")
            return
        ok, reason = validate_password(pwd_var, require_strong=(mode=="encrypt"))
        if not ok:
            messagebox.showerror("Weak password", reason)
            return

        self._stop_flag = False
        self._worker_thread = threading.Thread(
            target=self._worker_run, args=(mode, files.copy(), pwd_var.get(), del_var, progressbar, log_widget, pwd_var), daemon=True
        )
        self._worker_thread.start()

    def _worker_run(self, mode, files, password, del_var, progressbar, log_widget, pwd_var):
        success_list, failed_list = [], []
        total = len(files)
        output_folder = filedialog.askdirectory(title="Select output folder")
        if not output_folder:
            self._log(log_widget, "Operation cancelled: No output folder selected.")
            return
        for idx, fpath in enumerate(files, start=1):
            fname = Path(fpath).name
            try:
                # -------- ENCRYPT --------
                if mode == "encrypt":
                    out = os.path.join(output_folder, fname + ".enc")
                    encrypt_file(fpath, out, password)

                    # ✅ DELETE ORIGINAL AFTER ENCRYPT
                    if del_var.get() and os.path.exists(fpath):
                        os.remove(fpath)

                # -------- DECRYPT --------
                else:
                    base = fname[:-4] if fname.endswith(".enc") else fname
                    out = os.path.join(output_folder, base)
                    decrypt_file(fpath, out, password)

                    # ✅ DELETE .ENC AFTER DECRYPT
                    if del_var.get() and fpath.endswith(".enc") and os.path.exists(fpath):
                        os.remove(fpath)

                success_list.append((fname, out))
                self._log(log_widget, f"[{idx}/{total}] Success: {fname}")
            except Exception as e:
                failed_list.append((fname, str(e)))
                self._log(log_widget, f"[{idx}/{total}] Failed: {fname} ({e})")
            progressbar.set(idx/total)

        # Clear password box
        pwd_var.set("")

        # Summary popup
        msg = [f"Total files: {total}", f"Success: {len(success_list)}", f"Failed: {len(failed_list)}"]
        if success_list:
            msg.append("\nSuccessful outputs:")
            for n, o in success_list[:10]:
                msg.append(f" - {Path(o).name}")
            if len(success_list) > 10:
                msg.append(f" - ... and {len(success_list)-10} more")
        if failed_list:
            msg.append("\nFailed files:")
            for n, e in failed_list:
                msg.append(f" - {n}: {e}")
        messagebox.showinfo("Batch Operation Summary", "\n".join(msg))

    # ---- log ----
    def _log(self, log_widget, text):
        log_widget.configure(state="normal")
        log_widget.insert("end", text+"\n")
        log_widget.see("end")
        log_widget.configure(state="disabled")
    

