# gui/app_gui.py
import os
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from core.aes_utils import encrypt_file, decrypt_file
from core.password_utils import is_strong_password
from gui.theme import *

class SecureAESApp(ctk.CTk):
    def __init__(self):
        super().__init__()
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

    # ---------------------- UI ----------------------
    def _build_ui(self):
        title = ctk.CTkLabel(self, text="SecureAES", font=("Segoe UI", 36, "bold"), text_color=NEON_BLUE)
        title.pack(pady=(20,5))
        subtitle = ctk.CTkLabel(self, text="AES-256 Encryption/Decryption — Keep Your Files Safe", font=("Segoe UI",14))
        subtitle.pack(pady=(0,20))

        self.tabs = ctk.CTkTabview(self, width=1050, height=580)
        self.tabs.pack(padx=20, pady=10)
        self.tabs.add("Encrypt")
        self.tabs.add("Decrypt")

        self._build_tab(self.tabs.tab("Encrypt"), mode="encrypt")
        self._build_tab(self.tabs.tab("Decrypt"), mode="decrypt")

    def _build_tab(self, parent, mode="encrypt"):
        files = self.enc_files if mode=="encrypt" else self.dec_files

        # --- left frame ---
        left_frame = ctk.CTkFrame(parent)
        left_frame.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        lbl_files = ctk.CTkLabel(left_frame, text="Selected Files", font=("Segoe UI",14,"bold"), text_color=NEON_BLUE)
        lbl_files.grid(row=0, column=0, pady=(10,5), sticky="w")

        listbox = tk.Listbox(left_frame, selectmode="extended", bg="#0b1114", fg="white",
                             selectbackground="#24303a", selectforeground="white", font=("Segoe UI",10))
        listbox.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        scrollbar = tk.Scrollbar(left_frame, orient="vertical", command=listbox.yview)
        scrollbar.grid(row=1, column=1, sticky="ns", pady=5)
        listbox.config(yscrollcommand=scrollbar.set)

        # Buttons
        btn_frame = ctk.CTkFrame(left_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5, padx=5, sticky="ew")
        btn_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkButton(btn_frame, text="Add Files", command=lambda: self._add_files(files, listbox)).grid(row=0, column=0, sticky="ew", pady=2)
        ctk.CTkButton(btn_frame, text="Remove Selected", command=lambda: self._remove_selected(files, listbox)).grid(row=1, column=0, sticky="ew", pady=2)
        ctk.CTkButton(btn_frame, text="Clear All", command=lambda: self._clear_all(files, listbox)).grid(row=2, column=0, sticky="ew", pady=2)

        # Right frame
        right_frame = ctk.CTkFrame(parent, width=520, height=550)
        right_frame.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")
        right_frame.grid_propagate(False)

        ctk.CTkLabel(right_frame, text=f"{mode.capitalize()} Options", font=("Segoe UI",18,"bold"), text_color=NEON_BLUE).pack(pady=(10,5))

        pwd_var = tk.StringVar()
        pwd_entry = ctk.CTkEntry(right_frame, placeholder_text="Enter Password", show="*", textvariable=pwd_var)
        pwd_entry.pack(pady=5, padx=20, fill="x")

        show_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(right_frame, text="Show Password", variable=show_var,
                        command=lambda: pwd_entry.configure(show="" if show_var.get() else "*")).pack(padx=20, anchor="w")

        del_var = tk.BooleanVar(value=False)
        del_text = "Delete original files after encryption" if mode=="encrypt" else "Delete encrypted files after decryption"
        ctk.CTkCheckBox(right_frame, text=del_text, variable=del_var).pack(padx=20, anchor="w", pady=5)

        # **Start button comes BEFORE progressbar and log**
        start_btn = ctk.CTkButton(
            right_frame, text=mode.capitalize(),
            fg_color=BTN_GREEN if mode=="encrypt" else BTN_RED,
            command=lambda: self._start_process(mode, files, pwd_var, del_var, progressbar, log_widget)
        )
        start_btn.pack(padx=20, pady=10, fill="x")

        progressbar = ctk.CTkProgressBar(right_frame, width=480)
        progressbar.pack(padx=20, pady=5, fill="x")

        log_widget = ctk.CTkTextbox(right_frame, width=480, height=350)
        log_widget.pack(padx=20, pady=10)
        log_widget.configure(state="disabled")


    # ---- file ops ----
    def _add_files(self, files, listbox):
        paths = filedialog.askopenfilenames(title="Select Files")
        if not paths: return
        for p in paths:
            if p not in files: files.append(str(Path(p).resolve()))
        self._update_listbox(files, listbox)

    def _remove_selected(self, files, listbox):
        sel = list(listbox.curselection())
        if not sel: return
        for i in reversed(sel):
            files.pop(i)
        self._update_listbox(files, listbox)

    def _clear_all(self, files, listbox):
        files.clear()
        self._update_listbox(files, listbox)

    def _update_listbox(self, files, listbox):
        listbox.delete(0, "end")
        for f in files:
            listbox.insert("end", f)

    # ---- worker ----
    def _start_process(self, mode, files, pwd_var, del_var, progressbar, log_widget):
        pwd = pwd_var.get()
        if not files:
            messagebox.showwarning("No files", "Please add files to process.")
            return
        if mode=="encrypt":
            ok_flag, reason = is_strong_password(pwd)
            if not ok_flag:
                messagebox.showerror("Weak password", f"Cannot use weak password:\n{reason}")
                return
        self._stop_flag = False
        self._worker_thread = threading.Thread(
            target=self._worker_run, args=(mode, files.copy(), pwd, del_var, progressbar, log_widget), daemon=True
        )
        self._worker_thread.start()

    def _worker_run(self, mode, files, password, del_var, progressbar, log_widget):
        success_list, failed_list = [], []
        total = len(files)
        for idx, fpath in enumerate(files, start=1):
            fname = Path(fpath).name
            try:
                if mode=="encrypt":
                    out = fpath+".enc"
                    encrypt_file(fpath, out, password)
                    if del_var.get(): os.remove(fpath)
                else:
                    out = fpath[:-4] if fpath.endswith(".enc") else fpath+".dec"
                    decrypt_file(fpath, out, password)
                    if del_var.get() and fpath.endswith(".enc"): os.remove(fpath)
                success_list.append((fname, out))
                self._log(log_widget, f"[{idx}/{total}] Success: {fname}")
            except Exception as e:
                failed_list.append((fname, str(e)))
                self._log(log_widget, f"[{idx}/{total}] Failed: {fname} ({e})")
            progressbar.set(idx/total)

        # show summary popup
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
