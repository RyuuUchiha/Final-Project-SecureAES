# gui/password_dialog.py
import tkinter as tk
from tkinter import messagebox
from core.password_utils import is_strong_password

def ask_password(parent, action_label, require_strong_for_encrypt=True):
    """
    Modal password dialog.
    Returns password string (must be strong if required) or None if cancelled.
    """
    dlg = tk.Toplevel(parent)
    dlg.title("Enter password")
    dlg.configure(bg="#071018")
    dlg.resizable(False, False)
    dlg.grab_set()

    # center dialog
    dlg.update_idletasks()
    w, h = 520, 220
    sw = dlg.winfo_screenwidth(); sh = dlg.winfo_screenheight()
    x = (sw // 2) - (w // 2); y = (sh // 2) - (h // 2)
    dlg.geometry(f"{w}x{h}+{x}+{y}")

    tk.Label(dlg, text=f"Enter password to {action_label}", fg="#14FFEC", bg="#071018",
             font=("Segoe UI", 12, "bold")).pack(pady=(18,6))

    pwd_var = tk.StringVar()
    entry = tk.Entry(dlg, textvariable=pwd_var, show="*", width=36, font=("Segoe UI", 12),
                     bg="#0b1114", fg="#e6eef1", insertbackground="white")
    entry.pack(pady=(6,4))
    entry.focus_set()

    show_var = tk.BooleanVar(value=False)
    def toggle():
        entry.config(show="" if show_var.get() else "*")
    tk.Checkbutton(dlg, text="Show password", variable=show_var, command=toggle,
                   bg="#071018", fg="#9ab8b0", selectcolor="#071018").pack()

    err_label = tk.Label(dlg, text="", fg="#ff6b6b", bg="#071018", font=("Segoe UI", 10, "bold"))
    err_label.pack(pady=(6,4))

    result = {"pwd": None}

    def ok():
        p = pwd_var.get()
        if not p:
            err_label.config(text="Password cannot be empty.")
            return
        if require_strong_for_encrypt:
            ok_flag, reason = is_strong_password(p)
            if not ok_flag:
                # Force user to input again; do not allow weak password
                err_label.config(text=reason)
                return
        result["pwd"] = p
        dlg.destroy()

    def cancel():
        dlg.destroy()

    btn_frame = tk.Frame(dlg, bg="#071018")
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text="OK", width=14, bg="#00BFFF", fg="black", font=("Segoe UI", 10, "bold"),
              command=ok, relief="flat").grid(row=0, column=0, padx=8)
    tk.Button(btn_frame, text="Cancel", width=14, bg="#444444", fg="white", font=("Segoe UI", 10),
              command=cancel, relief="flat").grid(row=0, column=1, padx=8)

    parent.wait_window(dlg)
    return result["pwd"]
