# gui/password_dialog.py
import tkinter as tk
from core.password_utils import is_strong_password
from gui.theme import NEON_BLUE
import customtkinter as ctk

def create_password_box(parent):
    """
    Returns: (tk.StringVar, tk.Entry)
    Creates a password entry box with a 'Show Password' checkbox.
    """
    pwd_var = tk.StringVar()

    # Password label
    ctk.CTkLabel(parent, text="Enter Password:", text_color=NEON_BLUE).pack(pady=(10,2), padx=20, anchor="w")

    # Password entry
    pwd_entry = ctk.CTkEntry(
        parent,
        placeholder_text="Type your password here",
        show="*",
        textvariable=pwd_var
    )
    pwd_entry.pack(pady=5, padx=20, fill="x")

    # Show password checkbox
    show_var = tk.BooleanVar(value=False)
    ctk.CTkCheckBox(parent, text="Show Password", variable=show_var,
                     command=lambda: pwd_entry.configure(show="" if show_var.get() else "*")).pack(padx=20, anchor="w")

    return pwd_var, pwd_entry

def validate_password(pwd_var, require_strong=True):
    """
    Returns (True, "") if ok, else (False, reason)
    """
    pwd = pwd_var.get()
    if not pwd:
        return False, "Password cannot be empty."
    if require_strong:
        ok, reason = is_strong_password(pwd)
        if not ok:
            return False, reason
    return True, ""
