from tkinter import filedialog, messagebox
from pathlib import Path
import os
import psutil

def add_files(file_list, parent):
    """Open file dialog and add new files to file_list, ignoring duplicates.
       Shows warning if user tries to add duplicates."""
    paths = filedialog.askopenfilenames(title="Select Files")
    if not paths:
        return
    for p in paths:
        abs_path = str(Path(p).resolve())
        if abs_path not in file_list:
            file_list.append(abs_path)
        else:
            messagebox.showwarning("Duplicate File", f"The file is already added:\n{abs_path}", parent=parent)

def remove_selected(file_list, listbox):
    sel = list(listbox.curselection())
    if not sel:
        return
    for i in reversed(sel):
        file_list.pop(i)

def clear_all(file_list):
    file_list.clear()

def update_listbox(file_list, listbox):
    listbox.delete(0, "end")
    for f in file_list:
        listbox.insert("end", f)

def select_output_folder():
    folder = filedialog.askdirectory(title="Select output folder for output files")
    if folder:
        return folder
    return None

def confirm_overwrite(file_path):
    if os.path.exists(file_path):
        return messagebox.askyesno("File Exists", f"The file {os.path.basename(file_path)} already exists. Overwrite?")
    return True

def secure_delete(path, passes=1):
    if not os.path.exists(path):
        return
    size = os.path.getsize(path)
    with open(path, "ba+", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
    os.remove(path)

def get_safe_max_file_size(ratio: float = 0.30) -> int:
    mem = psutil.virtual_memory()
    return int(mem.available * ratio)

def format_size(bytes_size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return "Huge"

def validate_file_size(path: str):
    max_size = get_safe_max_file_size()
    size = os.path.getsize(path)

    if size > max_size:
        raise ValueError(
            f"File too large.\n"
            f"Maximum safe size: {format_size(max_size)}\n"
            f"Selected file: {format_size(size)}"
        )