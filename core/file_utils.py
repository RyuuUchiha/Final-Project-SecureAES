from tkinter import filedialog, messagebox
from pathlib import Path

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
