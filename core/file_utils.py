# core/file_utils.py
from pathlib import Path
import os

def safe_remove(path: str):
    p = Path(path)
    if p.exists() and p.is_file():
        os.remove(p)
        return True
    return False
