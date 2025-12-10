# core/password_utils.py
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>/?`~"

def is_strong_password(pw: str):
    """
    Return (True,'') if pw strong, else (False, reason).
    Rules:
      - at least 8 chars
      - at least one upper, one lower, one digit, one special
    """
    if len(pw) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in pw):
        return False, "Password must include at least one uppercase letter."
    if not any(c.islower() for c in pw):
        return False, "Password must include at least one lowercase letter."
    if not any(c.isdigit() for c in pw):
        return False, "Password must include at least one digit."
    if not any(c in SPECIAL_CHARS for c in pw):
        return False, "Password must include at least one special character."
    return True, ""
