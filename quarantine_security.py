import os
import shutil
import time
import getpass
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox

QUARANTINE_FOLDER = os.path.abspath("quarantine")
MASTER_PASSWORD = "123"  # Change this!
AUTO_LOCK_DELAY = 120  # 2 minutes
auto_lock_timer = None

def quarantine_file_with_retry(original_path, dest_path, attempts=3, delay=2):
    """
    Attempt to move a file to the quarantine folder with retry if the file is in use.
    Returns True if successful, False if all attempts fail.
    """
    for attempt in range(attempts):
        try:
            shutil.move(original_path, dest_path)
            return True
        except PermissionError as e:
            if "being used by another process" in str(e):
                print(f"[Attempt {attempt+1}] File in use. Retrying in {delay} sec...")
                time.sleep(delay)
            else:
                raise
    return False

def lock_quarantine():
    """Re-lock quarantine folder."""
    if os.path.exists(QUARANTINE_FOLDER):
        os.system(f'icacls "{QUARANTINE_FOLDER}" /inheritance:r')
        os.system(f'icacls "{QUARANTINE_FOLDER}" /deny Everyone:(OI)(CI)F')
        print("[🔒] Quarantine folder locked.")

def unlock_quarantine_via_prompt():
    """Ask for password and unlock folder temporarily."""
    global auto_lock_timer
    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring("Unlock Quarantine", "Enter password to access quarantine:", show="*")
    if password == MASTER_PASSWORD:
        try:
            user = getpass.getuser()
            print(f"[DEBUG] Unlocking for user: {user}")
            os.system(f'icacls "{QUARANTINE_FOLDER}" /remove:d Everyone')
            os.system(f'icacls "{QUARANTINE_FOLDER}" /grant "{user}":(OI)(CI)F')
            messagebox.showinfo("Access Granted", f"Quarantine folder unlocked for user: {user}")
            
            # Start auto-lock timer
            if auto_lock_timer and auto_lock_timer.is_alive():
                auto_lock_timer.cancel()
            auto_lock_timer = threading.Timer(AUTO_LOCK_DELAY, lock_quarantine)
            auto_lock_timer.start()

            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock folder: {e}")
            return False
    else:
        messagebox.showerror("Access Denied", "Incorrect password.")
        return False

def manual_lock_prompt():
    """Button-triggered immediate lock."""
    if messagebox.askyesno("Lock Quarantine", "Do you want to immediately lock the quarantine folder?"):
        lock_quarantine()
        messagebox.showinfo("Locked", "Quarantine folder has been locked.")

def ensure_locked_on_startup():
    """Run this once when app starts to lock folder."""
    lock_quarantine()
