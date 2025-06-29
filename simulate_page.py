import os
import random
import string
import time
import tkinter as tk
from tkinter import ttk, messagebox
import shutil

# This simulation lab will create files in the locations your monitor is watching.
# Ensure your real-time monitor is running before using this tool.

# --- CONFIGURATION ---
SIMULATION_DIR_NAME = "simulation_lab"
SIMULATION_DIR_PATH = os.path.abspath(SIMULATION_DIR_NAME)
HONEYPOT_FILENAME = "!AAA-Passwords-DO-NOT-MODIFY.txt"
HONEYPOT_PROCESS_NAME = "vssadmin.exe"
RANSOM_NOTE_PREFIXES = [
    "readme_to_decrypt", "how_to_get_your_files", "restore_my_files"
]

# --- HELPER FUNCTIONS ---
def random_string(length=8):
    """Generates a random alphanumeric string."""
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def update_status(status_label, message):
    """Updates the status bar and refreshes the UI."""
    status_label.config(text=f"Status: {message}")
    status_label.winfo_toplevel().update_idletasks()
    print(f"[SIMULATE] {message}")

# --- SIMULATION ACTIONS (RE-ENGINEERED FOR RELIABILITY) ---

def create_test_files(directory, count=15, ext=".txt", content="benign content"):
    os.makedirs(directory, exist_ok=True)
    paths = []
    for i in range(count):
        path = os.path.join(directory, f"test_file_{i}_{random_string(4)}{ext}")
        try:
            with open(path, "w") as f: f.write(content)
            paths.append(path)
        except Exception: pass
    return paths

def create_unique_ransom_note(status_label):
    """Creates a ransom note with a unique name to guarantee detection."""
    prefix = random.choice(RANSOM_NOTE_PREFIXES)
    filename = f"{prefix}_{random_string()}.txt"
    path = os.path.join(SIMULATION_DIR_PATH, filename)
    with open(path, "w") as f:
        f.write("All your files have been encrypted! Pay us bitcoin now.")
    update_status(status_label, f"Ransom note '{filename}' created.")

def create_high_entropy_and_encrypt(status_label):
    """Creates a high-entropy file and renames it to an encrypted extension."""
    path = os.path.join(SIMULATION_DIR_PATH, f"data_{random_string()}.bin")
    with open(path, "wb") as f:
        f.write(os.urandom(1024 * 256)) # 256KB of random data
    
    encrypted_path = os.path.splitext(path)[0] + ".crypt"
    
    # --- FIX: Add a retry loop to handle the race condition ---
    for i in range(3): # Try up to 3 times
        try:
            os.rename(path, encrypted_path)
            update_status(status_label, "High-entropy file encrypted.")
            return # Success, exit the function
        except PermissionError as e:
            if "being used by another process" in str(e) and i < 2:
                time.sleep(0.2) # Wait 200ms before retrying
            else:
                update_status(status_label, f"Error: Could not rename file. {e}")
                return # Give up after 3 tries

def trigger_honeypot_file(status_label):
    """Deletes and recreates the honeypot file to ensure event capture."""
    path = os.path.join(SIMULATION_DIR_PATH, HONEYPOT_FILENAME)
    try:
        if os.path.exists(path):
            os.remove(path)
            time.sleep(0.1) # Brief pause to ensure delete is processed
        with open(path, "w") as f:
            f.write("This is a security trap file. Tampered.")
        update_status(status_label, "Honeypot file triggered.")
    except Exception as e:
        update_status(status_label, f"Honeypot trigger failed: {e}")

def create_honeypot_process(status_label):
    """Creates the decoy honeypot process file."""
    path = os.path.join(SIMULATION_DIR_PATH, HONEYPOT_PROCESS_NAME)
    with open(path, "w") as f:
        f.write("This is a decoy process.")
    update_status(status_label, "Honeypot process file created.")

def create_double_extension_file(status_label):
    """Creates a file with a deceptive double extension."""
    path = os.path.join(SIMULATION_DIR_PATH, "important_document.pdf.exe")
    with open(path, "w") as f: f.write("This is a fake executable.")
    update_status(status_label, "Double extension file created.")

def create_exe_in_downloads(status_label):
    """Creates an executable in Downloads with suspicious content."""
    try:
        downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
        if not os.path.exists(downloads_path):
             update_status(status_label, "Downloads folder not found."); return
        
        path = os.path.join(downloads_path, f"installer_{random_string()}.exe")
        with open(path, "wb") as f: f.write(b"This is a fake exe. Decrypt with private key.")
        update_status(status_label, f"Suspicious EXE created in Downloads.")
    except Exception as e:
        update_status(status_label, f"Error creating EXE in Downloads: {e}")

def create_hidden_malicious_file(status_label):
    """Creates a hidden file with a high-risk batch script extension."""
    path = os.path.join(SIMULATION_DIR_PATH, f".config_{random_string()}.bat")
    with open(path, "w") as f: f.write("@echo off\n echo You have been pwned.")
    update_status(status_label, "Hidden malicious file created.")

def create_mass_encrypted_files(status_label):
    """Creates multiple files with encrypted extensions."""
    update_status(status_label, "Creating 15 files with '.locked' extension...")
    create_test_files(SIMULATION_DIR_PATH, 15, ".locked", "encrypted data")
    update_status(status_label, "Mass encrypted file simulation complete.")

def simulate_rapid_deletion_and_note(status_label):
    """Creates files, rapidly deletes them, then drops a ransom note."""
    update_status(status_label, "Creating 25 temporary files...")
    paths = create_test_files(SIMULATION_DIR_PATH, 25, ".tmp")
    update_status(status_label, "Simulating rapid deletion...")
    for path in paths:
        try: os.remove(path); time.sleep(0.05)
        except Exception: pass
    update_status(status_label, "Dropping ransom note to finalize attack...")
    create_unique_ransom_note(status_label)
    update_status(status_label, "Rapid deletion simulation complete.")

def simulate_mass_rename(status_label):
    """Creates .txt files, then rapidly renames them to a malicious extension."""
    update_status(status_label, "Creating 12 text files for renaming...")
    initial_files = create_test_files(SIMULATION_DIR_PATH, 12, ".txt")
    update_status(status_label, "Simulating mass rename to '.crypt'...")
    for old_path in initial_files:
        try:
            if os.path.exists(old_path):
                new_path = os.path.splitext(old_path)[0] + ".crypt"
                os.rename(old_path, new_path); time.sleep(0.05)
        except Exception: pass
    update_status(status_label, "Mass rename simulation complete.")

def create_mismatched_ransom_note(status_label):
    """Creates a .txt ransom note containing binary data."""
    prefix = random.choice(RANSOM_NOTE_PREFIXES)
    filename = f"{prefix}_{random_string()}.txt"
    path = os.path.join(SIMULATION_DIR_PATH, filename)
    with open(path, "wb") as f:
        f.write(b"Your files are gone! Send bitcoin... \x00\x01\x02\x03\x04\x05")
    update_status(status_label, "Mismatched (binary) ransom note created.")

def cleanup_lab(status_label):
    """Deletes the simulation directory and test files in other locations."""
    if messagebox.askyesno("Confirm Cleanup", "This will delete the 'simulation_lab' directory and any test files created in Downloads. Proceed?"):
        try:
            if os.path.exists(SIMULATION_DIR_PATH): shutil.rmtree(SIMULATION_DIR_PATH)
            downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
            if os.path.exists(downloads_path):
                for item in os.listdir(downloads_path):
                    if item.startswith("installer_") and item.endswith(".exe"):
                        os.remove(os.path.join(downloads_path, item))
        except Exception as e:
            messagebox.showerror("Error", f"Could not complete cleanup: {e}")
        os.makedirs(SIMULATION_DIR_PATH, exist_ok=True)
        update_status(status_label, "Cleanup complete. Lab is reset.")

# --- UI SETUP ---
def open_simulate_page(previous_window):
    previous_window.withdraw()
    win = tk.Toplevel()
    win.title("Ransomware Simulation Lab")
    
    main_frame = ttk.Frame(win, padding="10"); main_frame.grid(row=0, column=0, sticky="nsew")
    win.columnconfigure(0, weight=1); win.rowconfigure(0, weight=1)

    status_label = ttk.Label(main_frame, text="Status: Ready.", anchor="w", relief="sunken", padding="5")
    button_frame = ttk.LabelFrame(main_frame, text="Simulation Actions (Guaranteed Alerts)", padding="10")
    button_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
    
    buttons = [
        ("📝 Create Ransom Note", create_unique_ransom_note),
        ("🔐 Encrypt High-Entropy File", create_high_entropy_and_encrypt),
        ("⚠️ Trigger Honeypot File", trigger_honeypot_file),
        (" decoy vssadmin.exe", create_honeypot_process),
        ("📄.exe Create Double Extension", create_double_extension_file),
        ("💻 Create EXE in Downloads", create_exe_in_downloads),
        ("🤫 Create Hidden Malicious File", create_hidden_malicious_file),
        ("💥 Mass Encrypted Files", create_mass_encrypted_files),
        ("🔥 Rapid Deletion + Note", simulate_rapid_deletion_and_note),
        ("🔁 Mass File Rename", simulate_mass_rename),
        ("🚫 Mismatched Ransom Note", create_mismatched_ransom_note),
        ("🧹 Clean Up Simulation Lab", cleanup_lab)
    ]

    for i, (text, command) in enumerate(buttons):
        row, col = i % 6, i // 6 # 6 rows, 2 columns
        btn = ttk.Button(button_frame, text=text, command=lambda c=command: c(status_label))
        btn.grid(row=row, column=col, sticky="ew", padx=5, pady=5)
        button_frame.columnconfigure(col, weight=1)

    status_label.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))

    def back(): win.destroy(); previous_window.deiconify()
    back_button = ttk.Button(main_frame, text="⬅ Back to Dashboard", command=back)
    back_button.grid(row=2, column=0, columnspan=2, pady=10)

    os.makedirs(SIMULATION_DIR_PATH, exist_ok=True)
    update_status(status_label, "Simulation lab is ready.")
    win.protocol("WM_DELETE_WINDOW", back)