import os
import json
import logging
import math
import hashlib
import collections
import pefile


# CONFIGURATION AND LOGGING 

CONFIG_DIR = 'config'
LOG_DIR = 'logs'
CONFIG_FILE = os.path.join(CONFIG_DIR, 'scan_config.json')
SKIPPED_LOG_FILE = os.path.join(LOG_DIR, 'scan_skipped.log')

# Create directories if they don't exist
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

def load_config():
    """Loads configuration from the JSON file."""
    defaults = {
        "known_hashes": [],
        "whitelist_paths": [],
        "blacklist_filenames": [],
        "blacklist_extensions": []
    }
    try:
        with open(CONFIG_FILE, 'r') as f:
            # Normalize paths in the config for consistent matching
            config_data = json.load(f)
            config_data["whitelist_paths"] = [os.path.normpath(p.lower()) for p in config_data.get("whitelist_paths", [])]
            # Use sets for faster lookups
            for key in ["known_hashes", "blacklist_filenames", "blacklist_extensions"]:
                config_data[key] = set(config_data.get(key, []))
            return config_data
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"WARNING: '{CONFIG_FILE}' not found or invalid. Using default empty configuration.")
        return {key: set(value) for key, value in defaults.items()}

# Load configuration once when the module is imported
CONFIG = load_config()

# Setup a dedicated logger for skipped files
skipped_log = logging.getLogger('skipped_files')
skipped_log.setLevel(logging.INFO)
handler = logging.FileHandler(SKIPPED_LOG_FILE)
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
if not skipped_log.handlers:
    skipped_log.addHandler(handler)

# Static definitions for scoring (could also be moved to config if desired) 
RANSOM_NOTE_FILENAMES = {
    'readme.txt', 'restore_my_files.txt', 'decrypt_my_files.txt',
    'how_to_decrypt.txt', 'recovery_instructions.html', 'ransome_note.txt',
    '!!recover-my-files!!.txt'
}
ENCRYPTED_EXTENSIONS = {
    '.crypt', '.locked', '.encrypted', '.kraken', '.darkside', '.conti',
    '.wannacry', '.ryuk', '.cerber', '.thor', '.locky', '.zepto', '.onion', '.aes'
}
RANSOM_KEYWORDS = [
    b"bitcoin", b"wallet", b"decrypt", b"encrypt", b"tor browser",
    b"your files", b"private key", b"payment", b"recover data", b"unique id"
]
SUSPICIOUS_PE_IMPORTS = {
    "CryptEncrypt": 50, "CryptGenKey": 40, "SetFileAttributesW": 20,
    "DeleteFileW": 30, "CreateProcess": 10, "URLDownloadToFileA": 25,
    "ShellExecuteA": 15, "WriteFile": 20, "RegSetValueExA": 15
}
SCORE_THRESHOLDS = {"Critical": 100, "High": 70, "Medium": 40, "Low": 10}

# HELPER FUNCTIONS 

def get_file_entropy(data):
    if not data: return 0
    return -sum((c / len(data)) * math.log2(c / len(data)) for c in collections.Counter(data).values())

def calculate_sha256(path):
    hasher = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (IOError, PermissionError):
        return None

def check_pe_file(file_path):
    if not pefile: return 0, []
    score, details = 0, []
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode(errors='ignore')
                        if func_name in SUSPICIOUS_PE_IMPORTS:
                            score += SUSPICIOUS_PE_IMPORTS[func_name]
                            details.append(f"Suspicious Import ({func_name})")
    except Exception: pass
    return score, details

# MAIN ANALYSIS FUNCTION 

def analyze_file_for_scan(file_path):
    """
    Analyzes a file, incorporating config-based whitelists, blacklists, and hash matching.
    ALWAYS returns a result dictionary for the GUI.
    """
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return None  # Instruct GUI to skip this item completely

    # 1. Whitelist Check 
    normalized_path = os.path.normpath(file_path.lower())
    for safe_path in CONFIG["whitelist_paths"]:
        if normalized_path.startswith(safe_path):
            skipped_log.info(f"Whitelisted: {file_path}")
            return None # Returning None will make the GUI skip showing it

    score = 0
    threat_details = []
    file_name = os.path.basename(file_path)
    file_ext = os.path.splitext(file_name)[1].lower()

    try:
        # 2. High-Confidence Checks (Hashes & Blacklists)
        file_hash = calculate_sha256(file_path)
        if file_hash and file_hash in CONFIG["known_hashes"]:
            score += 100
            threat_details.append("Known Ransomware Hash")

        if file_name.lower() in CONFIG["blacklist_filenames"]:
            score += 80
            threat_details.append("Blacklisted Filename")

        if file_ext in CONFIG["blacklist_extensions"]:
            score += 80
            threat_details.append("Blacklisted Extension")

        # 3. Heuristic Analysis (only if not already a critical threat) 
        if score < SCORE_THRESHOLDS["Critical"]:
            # Filename and generic extension checks
            if file_name.lower() in RANSOM_NOTE_FILENAMES: score += 70; threat_details.append("Ransomware Note")
            if file_ext in ENCRYPTED_EXTENSIONS: score += 60; threat_details.append("Encrypted Extension")

            # Content analysis
            with open(file_path, "rb") as f: content = f.read(1024 * 1024)
            if content:
                if any(k in content.lower() for k in RANSOM_KEYWORDS): score += 35; threat_details.append("Suspicious Content")
                if file_ext not in {".exe",".dll",".zip",".rar",".7z",".jpg",".png"} and get_file_entropy(content) > 7.2:
                    score += 50; threat_details.append("High Entropy Content")
            
            # Executable analysis
            if pefile and file_ext in {".exe", ".dll", ".scr", ".sys"}:
                pe_score, pe_details = check_pe_file(file_path)
                if pe_score > 0: score += pe_score; threat_details.extend(pe_details); threat_details.append("Suspicious Executable")

        # 4. Final Result Generation 
        if score == 0:
            return {
                "threat_type": "No Threat Detected",
                "risk_level": "Clean", # Using 'Clean' for clarity in the GUI
                "score": 0,
                "details": "File appears safe based on current rules."
            }

        # Determine risk level from score
        risk_level = "Low"
        for level, threshold in sorted(SCORE_THRESHOLDS.items(), key=lambda x: x[1], reverse=True):
            if score >= threshold:
                risk_level = level
                break

        # Determine a primary threat type for cleaner GUI display
        primary_threat = sorted(list(set(threat_details)))[0] # Default to the first finding
        priority_order = ["Known Ransomware Hash", "Blacklisted Filename", "Suspicious Executable", "Ransomware Note", "High Entropy Content"]
        for p in priority_order:
            if p in threat_details:
                primary_threat = p
                break
        
        return {
            "threat_type": primary_threat,
            "risk_level": risk_level,
            "score": score,
            "details": ", ".join(sorted(list(set(threat_details))))
        }

    except (IOError, PermissionError):
        # Can't access the file, return a specific error message
        return {
            "threat_type": "Access Error",
            "risk_level": "Info",
            "score": 0,
            "details": "Permission denied or file is locked."
        }
    except Exception as e:
        return {
            "threat_type": "Analysis Error",
            "risk_level": "Unknown",
            "score": 0,
            "details": str(e)
        }