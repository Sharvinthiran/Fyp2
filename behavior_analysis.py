import os
import time
import csv
import json
import math
import hashlib
import threading
import uuid
import collections
import getpass
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global variable to hold the communication queue
THREAT_QUEUE = None

try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    SCRIPT_DIR = os.getcwd()

# SETUP: CONFIGURATION, LOGGING, AND SESSION
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'config', 'monitor_config.json')
LOG_DIR = os.path.join(SCRIPT_DIR, 'database', 'monitor_history')
LOG_FILE_PATH = os.path.join(LOG_DIR, "monitor_history.csv")
SESSION_ID = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

os.makedirs(LOG_DIR, exist_ok=True)

def load_config():
    """Loads configuration from the JSON file."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"FATAL: '{CONFIG_FILE}' not found or invalid. The real-time monitor will not function correctly.")
        return {
            "score_thresholds": {"alert": 50, "critical_alert": 90, "max_score_cap": 250},
            "alert_cooldown_seconds": 30, "honeypot_filenames": [], "honeypot_processes": [], 
            "ransom_note_filenames": [], "encrypted_file_extensions": [], "high_risk_extensions": [],
            "time_window_seconds": 10, "whitelisted_hashes": [], "blacklisted_hashes": [], 
            "user_behavior_heuristics": {"enabled": False}, "detection_scores": {}, "suspicious_locations": []
        }

CONFIG = load_config()
UBH_CONFIG = CONFIG.get('user_behavior_heuristics', {})
SCORES = CONFIG.get('detection_scores', {})
SAFE_EXTENSIONS = ['.txt', '.log', '.csv', '.html', '.xml', '.json', '.md', '.png', '.jpg', '.jpeg', '.gif', '.pdf']

# GLOBAL TRACKERS 
honeypot_files = set()
WHITELISTED_HASHES = set(CONFIG.get('whitelisted_hashes', []))
BLACKLISTED_HASHES = set(CONFIG.get('blacklisted_hashes', []))
TIME_WINDOW = CONFIG.get('time_window_seconds', 10)
event_trackers = {'created': collections.deque(), 'modified': collections.deque(), 'deleted': collections.deque()}
mass_rename_tracker = collections.defaultdict(lambda: collections.defaultdict(collections.deque))
encrypted_extension_tracker = collections.deque()
alert_cooldown_tracker = {}
INITIALIZING_FILES = set()


# UTILITY FUNCTIONS 
def get_file_sha256(path):
    try:
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, FileNotFoundError): return None

def get_file_entropy(path):
    try:
        with open(path, 'rb') as f: data = f.read(1024 * 512)
        if not data: return 0
        counter, data_len = collections.Counter(data), len(data)
        return -sum((c / data_len) * math.log2(c / data_len) for c in counter.values())
    except Exception: return 0

def is_content_type_mismatched(file_path):
    try:
        if os.path.splitext(file_path)[1].lower() in ['.txt', '.log', '.csv', '.html']:
            with open(file_path, 'rb') as f:
                if b'\x00' in f.read(1024): return True
    except Exception: pass
    return False

def log_to_csv(threat_info):
    file_exists = os.path.isfile(LOG_FILE_PATH)
    try:
        with open(LOG_FILE_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Timestamp", "Event Type", "File/Source", "Threat Type", "Risk Level", "Session ID"])
            writer.writerow([
                threat_info['timestamp'], "REALTIME",
                threat_info.get('file', 'System'), ', '.join(threat_info['details']),
                threat_info['risk_level'], SESSION_ID
            ])
            f.flush(); os.fsync(f.fileno())
    except Exception as e: print(f"[ERROR] Could not write to log file {LOG_FILE_PATH}: {e}")

def push_threat_to_queue(threat_info):
    print(f">>> THREAT DETECTED ({threat_info['risk_level']}): {threat_info['details']} for file {threat_info.get('file', 'N/A')}")
    if THREAT_QUEUE: THREAT_QUEUE.put(threat_info)
    log_to_csv(threat_info)

# CORE BEHAVIORAL ANALYSIS
def evaluate_file_threat(file_path, event_type):
    score, details = 0, []
    filename = os.path.basename(file_path).lower()
    file_ext = os.path.splitext(filename)[1]
    norm_path = os.path.normpath(file_path).lower()

    file_hash = get_file_sha256(file_path)
    if file_hash:
        if file_hash in WHITELISTED_HASHES: return 0, []
        if file_hash in BLACKLISTED_HASHES:
            score += SCORES.get('blacklisted_file', 200); details.append("Blacklisted File (Known Threat)")

    if norm_path in honeypot_files:
        score += SCORES.get('honeypot_file', 100); details.append("Honeypot File Tampering")
    if filename in CONFIG.get('honeypot_processes', []):
        score += SCORES.get('honeypot_process', 150); details.append(f"Honeypot Process Triggered ({filename})")

    if os.path.exists(file_path):
        if is_content_type_mismatched(file_path):
            score += SCORES.get('content_mismatch', 30); details.append("File Content-Type Mismatch")
        
        parts = filename.split('.')
        if len(parts) > 2 and f".{parts[-2]}" in SAFE_EXTENSIONS and f".{parts[-1]}" in CONFIG.get('high_risk_extensions', []):
             score += SCORES.get('double_extension_threat', 75); details.append("Double Extension Threat")

        if event_type == 'created' and (filename.startswith('.') or filename in ['desktop.ini', 'autorun.inf']):
            score += SCORES.get('hidden_or_system_file', 25); details.append("Hidden/Suspicious File Created")
        
        if event_type == 'created' and any(filename.startswith(note) for note in CONFIG.get('ransom_note_filenames', [])):
            score += SCORES.get('ransom_note', 80); details.append("Ransom Note Created")

        if (event_type == 'renamed' or event_type == 'created') and file_ext in CONFIG.get('encrypted_file_extensions', []):
            score += SCORES.get('encrypted_ext_rename', 90); details.append("File Renamed/Created with Encrypted Extension")
            encrypted_extension_tracker.append(time.time())

        if event_type == 'created' and file_ext in CONFIG.get('high_risk_extensions', []):
            if any(loc in norm_path for loc in CONFIG.get('suspicious_locations', [])):
                score += SCORES.get('executable_in_suspicious_folder', 50); details.append(f"Executable in Suspicious Location")
            elif "program files" in norm_path:
                score += SCORES.get('high_risk_ext_in_prog_files', 80); details.append("High-Risk Executable in Program Files")
            else:
                score += SCORES.get('high_risk_ext', 60); details.append("High-Risk Executable Created")
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(2048)
                is_ransom_note_name = any(filename.startswith(note) for note in CONFIG.get('ransom_note_filenames', []))
                if b'bitcoin' in content or b'decrypt' in content or b'private key' in content:
                    details.append("Suspicious Content Found")
                    score += 70 if is_ransom_note_name else SCORES.get('suspicious_content', 35)
        except Exception:
            pass

        entropy = get_file_entropy(file_path)
        if entropy > 7.2:
            score += SCORES.get('high_entropy', 40); details.append(f"High Entropy ({entropy:.2f})")
    
    return score, details

def evaluate_mass_rename_threat(file_path):
    if not UBH_CONFIG.get('enabled', False): return 0, []
    rename_config = UBH_CONFIG.get('mass_rename_detection', {})
    if not rename_config: return 0, []
    now, dir_path, new_ext = time.time(), os.path.dirname(file_path), os.path.splitext(file_path)[1]
    if not new_ext or new_ext.lower() in ['.tmp', '.lnk', '.ini']: return 0, []
    timestamps = mass_rename_tracker[dir_path][new_ext]
    while timestamps and now - timestamps[0] > TIME_WINDOW: timestamps.popleft()
    timestamps.append(now)
    if len(timestamps) >= rename_config.get('count', 10):
        timestamps.clear()
        return rename_config.get('score', 80), [f"Mass File Renaming to '{new_ext}'"]
    return 0, []

def evaluate_user_behavior_threats(event_type):
    if not UBH_CONFIG.get('enabled', False): return 0, []
    score, details, now = 0, [], time.time()
    
    tracker = event_trackers.get(event_type)
    if tracker is not None:
        while tracker and now - tracker[0] > TIME_WINDOW: tracker.popleft()
        tracker.append(now)

        if event_type == 'created' and len(tracker) >= UBH_CONFIG.get('rapid_creation', {}).get('count', 999):
            score += UBH_CONFIG['rapid_creation']['score']; details.append("Rapid File Creation"); tracker.clear()
        elif event_type == 'modified' and len(tracker) >= UBH_CONFIG.get('rapid_modification', {}).get('count', 999):
            score += UBH_CONFIG['rapid_modification']['score']; details.append("Rapid File Modification"); tracker.clear()
        elif event_type == 'deleted' and len(tracker) >= UBH_CONFIG.get('rapid_deletion', {}).get('count', 999):
            score += UBH_CONFIG['rapid_deletion']['score']; details.append("Rapid File Deletion"); tracker.clear()

    enc_config = UBH_CONFIG.get('mass_encrypted_ext_creation', {})
    if enc_config:
        while encrypted_extension_tracker and now - encrypted_extension_tracker[0] > TIME_WINDOW:
            encrypted_extension_tracker.popleft()
        if len(encrypted_extension_tracker) >= enc_config.get('count', 10):
            score += enc_config.get('score', 70); details.append("Mass Encrypted File Creation")
            encrypted_extension_tracker.clear()
            
    return score, details

class BehaviorMonitor(FileSystemEventHandler):
    def process_event(self, event_path, event_type):
        filename = os.path.basename(event_path)
        if filename.startswith('~$') or filename.startswith('.~') or filename.lower().endswith(('.tmp', '.tmp.partial')):
            return

        norm_path = os.path.normpath(event_path).lower()
        if 'microsoft\\office' in norm_path and 'officefilecache' in norm_path:
            return

        if norm_path in INITIALIZING_FILES:
            try: INITIALIZING_FILES.remove(norm_path)
            except KeyError: pass
            return

        if not os.path.exists(event_path) and event_type not in ['deleted', 'renamed']: return

        file_score, file_details = evaluate_file_threat(event_path, event_type)
        user_score, user_details = evaluate_user_behavior_threats(event_type)
        rename_score, rename_details = (0, [])
        if event_type == 'renamed':
            rename_score, rename_details = evaluate_mass_rename_threat(event_path)
        
        backup_score, backup_details = 0, []
        if event_type == 'deleted' and os.path.splitext(event_path)[1].lower() in ['.bak', '.old']:
            backup_score = SCORES.get('backup_file_deletion', 60)
            backup_details = ["Backup File Deletion"]

        total_score = file_score + user_score + rename_score + backup_score
        all_details = sorted(list(set(file_details + user_details + rename_details + backup_details)))
        if not all_details: return
        
        now = time.time()
        cooldown_period = CONFIG.get('alert_cooldown_seconds', 30)
        dir_path = os.path.dirname(norm_path)
        file_ext = os.path.splitext(filename)[1]

        threat_signature = None
        mass_event_signatures = {
            "File Renamed/Created with Encrypted Extension": ("Mass Encryption Event", dir_path, file_ext),
            "Mass File Renaming": ("Mass Rename Event", dir_path, file_ext),
            "Rapid File Creation": ("Mass Creation Event", dir_path),
            "Rapid File Modification": ("Mass Modification Event", dir_path),
            "Rapid File Deletion": ("Mass Deletion Event", dir_path),
            "Mass Encrypted File Creation": ("Mass Encryption Event", dir_path)
        }
        
        for detail in all_details:
            if detail in mass_event_signatures:
                threat_signature = mass_event_signatures[detail]
                break
        
        if not threat_signature:
            threat_signature = (norm_path, tuple(all_details))

        if threat_signature in alert_cooldown_tracker and now - alert_cooldown_tracker[threat_signature] < cooldown_period:
            return
        
        max_score = CONFIG.get('score_thresholds', {}).get('max_score_cap', 250)
        total_score = min(total_score, max_score)

        score_thresholds = CONFIG.get('score_thresholds', {"alert": 50, "critical_alert": 90})
        if total_score < score_thresholds['alert']: return
        
        risk_level = "CRITICAL" if total_score >= score_thresholds['critical_alert'] else "High"
        
        threat_info = {
            'file': os.path.basename(event_path), 'full_path': event_path,
            'risk_level': risk_level, 'score': total_score, 'details': all_details,
            'session_id': SESSION_ID, 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        push_threat_to_queue(threat_info)
        alert_cooldown_tracker[threat_signature] = now
        
    def on_created(self, event):
        if not event.is_directory: self.process_event(event.src_path, 'created')
    def on_modified(self, event):
        if not event.is_directory: self.process_event(event.src_path, 'modified')
    def on_moved(self, event):
        if not event.is_directory: self.process_event(event.dest_path, 'renamed')
    def on_deleted(self, event):
        if not event.is_directory: self.process_event(event.src_path, 'deleted')

def check_irregular_login_time():
    if not UBH_CONFIG.get('enabled', False): return
    login_config = UBH_CONFIG.get('off_hours_login', {})
    hour = datetime.now().hour
    if hour >= login_config.get('start_hour', 23) or hour < login_config.get('end_hour', 6):
        threat_info = {
            'file': f'User: {getpass.getuser()}', 'risk_level': 'Low',
            'score': login_config.get('score', 25), 'details': [f"Off-Hours Login ({hour}:00)"],
            'session_id': SESSION_ID, 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        push_threat_to_queue(threat_info)

# STARTUP AND EXECUTION
def create_honeypot_files(dirs_to_watch):
    print("[STARTUP] Creating honeypot trap files...")
    for directory in dirs_to_watch:
        for filename in CONFIG.get('honeypot_filenames', []):
            try:
                path = os.path.join(directory, filename)
                with open(path, 'w') as f: f.write("This is a security trap file.")
                honeypot_files.add(os.path.normpath(path).lower())
            except Exception as e: print(f"  -> Warning: Could not create honeypot in {directory}: {e}")
        for filename in CONFIG.get('honeypot_processes', []):
             try:
                path = os.path.join(directory, filename)
                with open(path, 'w') as f: f.write("This is a security decoy process.")
             except Exception as e: print(f"  -> Warning: Could not create decoy process in {directory}: {e}")

def get_dirs_to_watch():
    base = os.path.expanduser("~")
    paths = [os.path.join(base, d) for d in ["Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music"]]
    paths.extend([os.path.join(base, "OneDrive", d) for d in ["Desktop", "Documents"]])
    paths.extend([os.environ.get("ProgramFiles", "C:\\Program Files"), 
                  os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")])
    appdata_base = os.environ.get('APPDATA')
    if appdata_base: paths.append(appdata_base)
    local_appdata_base = os.environ.get('LOCALAPPDATA')
    if local_appdata_base:
        paths.append(local_appdata_base)
        paths.append(os.path.join(local_appdata_base, 'Temp'))
        
    simulation_dir = os.path.abspath("simulation_lab")
    paths.append(simulation_dir)

    return list(dict.fromkeys([os.path.normpath(p) for p in paths if p and os.path.exists(p)]))

def start_monitor_in_background(queue):
    global THREAT_QUEUE
    THREAT_QUEUE = queue
    check_irregular_login_time()
    threading.Thread(target=start_file_system_monitor, daemon=True).start()
    print("[MONITOR] Real-time behavior monitor started in background.")

def start_file_system_monitor():
    dirs_to_monitor = get_dirs_to_watch()
    if not dirs_to_monitor: print("[ERROR] No user directories found to monitor."); return
    
    print("[STARTUP] Populating initial honeypot file list to prevent self-detection...")
    for directory in dirs_to_monitor:
        for filename in CONFIG.get('honeypot_filenames', []):
            INITIALIZING_FILES.add(os.path.normpath(os.path.join(directory, filename)).lower())
        for filename in CONFIG.get('honeypot_processes', []):
            INITIALIZING_FILES.add(os.path.normpath(os.path.join(directory, filename)).lower())

    create_honeypot_files(dirs_to_monitor)
    
    # Clear the initialization whitelist after startup creation is complete
    INITIALIZING_FILES.clear()
    print("[STARTUP] Initial file creation complete. Whitelist cleared. Monitoring is now live.")
    
    observer = Observer()
    event_handler = BehaviorMonitor()
    for folder in dirs_to_monitor:
        try:
            observer.schedule(event_handler, folder, recursive=True)
            print(f"[MONITORING] {folder}")
        except Exception as e: print(f"[ERROR] Could not monitor {folder}: {e}")
    observer.start()
    print("\n[REAL-TIME MONITORING ACTIVE] Watching for suspicious file behavior...")
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt: observer.stop()
    observer.join()