import logging
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import shutil
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from scan_analysis import analyze_file_for_scan 
from quarantine_security import lock_quarantine, unlock_quarantine_via_prompt, manual_lock_prompt, quarantine_file_with_retry
import time
import csv
import threading

# Setup
logging.basicConfig(filename="scan_report.log", level=logging.INFO, format="%(asctime)s - %(message)s")

scan_results = []
quarantine_folder = "quarantine"
history_file = "database/scan_history/scan_history.csv"
quarantine_history_file = "database/scan_history/quarantine_history.csv"
os.makedirs("database/scan_history", exist_ok=True)
os.makedirs(quarantine_folder, exist_ok=True)
current_session_id = None

THREAT_INFO = {
    "Ransomware Note": ("A note usually dropped by ransomware...", "Do not pay. Disconnect device and investigate."),
    "Suspicious Executable": ("A potentially dangerous executable...", "Avoid executing and quarantine immediately."),
    "Encrypted Extension": ("File extensions often used to signify encrypted or locked files.", "Back up and scan."),
    "Binary/Encrypted Content": ("Contains binary or encrypted content.", "Further inspection required."),
    "Suspicious Content in File": ("Contains common ransom keywords...", "Verify source and quarantine if unknown."),
    "Rapid File Modifications": ("File modified many times quickly.", "Investigate the program."),
    "Frequent File Access": ("File accessed multiple times quickly.", "Monitor process behavior."),
    "Large File": ("The file is unusually large.", "Check for embedded content."),
    "No Threat": ("No known threat indicators found.", "No action needed.")
}

# Quarantine status
quarantine_locked = True  # Initially assume locked

def update_lock_status_ui():
    if quarantine_locked:
        lock_status_label.config(text="🔒 Quarantine is LOCKED", fg="red")
    else:
        lock_status_label.config(text="🔓 Quarantine is UNLOCKED", fg="green")

def log_scan(file_path, threat_type, risk_level, action, additional_info=""):
    logging.info(f"Scanned: {file_path}, Threat Type: {threat_type}, Risk Level: {risk_level}, Action: {action}, Info: {additional_info}")

def save_scan_result(file_path, file_name, threat_type, risk_level, timestamp):
    try:
        last_modified = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(file_path)))
    except Exception:
        last_modified = "Unavailable"

    scan_results.append({
        "file": file_name,
        "threat_type": threat_type,
        "risk_level": risk_level,
        "timestamp": timestamp,
        "last_modified": last_modified,
        "session_id": current_session_id
    })
    with open(history_file, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, file_name, threat_type, risk_level, current_session_id, last_modified])

def get_all_files(directory):
    file_list = []
    for root, _, files in os.walk(directory):
        for name in files:
            file_list.append(os.path.join(root, name))
    return file_list

def open_scan_page(previous_window, open_summary_page):
    previous_window.withdraw()
    scan_window = tk.Toplevel()
    scan_window.title("Ransomware Behavior Scan")
    scan_window.geometry("800x700")
    scan_window.configure(bg="#f9f9f9")

    # Data structures for file selection and results
    selected_files_to_scan = []
    file_selection_checked_states = {} # Tracks checked states for the file selection list
    checked_items = {} # This is for the results table below, remains unchanged

    tk.Label(scan_window, text="Scan for Ransomware Behavior", font=("Arial", 18, "bold"), bg="#f9f9f9").pack(pady=15)

    selection_frame = tk.LabelFrame(scan_window, text="File Selection", padx=10, pady=10, bg="#ffffff")
    selection_frame.pack(fill="x", padx=20, pady=10)

    # Function to update the new Treeview for file selection 
    def update_file_selection_treeview():
        # Clear existing entries
        for item in file_selection_treeview.get_children():
            file_selection_treeview.delete(item)
        # Repopulate with current files and their checked states
        for file_path in selected_files_to_scan:
            is_checked = file_selection_checked_states.get(file_path, False)
            checkbox_char = "☑" if is_checked else "☐"
            file_name = os.path.basename(file_path)
            file_selection_treeview.insert("", "end", iid=file_path, values=(checkbox_char, file_name))
        scan_window.update_idletasks()

    # Functions to handle file/folder selection 
    def select_file():
        files = filedialog.askopenfilenames()
        if files:
            for f in files:
                if f not in selected_files_to_scan:
                    selected_files_to_scan.append(f)
                    file_selection_checked_states[f] = False # Add to state tracker
            update_file_selection_treeview()

    def select_folder():
        folder = filedialog.askdirectory()
        if folder:
            files = get_all_files(folder)
            for f in files:
                if f not in selected_files_to_scan:
                    selected_files_to_scan.append(f)
                    file_selection_checked_states[f] = False # Add to state tracker
            update_file_selection_treeview()

    # Function to remove checked files from the selection list
    def remove_checked_files():
        # Using a list comprehension to create a new list of files to keep
        files_to_remove = [path for path, checked in file_selection_checked_states.items() if checked]
        
        if not files_to_remove:
            messagebox.showwarning("No Selection", "Please check one or more files to remove.")
            return

        # Filter out the files marked for removal
        nonlocal selected_files_to_scan
        selected_files_to_scan = [f for f in selected_files_to_scan if f not in files_to_remove]
        
        # Clean up the state dictionary
        for path in files_to_remove:
            del file_selection_checked_states[path]
            
        update_file_selection_treeview()

    # Function to clear the entire file selection list with confirmation
    def clear_file_list():
        if not selected_files_to_scan:
            return # Don't show a prompt if the list is already empty
            
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear all files from the list?"):
            selected_files_to_scan.clear()
            file_selection_checked_states.clear()
            update_file_selection_treeview()

    # Buttons for file selection now include Remove Checked and Clear List 
    tk.Button(selection_frame, text="📄 Select Files", command=select_file, width=18).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(selection_frame, text="📁 Select Folder", command=select_folder, width=18).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(selection_frame, text="❌ Remove Checked", command=remove_checked_files, width=18).grid(row=0, column=2, padx=5, pady=5)
    tk.Button(selection_frame, text="🗑️ Clear List", command=clear_file_list, width=18).grid(row=0, column=3, padx=5, pady=5)

    # Replaced Listbox with a Treeview for checkbox support
    listbox_frame = tk.Frame(scan_window, bg="#f9f9f9")
    listbox_frame.pack(padx=20, pady=5, fill="x")

    file_selection_treeview = ttk.Treeview(listbox_frame, columns=("Select", "File"), show="headings", height=5)
    file_selection_treeview.heading("Select", text="Select")
    file_selection_treeview.heading("File", text="File Name")
    file_selection_treeview.column("Select", width=50, anchor="center", stretch=False)
    file_selection_treeview.column("File", width=650)
    
    file_selection_treeview.pack(side="left", fill="x", expand=True)
    file_scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=file_selection_treeview.yview)
    file_selection_treeview.config(yscrollcommand=file_scrollbar.set)
    file_scrollbar.pack(side="right", fill="y")

    # Event handler to toggle checkboxes in the selection list ---
    def toggle_selection_checkbox(event):
        item_id = file_selection_treeview.identify_row(event.y)
        if not item_id:
            return

        # Toggle the checked state
        is_checked = not file_selection_checked_states[item_id]
        file_selection_checked_states[item_id] = is_checked

        # Update the visual representation in the treeview
        new_text = "☑" if is_checked else "☐"
        current_values = file_selection_treeview.item(item_id, 'values')
        file_selection_treeview.item(item_id, values=(new_text,) + current_values[1:])
    
    file_selection_treeview.bind("<Button-1>", toggle_selection_checkbox)

    control_frame = tk.Frame(scan_window, bg="#f9f9f9")
    control_frame.pack(pady=10)
    scan_button = tk.Button(control_frame, text="▶️ Start Scan", width=25, bg="#4CAF50", fg="white")
    scan_button.grid(row=0, column=0, padx=10)
    progress_bar = ttk.Progressbar(control_frame, length=400, mode="determinate")
    progress_bar.grid(row=0, column=1, padx=10)
    scan_status_label = tk.Label(scan_window, text="Scan not started", font=("Arial", 10), bg="#f9f9f9")
    scan_status_label.pack(pady=5)

    threat_results_label = tk.Label(scan_window, text="Threat Analysis Results", font=("Arial", 14, "bold"), bg="#f9f9f9")
    threat_table_frame = tk.Frame(scan_window)
    
    columns = ("Select", "File", "Threat Type", "Risk Level")
    threat_table = ttk.Treeview(threat_table_frame, columns=columns, show="headings", height=8)
    
    threat_table.heading("Select", text="Select")
    threat_table.heading("File", text="File Name")
    threat_table.heading("Threat Type", text="Threat Type")
    threat_table.heading("Risk Level", text="Risk Level")
    
    threat_table.column("Select", width=50, anchor="center", stretch=False)
    threat_table.column("File", width=300); threat_table.column("Threat Type", width=210); threat_table.column("Risk Level", width=100)

    table_scrollbar = ttk.Scrollbar(threat_table_frame, orient="vertical", command=threat_table.yview)
    threat_table.configure(yscrollcommand=table_scrollbar.set)
    table_scrollbar.pack(side="right", fill="y")

    action_frame = tk.Frame(scan_window, bg="#f9f9f9")
    
    def toggle_select_all():
        is_checking_all = any(not is_checked for item_id in threat_table.get_children() for is_checked in [checked_items.get(item_id, False)])
        
        for item_id in threat_table.get_children():
            checked_items[item_id] = is_checking_all
            new_text = "☑" if is_checking_all else "☐"
            threat_table.item(item_id, values=(new_text,) + threat_table.item(item_id, 'values')[1:])

    select_all_button = tk.Button(action_frame, text="✅ Select All / None", command=toggle_select_all, width=20, bg="#6c757d", fg="white")
    quarantine_button = tk.Button(action_frame, text="🛡️ Quarantine", command=lambda: quarantine_files(), width=20, bg="#FFD700")
    delete_button = tk.Button(action_frame, text="🗑️ Delete", command=lambda: delete_files(), width=20, bg="#FF4C4C", fg="white")
    ignore_button = tk.Button(action_frame, text="➡️ Ignore", command=lambda: ignore_files(), width=20, bg="#e0e0e0")
    summary_button = tk.Button(action_frame, text="📊 Summary Page", command=lambda: open_summary_page(previous_window), width=20)

    def unlock_now_and_update():
        global quarantine_locked
        if unlock_quarantine_via_prompt():
            quarantine_locked = False
            update_lock_status_ui()

    def lock_now_and_update():
        global quarantine_locked
        manual_lock_prompt()
        quarantine_locked = True
        update_lock_status_ui()

    unlock_button = tk.Button(action_frame, text="🔓 Unlock Quarantine", command=unlock_now_and_update, width=20, bg="#007BFF", fg="white")
    unlock_button.grid(row=2, column=1, padx=5, pady=5)

    lock_button = tk.Button(action_frame, text="🔒 Lock Now", command=lock_now_and_update, width=20, bg="#343a40", fg="white")
    lock_button.grid(row=2, column=2, padx=5, pady=5)
    
    select_all_button.grid(row=0, column=0, padx=5, pady=5)
    quarantine_button.grid(row=0, column=1, padx=5, pady=5)
    delete_button.grid(row=0, column=2, padx=5, pady=5)
    ignore_button.grid(row=1, column=0, padx=5, pady=5)
    summary_button.grid(row=1, column=1, columnspan=2, pady=5, padx=5, sticky="ew")

    def start_scan():
        global current_session_id
        files_to_process = [p for p in selected_files_to_scan if p not in checked_items]

        if not files_to_process:
            messagebox.showwarning("No New Files", "No new files have been added to the list to scan.")
            return

        if not current_session_id:
            current_session_id = time.strftime("%Y-%m-%d_%H-%M-%S")
            
        scan_button.config(state=tk.DISABLED)
        progress_bar["value"] = 0
        scan_status_label.config(text="Scanning...")
        scan_window.update_idletasks()
        
        show_results(files_to_process)

    def show_results(files_to_process):
        if not threat_results_label.winfo_ismapped():
            threat_results_label.pack(pady=10)
            threat_table_frame.pack(pady=5)
            threat_table.pack()
            tk.Label(scan_window, text="💡 Click a row to check/uncheck it. Double-click for details.", font=("Arial", 9, "italic"), fg="gray", bg="#f9f9f9").pack()
            action_frame.pack(pady=15)
            global lock_status_label
            lock_status_label = tk.Label(scan_window, text="", font=("Arial", 10, "bold"), bg="#f9f9f9")
            lock_status_label.pack(pady=2)
            update_lock_status_ui()


        for i, file_path in enumerate(files_to_process):
            result = analyze_file_for_scan(file_path)
            if result:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                values = ("☐", os.path.basename(file_path), result["threat_type"], result["risk_level"])
                threat_table.insert("", "end", iid=file_path, values=values)
                checked_items[file_path] = False 
                
                log_scan(file_path, result["threat_type"], result["risk_level"], "Scanned")
                save_scan_result(file_path, os.path.basename(file_path), result["threat_type"], result["risk_level"], timestamp)
            
            progress_bar["value"] = ((i + 1) / len(files_to_process)) * 100
            scan_status_label.config(text=f"Scanning: {os.path.basename(file_path)}")
            scan_window.update_idletasks()
        
        scan_status_label.config(text="Scan Complete")
        scan_button.config(text="🔄 Scan New Files", state=tk.NORMAL)
    
    def get_checked_paths():
        return [path for path, is_checked in checked_items.items() if is_checked]

    def quarantine_files():
        global quarantine_locked
        if not unlock_quarantine_via_prompt():
            messagebox.showwarning("Access Denied", "Cannot quarantine files without unlocking the folder.")
            return
        quarantine_locked = False
        update_lock_status_ui()

        selected_paths = get_checked_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please check one or more files to quarantine.")
            return

        quarantined_count = 0
        skipped_in_use = 0

        for original_path in selected_paths:
            if os.path.exists(original_path):
                try:
                    base_name = os.path.basename(original_path)
                    dest_path = os.path.join(quarantine_folder, base_name + ".quarantined")
                    counter = 1
                    while os.path.exists(dest_path):
                        name, ext = os.path.splitext(base_name)
                        dest_path = os.path.join(quarantine_folder, f"{name}_{counter}{ext}.quarantined")
                        counter += 1

                    success = quarantine_file_with_retry(original_path, dest_path)
                    if not success:
                        skipped_in_use += 1
                        continue

                    threat_row = threat_table.item(original_path, "values")
                    threat_type = threat_row[2] if len(threat_row) > 2 else "Unknown"
                    risk_level = threat_row[3] if len(threat_row) > 3 else "Unknown"
                    log_scan(original_path, threat_type, risk_level, "Quarantined")
                    with open(quarantine_history_file, "a", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            time.strftime("%Y-%m-%d %H:%M:%S"), os.path.basename(dest_path),
                            dest_path, original_path, threat_type, risk_level
                        ])
                    threat_table.delete(original_path)
                    del checked_items[original_path]
                    quarantined_count += 1

                except PermissionError as e:
                    if "being used by another process" in str(e):
                        skipped_in_use += 1
                        continue
                    else:
                        messagebox.showerror("Permission Error", f"Access denied to {base_name}.\n\n{str(e)}")

                except Exception as e:
                    messagebox.showerror("Error", f"Failed to quarantine {base_name}.\n{str(e)}")
            else:
                messagebox.showwarning("File Not Found", f"The file {os.path.basename(original_path)} could not be found.")
                threat_table.delete(original_path)
                del checked_items[original_path]

        if quarantined_count > 0 or skipped_in_use > 0:
            msg = f"{quarantined_count} file(s) quarantined."
            if skipped_in_use > 0:
                msg += f"\n{skipped_in_use} file(s) were skipped because they are in use."
            messagebox.showinfo("Quarantine Status", msg)

    def delete_files():
        selected_paths = get_checked_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please check one or more files to delete.")
            return
        
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to permanently delete {len(selected_paths)} checked file(s)?"):
            deleted_count = 0
            for original_path in selected_paths:
                if os.path.exists(original_path):
                    try:
                        os.remove(original_path)
                        log_scan(original_path, "Deleted", "N/A", "Deleted")
                        threat_table.delete(original_path)
                        del checked_items[original_path]
                        deleted_count += 1
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to delete {os.path.basename(original_path)}.\n{str(e)}")
                else:
                    messagebox.showwarning("File Not Found", f"The file {os.path.basename(original_path)} could not be found.")
                    threat_table.delete(original_path)
                    del checked_items[original_path]
            
            if deleted_count > 0:
                messagebox.showinfo("Deletion Complete", f"{deleted_count} file(s) successfully deleted.")

    def ignore_files():
        selected_paths = get_checked_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please check one or more files to ignore.")
            return
        count = len(selected_paths)
        for path in selected_paths:
            threat_table.delete(path)
            del checked_items[path]
        scan_status_label.config(text=f"{count} file(s) ignored from this session.")

    def toggle_checkbox(event):
        item_id = threat_table.identify_row(event.y)
        if not item_id:
            return

        is_checked = not checked_items.get(item_id, False)
        checked_items[item_id] = is_checked

        new_text = "☑" if is_checked else "☐"
        current_values = threat_table.item(item_id, 'values')
        threat_table.item(item_id, values=(new_text,) + current_values[1:])
        
    def show_threat_info(event):
        item_id = threat_table.identify_row(event.y)
        if item_id:
            values = threat_table.item(item_id, "values")
            if values:
                threat_type = values[2]
                desc, rec = THREAT_INFO.get(threat_type, ("No info.", "No recommendation."))
                messagebox.showinfo(f"Threat Info: {threat_type}", f"Description:\n{desc}\n\nRecommended Action:\n{rec}")

    threat_table.bind("<Button-1>", toggle_checkbox)
    threat_table.bind("<Double-1>", show_threat_info)

    def confirm_back_to_dashboard():
        if not threat_table.get_children() or messagebox.askyesno("Confirm", "Return to dashboard? Unhandled scan results will be lost."):
            scan_window.destroy()
            previous_window.deiconify()

    bottom_frame = tk.Frame(scan_window, bg="#f9f9f9")
    bottom_frame.pack(side="bottom", pady=10)
    back_button = tk.Button(bottom_frame, text="⬅️ Back to Dashboard", width=25, bg="#d3d3d3", command=confirm_back_to_dashboard)
    back_button.pack()

    scan_button.config(command=start_scan)
    scan_window.protocol("WM_DELETE_WINDOW", confirm_back_to_dashboard)