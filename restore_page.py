import os
import csv
import shutil
import mimetypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

# Configuration 
QUARANTINE_FOLDER = "quarantine"
HISTORY_FILE = "database/scan_history/quarantine_history.csv"
os.makedirs("database/scan_history", exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# This ensures the history file always exists, even if it's empty.
if not os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "w", newline="") as f:
        # We are just creating an empty file so the program can always find it.
        pass 

# Main Page Function
def open_restore_page(previous_window):
    previous_window.withdraw()
    win = tk.Toplevel()
    win.title("Quarantine Manager")
    win.geometry("1000x700")
    win.configure(bg="#f0f2f5")
    win.minsize(800, 500)

    # Threat Type Tooltip Data
    threat_descriptions = {
        "Malware": "Software designed to disrupt, damage, or gain unauthorized access to a computer system.",
        "PUP": "Potentially Unwanted Program. Not overtly malicious, but may impact privacy or performance.",
        "Ransomware": "A type of malware that threatens to publish the victim's data or perpetually block access to it unless a ransom is paid.",
        "Spyware": "Software that enables a user to obtain covert information about another's computer activities by transmitting data covertly from their hard drive.",
        "Adware": "Software that generates revenue for its developer by automatically generating online advertisements in the user interface of the software."
    }

    # WIDGET CREATION 
    tk.Label(win, text="🛡️ Quarantine Manager", font=("Segoe UI", 20, "bold"), bg="#f0f2f5").pack(pady=15)

    search_frame = tk.LabelFrame(win, text="Filter Results", font=("Segoe UI", 10), bg="#f0f2f5", padx=10, pady=5)
    search_frame.pack(fill="x", padx=15, pady=5)

    search_var = tk.StringVar()
    search_entry = ttk.Entry(search_frame, textvariable=search_var, width=50, font=("Segoe UI", 10))
    search_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

    # Dropdown filters 
    threat_filter_var = tk.StringVar(value="All Threats")
    threat_filter_cb = ttk.Combobox(search_frame, textvariable=threat_filter_var, state="readonly", width=15)
    threat_filter_cb.pack(side="left", padx=5)

    risk_filter_var = tk.StringVar(value="All Risks")
    risk_filter_cb = ttk.Combobox(search_frame, textvariable=risk_filter_var, state="readonly", width=15)
    risk_filter_cb.pack(side="left", padx=5)

    tree_frame = tk.Frame(win)
    tree_frame.pack(fill="both", expand=True, padx=15, pady=10)

    # File Size Column
    columns = ("Timestamp", "File Name", "File Size", "Threat Type", "Risk Level", "Original Path")
    tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
    scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    
    # Risk-level color-coded rows
    tree.tag_configure('high_risk', background='#ffdddd')
    tree.tag_configure('medium_risk', background='#fffadd')
    tree.tag_configure('low_risk', background='#e6ffe6')

    btn_frame = tk.LabelFrame(win, text="Actions", font=("Segoe UI", 10), bg="#f0f2f5", padx=10, pady=10)
    btn_frame.pack(fill="x", padx=15, pady=5)

    log_frame = tk.LabelFrame(win, text="Activity Log", font=("Segoe UI", 10), bg="#f0f2f5", padx=10, pady=5)
    log_frame.pack(fill="x", padx=15, pady=10)
    log_box = tk.Text(log_frame, height=4, bg="#ffffff", font=("Courier New", 9), relief="sunken", bd=1)
    log_box.pack(fill="x", expand=True, side="left", padx=(0, 5))
    log_box.config(state="disabled")

    bottom_frame = tk.Frame(win, bg="#f0f2f5")
    bottom_frame.pack(side="bottom", fill="x", padx=15, pady=10)

    file_map = {}
    auto_refresh_id = None

    # FUNCTION DEFINITIONS 

    def get_timestamp():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def log_action(message):
        log_box.config(state="normal")
        log_box.insert("end", f"[{get_timestamp()}] {message}\n")
        log_box.config(state="disabled")
        log_box.see("end")

    # Sort arrows on column headers 
    def sort_tree(tv, col, descending):
        # Reset all headers to remove old arrows
        for c in columns:
            tv.heading(c, text=c.replace("_", " "))
        
        # Sort data
        data = [(tv.set(k, col), k) for k in tv.get_children('')]
        # A simple numeric sort for file size
        if col == "File Size":
            # Extract numbers for sorting
            data.sort(reverse=descending, key=lambda t: float(str(t[0]).split(' ')[0]))
        else:
            data.sort(reverse=descending, key=lambda t: str(t[0]).lower())
        
        for idx, (_, k) in enumerate(data):
            tv.move(k, '', idx)

        # Add arrow to the current column header
        arrow = "▼" if descending else "▲"
        tv.heading(col, text=f"{col.replace('_', ' ')} {arrow}", command=lambda: sort_tree(tv, col, not descending))

    def load_quarantine_data():
        file_map.clear()
        if not os.path.exists(HISTORY_FILE):
            log_action("History file not found. Nothing to load.")
            return
        
        all_threats = set(["All Threats"])
        all_risks = set(["All Risks"])

        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for i, row in enumerate(reader):
                    if len(row) >= 6:
                        item_id = f"item_{i}"
                        file_map[item_id] = row
                        # Populate filter data 
                        all_threats.add(row[4]) # threat
                        all_risks.add(row[5]) # risk
                    elif row:
                        log_action(f"Warning: Skipping malformed row {i+1} in history file.")
            log_action("Quarantine history loaded successfully.")
        except Exception as e:
            messagebox.showerror("Load Error", f"An unexpected error occurred while reading the quarantine history file:\n{e}")
        
        threat_filter_cb['values'] = sorted(list(all_threats))
        risk_filter_cb['values'] = sorted(list(all_risks))

        filter_tree()

    # Helper function to format file size
    def format_file_size(size_bytes):
        if size_bytes == 0:
            return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB")
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"

    def filter_tree(*_):
        tree.delete(*tree.get_children())
        query = search_var.get().lower().strip()
        if query == placeholder_text.lower():
            query = ""
        
        # Get filter values 
        threat_filter = threat_filter_var.get()
        risk_filter = risk_filter_var.get()
        
        for item_id, row_data in file_map.items():
            timestamp, fname, qpath, opath, threat, risk = row_data[:6]
            
            # Apply filters
            if query not in str(row_data).lower():
                continue
            if threat_filter != "All Threats" and threat != threat_filter:
                continue
            if risk_filter != "All Risks" and risk != risk_filter:
                continue

            if os.path.exists(qpath):
                # Determine risk tag 
                risk_tag = ''
                if risk.lower() == 'high':
                    risk_tag = 'high_risk'
                elif risk.lower() == 'medium':
                    risk_tag = 'medium_risk'
                elif risk.lower() == 'low':
                    risk_tag = 'low_risk'
                
                # Get and format file size 
                try:
                    size = format_file_size(os.path.getsize(qpath))
                except FileNotFoundError:
                    size = "N/A"

                tree.insert("", "end", iid=item_id, values=(timestamp, fname, size, threat, risk, opath), tags=(risk_tag,))

    def restore_selected(custom=False):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select at least one file to restore.")
            return

        # Confirmation before restoring files 
        if not messagebox.askyesno("Confirm Restore", "Restoring files from quarantine could expose your system to security threats.\n\nAre you sure you want to proceed?"):
            log_action("Restore operation cancelled by user.")
            return

        items_to_restore = list(selected_items)
        for item_id in items_to_restore:
            if item_id in file_map:
                _, _, qpath, original_path, _, _ = file_map[item_id]
                filename = os.path.basename(original_path)
                if not os.path.exists(qpath):
                    messagebox.showwarning("File Missing", f"The file '{filename}' is no longer in quarantine.")
                    tree.delete(item_id)
                    continue
                restore_target_path = original_path
                if custom:
                    target_folder = filedialog.askdirectory(title=f"Select folder to restore '{filename}'")
                    if not target_folder:
                        log_action(f"Restore cancelled for {filename}.")
                        continue
                    restore_target_path = os.path.join(target_folder, filename)
                try:
                    os.makedirs(os.path.dirname(restore_target_path), exist_ok=True)
                    if os.path.exists(restore_target_path):
                        base, ext = os.path.splitext(restore_target_path)
                        restore_target_path = f"{base}_restored_{get_timestamp().replace(':', '-').replace(' ', '_')}{ext}"
                    shutil.move(qpath, restore_target_path)
                    log_action(f"Restored '{filename}' to '{restore_target_path}'.")
                    tree.delete(item_id)
                    del file_map[item_id]
                except Exception as e:
                    messagebox.showerror("Restore Error", f"Failed to restore '{filename}'.\n{e}")
        # After operation, refresh data in file_map from remaining tree items
        update_file_map_from_tree()


    def delete_selected():
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select at least one file to delete.")
            return
        if not messagebox.askyesno("Confirm Deletion", f"Permanently delete {len(selected_items)} file(s)? This cannot be undone."):
            return
        items_to_delete = list(selected_items)
        for item_id in items_to_delete:
            if item_id in file_map:
                _, filename, qpath, _, _, _ = file_map[item_id]
                try:
                    if os.path.exists(qpath):
                        os.remove(qpath)
                    tree.delete(item_id)
                    del file_map[item_id]
                    log_action(f"Deleted '{filename}' from quarantine.")
                except Exception as e:
                    messagebox.showerror("Delete Error", f"Failed to delete '{filename}'.\n{e}")
        # After operation, refresh data in file_map from remaining tree items
        update_file_map_from_tree()

    def update_file_map_from_tree():
        """Ensure file_map is in sync with the tree after deletions/restores."""
        current_ids = tree.get_children()
        # Create a new map with only the items still present in the tree
        new_file_map = {item_id: file_map[item_id] for item_id in current_ids if item_id in file_map}
        file_map.clear()
        file_map.update(new_file_map)


    def preview_selected():
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a file to preview.")
            return
        item_id = selected[0]
        if item_id in file_map:
            _, filename, qpath, _, _, _ = file_map[item_id]

            if not os.path.exists(qpath):
                messagebox.showerror("File Not Found", f"Cannot find '{filename}' in quarantine.")
                return

            ext = os.path.splitext(filename)[1].lower()
            mime_type, _ = mimetypes.guess_type(qpath)
            known_text_extensions = [".txt", ".log", ".csv", ".json", ".xml", ".html"]
            is_text_file = (mime_type and mime_type.startswith("text")) or (ext in known_text_extensions)

            preview = tk.Toplevel(win)
            preview.title(f"Preview: {filename}")
            preview.geometry("800x600")

            text_area = tk.Text(preview, wrap="none", font=("Courier New", 10))
            text_area.pack(fill="both", expand=True, padx=10, pady=(10, 0))

            content_to_display = ""
            try:
                if is_text_file:
                    with open(qpath, "r", encoding="utf-8", errors="ignore") as f:
                        content_to_display = f.read(10000)
                        text_area.insert("1.0", content_to_display if content_to_display.strip() else "[File is empty or unreadable]")
                else:
                    with open(qpath, "rb") as f:
                        raw = f.read(512)
                        hex_view = " ".join(f"{byte:02x}" for byte in raw)
                        content_to_display = f"[Binary File Preview - First 512 Bytes]\n{hex_view}"
                        text_area.insert("1.0", content_to_display)
            except Exception as e:
                content_to_display = f"[Error reading file: {e}]"
                text_area.insert("1.0", content_to_display)
            text_area.config(state="disabled")
            
            # --- FEATURE 4: Preview: Copy & Save As buttons ---
            preview_btn_frame = tk.Frame(preview)
            preview_btn_frame.pack(fill="x", padx=10, pady=5)
            
            def copy_content():
                preview.clipboard_clear()
                preview.clipboard_append(text_area.get("1.0", "end-1c"))
                messagebox.showinfo("Copied", "Content copied to clipboard.", parent=preview)

            def save_content():
                filepath = filedialog.asksaveasfilename(
                    initialfile=filename,
                    defaultextension=ext,
                    filetypes=[("All Files", "*.*")]
                )
                if filepath:
                    try:
                        with open(filepath, "w", encoding="utf-8") as f:
                            f.write(text_area.get("1.0", "end-1c"))
                        messagebox.showinfo("Saved", "Content saved successfully.", parent=preview)
                    except Exception as e:
                        messagebox.showerror("Save Error", f"Failed to save file: {e}", parent=preview)

            tk.Button(preview_btn_frame, text="Copy Content", command=copy_content).pack(side="left", padx=5)
            tk.Button(preview_btn_frame, text="Save As...", command=save_content).pack(side="left", padx=5)


    def export_to_csv():
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if path:
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([tree.heading(col)["text"].strip() for col in columns])
                    for item_id in tree.get_children():
                        writer.writerow(tree.item(item_id, "values"))
                log_action(f"Data exported to '{os.path.basename(path)}'.")
                messagebox.showinfo("Export Complete", "Quarantine data exported successfully.")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data.\n{e}")

    # Select All button 
    def select_all_items():
        all_items = tree.get_children()
        # If everything is already selected, deselect all. Otherwise, select all.
        if len(tree.selection()) == len(all_items):
             tree.selection_set([]) # Deselect all
        else:
            tree.selection_set(all_items) # Select all

    # Auto-refresh toggle
    auto_refresh_var = tk.BooleanVar()
    def schedule_refresh():
        nonlocal auto_refresh_id
        if auto_refresh_var.get():
            load_quarantine_data()
            auto_refresh_id = win.after(15000, schedule_refresh) # 15 seconds

    def toggle_auto_refresh():
        nonlocal auto_refresh_id
        if auto_refresh_var.get():
            log_action("Auto-refresh enabled (15s).")
            schedule_refresh()
        else:
            if auto_refresh_id:
                win.after_cancel(auto_refresh_id)
                auto_refresh_id = None
            log_action("Auto-refresh disabled.")
    
    # FEATURE 8: Export Activity Log button 
    def export_log():
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log files", "*.log"), ("Text files", "*.txt")])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(log_box.get("1.0", "end-1c"))
                log_action("Activity log exported.")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export log.\n{e}")

    # FEATURE 10: Threat Type tooltip functions 
    tooltip = None
    def show_tooltip(event):
        nonlocal tooltip
        hide_tooltip()
        
        region = tree.identify_region(event.x, event.y)
        if region != "cell":
            return
            
        col_id = tree.identify_column(event.x)
        item_id = tree.identify_row(event.y)
        
        # In this setup, column IDs are #1, #2, etc. We need the configured name.
        col_index = int(col_id.replace('#', '')) - 1
        col_name = columns[col_index]

        if col_name == "Threat Type" and item_id:
            threat_type = tree.item(item_id, "values")[3]
            description = threat_descriptions.get(threat_type, "No description available.")
            
            tooltip = tk.Toplevel(win)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root + 15}+{event.y_root + 10}")
            label = tk.Label(tooltip, text=description, justify="left",
                             background="#ffffe0", relief="solid", borderwidth=1,
                             wraplength=300, font=("Segoe UI", 9))
            label.pack(ipadx=1, ipady=1)

    def hide_tooltip(*_):
        nonlocal tooltip
        if tooltip:
            tooltip.destroy()
            tooltip = None

    #  WIDGET CONFIGURATION 
    placeholder_text = "Type here to search by any column..."
    search_entry.insert(0, placeholder_text)
    search_entry.config(foreground="grey")
    def on_focus_in(event):
        if search_entry.get() == placeholder_text:
            search_entry.delete(0, "end")
            search_entry.config(foreground="black")
    def on_focus_out(event):
        if not search_entry.get():
            search_entry.insert(0, placeholder_text)
            search_entry.config(foreground="grey")
    search_entry.bind("<FocusIn>", on_focus_in)
    search_entry.bind("<FocusOut>", on_focus_out)
    search_var.trace_add("write", filter_tree)
    threat_filter_cb.bind("<<ComboboxSelected>>", filter_tree)
    risk_filter_cb.bind("<<ComboboxSelected>>", filter_tree)

    for col in columns:
        tree.heading(col, text=col.replace("_", " "), command=lambda c=col: sort_tree(tree, c, False))
    tree.column("Timestamp", width=150, anchor="w")
    tree.column("File Name", width=200, anchor="w")
    tree.column("File Size", width=80, anchor="e")
    tree.column("Threat Type", width=150, anchor="w")
    tree.column("Risk Level", width=100, anchor="center")
    tree.column("Original Path", width=300, anchor="w")
    scrollbar.pack(side="right", fill="y")
    tree.pack(side="left", fill="both", expand=True)

    # BUTTONS 
    tk.Button(btn_frame, text="✅ Select All / None", bg="#6c757d", fg="white", font=("Segoe UI", 10), command=select_all_items).pack(side="left", padx=5)
    tk.Button(btn_frame, text="🔁 Restore to Original", bg="#28a745", fg="white", font=("Segoe UI", 10), command=restore_selected).pack(side="left", padx=5)
    tk.Button(btn_frame, text="📂 Restore to...", bg="#007bff", fg="white", font=("Segoe UI", 10), command=lambda: restore_selected(custom=True)).pack(side="left", padx=5)
    tk.Button(btn_frame, text="🗑️ Delete Permanently", bg="#dc3545", fg="white", font=("Segoe UI", 10), command=delete_selected).pack(side="left", padx=5)
    tk.Button(btn_frame, text="📑 Preview Contents", bg="#6c757d", fg="white", font=("Segoe UI", 10), command=preview_selected).pack(side="left", padx=5)
    
    # Right-aligned buttons
    tk.Button(btn_frame, text="📥 Export as CSV", bg="#17a2b8", fg="white", font=("Segoe UI", 10), command=export_to_csv).pack(side="right", padx=5)
    ttk.Checkbutton(btn_frame, text="Auto-Refresh", variable=auto_refresh_var, command=toggle_auto_refresh).pack(side="right", padx=5)
    tk.Button(btn_frame, text="🔄 Refresh List", bg="#ffc107", fg="black", font=("Segoe UI", 10), command=load_quarantine_data).pack(side="right", padx=5)
    
    tk.Button(log_frame, text="Export Log", font=("Segoe UI", 8), command=export_log).pack(side="right")
    tk.Button(bottom_frame, text="⬅ Back to Dashboard", bg="#343a40", fg="white", font=("Segoe UI", 10), command=lambda: [win.destroy(), previous_window.deiconify()]).pack()

    # BINDINGS AND FINAL SETUP 
    tree.bind("<Motion>", show_tooltip)
    tree.bind("<Leave>", hide_tooltip)
    
    load_quarantine_data()
    win.protocol("WM_DELETE_WINDOW", lambda: [win.destroy(), previous_window.deiconify()])

# Example of how to run this window (for testing purposes)
if __name__ == "__main__":
    # Create some dummy data for testing
    if not os.path.exists(HISTORY_FILE) or os.path.getsize(HISTORY_FILE) == 0:
        dummy_data = [
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'eicar.com', os.path.join(QUARANTINE_FOLDER, 'eicar.com'), '/home/user/downloads/eicar.com', 'Malware', 'High'),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'toolbar.exe', os.path.join(QUARANTINE_FOLDER, 'toolbar.exe'), 'C:\\Program Files\\toolbars\\toolbar.exe', 'PUP', 'Medium'),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'bad.js', os.path.join(QUARANTINE_FOLDER, 'bad.js'), 'C:\\temp\\bad.js', 'Spyware', 'High'),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'ads.dll', os.path.join(QUARANTINE_FOLDER, 'ads.dll'), 'C:\\Windows\\System32\\ads.dll', 'Adware', 'Low'),
        ]
        with open(HISTORY_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(dummy_data)
        
        # Create dummy files in quarantine
        for _, fname, qpath, _, _, _ in dummy_data:
            with open(qpath, "w") as f:
                f.write(f"This is a dummy quarantined file named {fname}")

    root = tk.Tk()
    root.title("Main Dashboard")
    root.geometry("400x300")
    tk.Label(root, text="This is the main application window.").pack(pady=20)
    tk.Button(root, text="Open Quarantine Manager", command=lambda: open_restore_page(root)).pack(pady=20)
    root.mainloop()