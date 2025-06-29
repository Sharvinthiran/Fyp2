# gui/realtime_summary_page.py

from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import os

try:
    GUI_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = os.path.dirname(GUI_DIR)
except NameError:
    BASE_DIR = os.getcwd()

monitor_file = os.path.join(BASE_DIR, "database", "monitor_history", "monitor_history.csv")
user_behavior_file = os.path.join(BASE_DIR, "database", "monitor_history", "user_behavior_log.csv")
os.makedirs(os.path.dirname(monitor_file), exist_ok=True)

def convert_session_id(session_id):
    """Converts a session ID string into a human-readable format, keeping the original ID."""
    try:
        if session_id.startswith("user_session_"):
            dt = datetime.fromtimestamp(int(session_id.replace("user_session_", "")))
            return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({session_id})"
        elif "_" in session_id:
            date_str, time_str, *_ = session_id.split("_")
            dt = datetime.strptime(date_str + time_str, "%Y%m%d%H%M%S")
            return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({session_id})"
    except:
        pass
    return session_id

def load_combined_logs_with_readable_sessions():
    logs, session_map = [], {}
    
    # Process monitor log file
    if os.path.exists(monitor_file):
        with open(monitor_file, 'r', encoding="utf-8", errors='ignore') as f:
            reader = csv.reader(f)
            try:
                next(reader, None) # Skip header
                for row in reader:
                    if len(row) >= 6:
                        session_id = row[5].strip()
                        if session_id and session_id not in session_map: session_map[session_id] = convert_session_id(session_id)
                        logs.append({"timestamp": row[0], "event_type": row[1], "file": row[2], "threat_type": row[3], "risk_level": row[4], "session_id": session_id})
            except (StopIteration, IndexError): pass

    # Process user behavior log file
    if os.path.exists(user_behavior_file):
        with open(user_behavior_file, 'r', encoding="utf-8", errors='ignore') as f:
            reader = csv.reader(f)
            try:
                next(reader, None)
                for row in reader:
                    if len(row) >= 5:
                        session_id = row[4].strip()
                        if session_id and session_id not in session_map: session_map[session_id] = convert_session_id(session_id)
                        logs.append({"timestamp": row[0], "event_type": "USER", "file": row[2], "threat_type": row[1], "risk_level": row[3], "session_id": session_id})
            except (StopIteration, IndexError): pass
            
    return logs, session_map

def open_realtime_summary_page(root=None):
    window = tk.Toplevel()
    window.title("Real-Time Monitoring Summary")
    window.geometry("950x730")
    window.configure(bg="#f7f7f7")

    def on_close(): window.destroy(); root.deiconify() if root else None

    all_logs, session_map = load_combined_logs_with_readable_sessions()
    session_ids = sorted(session_map.keys(), key=lambda s: session_map[s], reverse=True)

    search_frame = tk.Frame(window, bg="#f7f7f7"); search_frame.pack(pady=10)
    tk.Label(search_frame, text="Search Filename:", bg="#f7f7f7", font=("Arial", 10)).pack(side="left", padx=5)
    search_var = tk.StringVar(); search_entry = tk.Entry(search_frame, textvariable=search_var, width=40); search_entry.pack(side="left", padx=5)
    tk.Button(search_frame, text="Search", command=lambda: filter_logs(), bg="#4CAF50", fg="white", width=12).pack(side="left", padx=10)

    filter_frame = tk.Frame(window, bg="#f7f7f7"); filter_frame.pack(pady=5)
    risk_filter = {lbl: tk.BooleanVar(value=True) for lbl in ["CRITICAL", "High", "Medium", "Low"]}
    for i, (label, var) in enumerate(risk_filter.items()):
        cb = tk.Checkbutton(filter_frame, text=label, variable=var, bg="#f7f7f7", font=("Arial", 9), command=lambda: filter_logs()); cb.grid(row=0, column=i, padx=10)
    
    session_frame = tk.Frame(window, bg="#f7f7f7"); session_frame.pack(pady=5)
    tk.Label(session_frame, text="Select Session:", font=("Arial", 10, "bold"), bg="#f7f7f7").pack(side="left")
    session_var = tk.StringVar()
    session_dropdown = ttk.Combobox(session_frame, textvariable=session_var, values=[session_map.get(sid, sid) for sid in session_ids], state="readonly", width=50)
    session_dropdown.pack(side="left", padx=10)
    
    table_frame = tk.Frame(window); table_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)
    columns = ("Timestamp", "Event", "File", "Threat Type", "Risk Level")
    table = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
    for col in columns: table.heading(col, text=col)
    table.column("Timestamp", width=160, anchor='w'); table.column("Event", width=80, anchor='w'); table.column("File", width=250, anchor='w'); table.column("Threat Type", width=220, anchor='w'); table.column("Risk Level", width=100, anchor='center')
    table.tag_configure("critical_risk", background="#f8d7da"); table.tag_configure("high_risk", background="#ffcccc"); table.tag_configure("medium_risk", background="#fff3cd"); table.tag_configure("low_risk", background="#d4edda")
    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview); table.configure(yscrollcommand=scrollbar.set); scrollbar.pack(side="right", fill="y"); table.pack(fill=tk.BOTH, expand=True)

    def get_tag(level): return {"CRITICAL": "critical_risk", "High": "high_risk", "Medium": "medium_risk", "Low": "low_risk"}.get(level)
    def populate_table(logs_to_display):
        table.delete(*table.get_children())
        search_term = search_var.get().lower()
        for log in logs_to_display:
            if not risk_filter.get(log.get("risk_level", ""), tk.BooleanVar(value=False)).get(): continue
            if search_term and search_term not in log.get("file", "").lower(): continue
            table.insert("", "end", values=(log.get("timestamp"), log.get("event_type"), log.get("file"), log.get("threat_type"), log.get("risk_level")), tags=(get_tag(log.get("risk_level")),))
    def filter_logs():
        selected_label = session_var.get()
        selected_session_id = next((sid for sid, label in session_map.items() if label == selected_label), None)
        populate_table([log for log in all_logs if log["session_id"] == selected_session_id] if selected_session_id else [])
    def on_session_change(event): filter_logs()
    session_dropdown.bind("<<ComboboxSelected>>", on_session_change)
    if session_ids: session_var.set(session_map[session_ids[0]]); filter_logs()
    def refresh_logs(): window.destroy(); open_realtime_summary_page(root)

    def export_logs():
        selected_label = session_var.get()
        selected_session = next((sid for sid, label in session_map.items() if label == selected_label), None)
        if not selected_session: messagebox.showwarning("No Session", "Please select a session to export."); return
        export_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save Session Logs", initialfile=f"session_{selected_session}_export.csv")
        if not export_path: return
        try:
            with open(export_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Event Type", "File/Details", "Threat Type", "Risk Level", "Session ID"])
                for log in all_logs:
                    if log["session_id"] == selected_session:
                        writer.writerow([log["timestamp"], log["event_type"], log["file"], log["threat_type"], log["risk_level"], log["session_id"]])
            messagebox.showinfo("Success", f"Session logs exported to:\n{export_path}")
        except Exception as e: messagebox.showerror("Error", f"Could not export logs:\n{e}")

    def delete_session():
        selected_label = session_var.get()
        selected_session = next((sid for sid, label in session_map.items() if label == selected_label), None)
        if not selected_session: messagebox.showwarning("No Session", "Please select a session to delete."); return
        if not messagebox.askyesno("Confirm Delete", f"Delete all logs from session:\n{selected_label}?\nThis cannot be undone.", icon='warning'): return
        
        new_monitor = [log for log in all_logs if log["session_id"] != selected_session and log["event_type"] != "USER"]
        new_user = [log for log in all_logs if log["session_id"] != selected_session and log["event_type"] == "USER"]
        
        try:
            with open(monitor_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f); writer.writerow(["Timestamp", "Event Type", "File", "Threat Type", "Risk Level", "Session ID"])
                for log in new_monitor: writer.writerow([log["timestamp"], log["event_type"], log["file"], log["threat_type"], log["risk_level"], log["session_id"]])
            with open(user_behavior_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f); writer.writerow(["Timestamp", "Event", "Details", "Risk Level", "Session ID"])
                for log in new_user: writer.writerow([log["timestamp"], log["threat_type"], log["file"], log["risk_level"], log["session_id"]])
            messagebox.showinfo("Success", "Session deleted."); refresh_logs()
        except Exception as e: messagebox.showerror("Error", f"Could not delete session:\n{e}")

    button_frame = tk.Frame(window, bg="#f7f7f7"); button_frame.pack(pady=15)
    tk.Button(button_frame, text="Export Session to CSV", command=export_logs, width=20, bg="#4CAF50", fg="white").grid(row=0, column=0, padx=10)
    tk.Button(button_frame, text="Delete Session", command=delete_session, width=15, bg="#ff4d4d", fg="white").grid(row=0, column=1, padx=10)
    tk.Button(button_frame, text="Back to Dashboard", command=on_close, width=20, bg="#6c757d", fg="white").grid(row=0, column=2, padx=10)
    tk.Button(button_frame, text="🔄 Refresh", command=refresh_logs, width=15, bg="#007bff", fg="white").grid(row=0, column=3, padx=10)