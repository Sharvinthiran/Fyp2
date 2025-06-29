import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import csv

history_file = "database/scan_history/scan_history.csv"

def sort_by_column(treeview, col, descending):
    # This helper function for sorting remains the same.
    # We are getting the index from the column identifier (e.g., #1, #2)
    try:
        col_index = int(treeview.column(col, "id")) -1
    except ValueError:
        return # Cannot sort if column ID is not a number

    data = [(treeview.item(item)["values"], item) for item in treeview.get_children('')]
    
    # Check if data list is not empty and has the required column index
    if data and len(data[0][0]) > col_index:
        data.sort(key=lambda x: x[0][col_index], reverse=descending)
        for i, item in enumerate(data):
            treeview.move(item[1], '', i)
        
        # Update heading to show sort direction
        for c in treeview["columns"]:
            treeview.heading(c, text=c) # Reset all
        arrow = " ▼" if descending else " ▲"
        treeview.heading(col, text=col + arrow)
        
        # Update the command to reverse the sort order next time
        treeview.heading(col, command=lambda: sort_by_column(treeview, col, not descending))


def open_summary_page(root=None):
    summary_window = tk.Toplevel()
    summary_window.title("Scan Summary")
    summary_window.geometry("900x730")
    summary_window.configure(bg="#f7f7f7")

    def on_close():
        try:
            summary_window.destroy()
        finally:
            if isinstance(root, (tk.Tk, tk.Toplevel)) and root.winfo_exists():
                root.deiconify()

    summary_window.protocol("WM_DELETE_WINDOW", on_close)

    def load_data():
        if os.path.exists(history_file):
            with open(history_file, newline="", encoding="utf-8") as file:
                reader = csv.reader(file)
                # Skip header if it exists
                try:
                    next(reader)
                except StopIteration:
                    return [] # File is empty
                
                return [
                    {
                        "timestamp": row[0],
                        "file": row[1],
                        "threat_type": row[2],
                        "risk_level": row[3],
                        "session_id": row[4]
                    }
                    for row in reader if len(row) >= 5
                ]
        return []

    all_results = load_data()
    session_ids = sorted(list(set(result["session_id"] for result in all_results)), reverse=True)
    
    # --- DYNAMICALLY FIND ALL UNIQUE RISK LEVELS ---
    all_risk_levels = sorted(list(set(r['risk_level'] for r in all_results if r.get('risk_level'))))
    risk_filter = {level: tk.BooleanVar(value=True) for level in all_risk_levels}

    search_frame = tk.Frame(summary_window, bg="#f7f7f7")
    search_frame.pack(pady=10)

    tk.Label(search_frame, text="Search Filename:", bg="#f7f7f7", font=("Arial", 10)).pack(side="left", padx=5)
    search_var = tk.StringVar()
    search_entry = tk.Entry(search_frame, textvariable=search_var, width=40)
    search_entry.pack(side="left", padx=5)
    
    # This needs to be defined before it's used by the widgets below
    def filter_and_populate():
        selected_session = session_var.get()
        if not selected_session:
            return
        
        keyword = search_var.get().lower()
        summary_table.delete(*summary_table.get_children())
        
        for result in all_results:
            # Check if the result belongs to the selected session
            if result["session_id"] != selected_session:
                continue
            
            # Check if the risk level filter is checked (or if the risk level doesn't have a filter)
            risk_level = result.get("risk_level", "Unknown")
            if risk_level in risk_filter and not risk_filter[risk_level].get():
                continue
            
            # Check if the file name matches the search keyword
            if keyword not in result["file"].lower():
                continue
            
            # If all checks pass, insert the row
            tag = get_tag(risk_level)
            summary_table.insert("", "end", values=(
                result["timestamp"],
                result["file"],
                result["threat_type"],
                risk_level
            ), tags=(tag,))

    tk.Button(search_frame, text="Search", command=filter_and_populate, bg="#4CAF50", fg="white", width=12).pack(side="left", padx=10)

    filter_frame = tk.Frame(summary_window, bg="#f7f7f7")
    filter_frame.pack(pady=5)

    # --- DYNAMICALLY CREATE CHECKBOXES ---
    for i, (level, var) in enumerate(risk_filter.items()):
        cb = tk.Checkbutton(
            filter_frame, text=level, variable=var,
            bg="#f7f7f7", font=("Arial", 9),
            onvalue=True, offvalue=False, command=filter_and_populate
        )
        cb.grid(row=0, column=i, padx=10)

    session_frame = tk.Frame(summary_window, bg="#f7f7f7")
    session_frame.pack(pady=5)

    tk.Label(session_frame, text="Select Scan Session:", font=("Arial", 10, "bold"), bg="#f7f7f7").pack(side="left")

    session_var = tk.StringVar()
    session_dropdown = ttk.Combobox(session_frame, textvariable=session_var, values=session_ids, state="readonly", width=40)
    session_dropdown.pack(side="left", padx=10)

    table_frame = tk.Frame(summary_window)
    table_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)
    
    columns = ("Timestamp", "File", "Threat Type", "Risk Level")
    summary_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
    
    for col in columns:
        summary_table.heading(col, text=col, anchor=tk.W, command=lambda c=col: sort_by_column(summary_table, c, False))

    summary_table.column("Timestamp", width=180)
    summary_table.column("File", width=280)
    summary_table.column("Threat Type", width=180)
    summary_table.column("Risk Level", width=100)

    def get_tag(level):
        level = str(level).lower()
        if level == "critical": return "critical_risk"
        if level == "high": return "high_risk"
        if level == "medium": return "medium_risk"
        return "low_risk" # Default for "Low", "Clean", "Info", etc.

    summary_table.tag_configure("critical_risk", background="#f8d7da")
    summary_table.tag_configure("high_risk", background="#ffcccc")
    summary_table.tag_configure("medium_risk", background="#fff3cd")
    summary_table.tag_configure("low_risk", background="#d4edda")

    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=summary_table.yview)
    summary_table.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    summary_table.pack(fill=tk.BOTH, expand=True)

    def on_session_change(event):
        filter_and_populate()

    session_dropdown.bind("<<ComboboxSelected>>", on_session_change)
    if session_ids:
        session_var.set(session_ids[0])
        filter_and_populate()

    def export_summary():
        selected_session = session_var.get()
        if not selected_session:
            messagebox.showwarning("No Session Selected", "Please select a scan session to export.")
            return

        export_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialdir=os.path.join(os.getcwd(), "database"),
            title="Save Scan Report As"
        )
        if not export_path:
            return

        try:
            with open(export_path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "File", "Threat Type", "Risk Level", "Session ID"])
                for result in all_results:
                    if result["session_id"] == selected_session:
                        writer.writerow([
                            result["timestamp"],
                            result["file"],
                            result["threat_type"],
                            result["risk_level"],
                            result["session_id"]
                        ])
            messagebox.showinfo("Export Successful", f"Summary exported to:\n{export_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export CSV:\n{str(e)}")

    def delete_session():
        selected_session = session_var.get()
        if not selected_session:
            messagebox.showwarning("No Session Selected", "Please select a session to delete.")
            return

        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete all results from session:\n{selected_session}?")
        if not confirm:
            return

        # Filter out the session to be deleted
        new_results = [r for r in all_results if r["session_id"] != selected_session]
        
        try:
            # Write the remaining data back to the file
            with open(history_file, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                # Write header first
                writer.writerow(["Timestamp", "File Name", "Threat Type", "Risk Level", "Session ID", "Last Modified"]) # Assuming this header
                for result in new_results:
                    # Make sure to write all columns, even if some are empty
                    writer.writerow([
                        result.get("timestamp", ""),
                        result.get("file", ""),
                        result.get("threat_type", ""),
                        result.get("risk_level", ""),
                        result.get("session_id", ""),
                        result.get("last_modified", "") 
                    ])
            messagebox.showinfo("Deleted", "Session deleted successfully.")
            # Re-open the page to reflect the changes
            summary_window.destroy()
            open_summary_page(root)
        except Exception as e:
            messagebox.showerror("Delete Failed", f"Could not delete session:\n{str(e)}")

    button_frame = tk.Frame(summary_window, bg="#f7f7f7")
    button_frame.pack(pady=15)

    export_button = tk.Button(button_frame, text="Export Session to CSV", command=export_summary, width=20, bg="#4CAF50", fg="white")
    delete_button = tk.Button(button_frame, text="Delete Session", command=delete_session, width=15, bg="#ff4d4d", fg="white")
    back_button = tk.Button(button_frame, text="Back to Dashboard", command=on_close, width=20, bg="#6c757d", fg="white")

    export_button.grid(row=0, column=0, padx=10)
    delete_button.grid(row=0, column=1, padx=10)
    back_button.grid(row=0, column=2, padx=10)