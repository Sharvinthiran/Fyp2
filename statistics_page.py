import pandas as pd
import matplotlib.pyplot as plt
import os
import tkinter as tk
from tkinter import messagebox

def open_statistics_page(root):
    file_path = "database/scan_history/scan_history.csv"
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "Scan history not found. Please perform a scan first.")
        return

    df = pd.read_csv(file_path, header=None, names=["Timestamp", "File", "Threat Type", "Risk Level", "Session ID", "Last Modified"])
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df.dropna(subset=["Timestamp"], inplace=True)
    df["Date"] = df["Timestamp"].dt.date

    def show_threats_over_time():
        threats_over_time = df.groupby("Date").size()
        plt.figure(figsize=(10, 5))
        threats_over_time.plot(kind="line", marker='o', title="Threats Over Time")
        plt.xlabel("Date")
        plt.ylabel("Number of Threats")
        plt.grid(True)
        plt.tight_layout()
        plt.show()

    def show_risk_level_breakdown():
        risk_counts = df["Risk Level"].value_counts()
        plt.figure(figsize=(6, 6))
        risk_counts.plot(kind="pie", autopct="%1.1f%%", title="Risk Level Breakdown")
        plt.ylabel("")
        plt.tight_layout()
        plt.show()

    def show_top_threat_types():
        threat_type_counts = df["Threat Type"].value_counts().head(10)
        plt.figure(figsize=(10, 5))
        threat_type_counts.plot(kind="bar", color='orange', title="Top Detected Threat Types")
        plt.xlabel("Threat Type")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    # --- Tkinter UI Window ---
    stats_window = tk.Toplevel(root)
    stats_window.title("Threat Statistics")
    stats_window.geometry("400x400")
    stats_window.configure(bg="#f0f2f5")

    tk.Label(stats_window, text="Threat Statistics Dashboard", font=("Arial", 16, "bold"), bg="#f0f2f5").pack(pady=20)

    tk.Button(stats_window, text="Threats Over Time", command=show_threats_over_time, width=30, bg="#4CAF50", fg="white").pack(pady=10)
    tk.Button(stats_window, text="Risk Level Breakdown", command=show_risk_level_breakdown, width=30, bg="#2196F3", fg="white").pack(pady=10)
    tk.Button(stats_window, text="Top Threat Types", command=show_top_threat_types, width=30, bg="#FF9800", fg="white").pack(pady=10)

    def back_to_dashboard():
        stats_window.destroy()
        root.deiconify()

    tk.Button(stats_window, text="Back to Dashboard", command=back_to_dashboard, width=30, bg="#6c757d", fg="white").pack(pady=20)
