import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import tkinter.font as tkFont
import queue
import os
import shutil
import subprocess
import sys

from gui.scan_page import open_scan_page
from gui.summary_page import open_summary_page
from gui.realtime_summary_page import open_realtime_summary_page
from gui.statistics_page import open_statistics_page
from gui.restore_page import open_restore_page
from gui.simulate_page import open_simulate_page
from quarantine_security import ensure_locked_on_startup
ensure_locked_on_startup()


# Import the behavior analysis module 
from behavior_analysis import start_monitor_in_background

# Create the communication queue and quarantine folder 
threat_alert_queue = queue.Queue()
QUARANTINE_FOLDER = "quarantine"
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)


#  Start Monitoring and pass the queue 
start_monitor_in_background(threat_alert_queue)



#  Threat Alert Popup Function 
def show_threat_popup(threat_info):
    """
    Creates a Toplevel popup that forces itself to the front of all other windows.
    """
    global root
    popup = tk.Toplevel(root)
    popup.title(f"⚠️ {threat_info['risk_level']} Threat Detected!")
    popup.configure(bg="#3a3a3a")

    # Force the popup to the front
    popup.attributes('-topmost', True)
    popup.lift()
    popup.focus_force()
    popup.grab_set()

    # Handle alerts with and without a 'full_path'
    # Build the message dynamically based on available info
    message_lines = [
        "A suspicious behavior was detected.\n",
        f"File/Source: {threat_info.get('file', 'N/A')}"
    ]
    if 'full_path' in threat_info:
        message_lines.append(f"Full Path: {threat_info['full_path']}")
    
    message_lines.extend([
        f"\nReason: {', '.join(threat_info.get('details', ['Unknown']))}",
        f"Score: {threat_info.get('score', 'N/A')}"
    ])
    message = "\n".join(message_lines)
    

    tk.Label(popup, text=message, padx=20, pady=20, justify=tk.LEFT, fg="white", bg="#3a3a3a", font=("Arial", 10)).pack()

    # Frame for buttons
    button_frame = tk.Frame(popup, bg="#3a3a3a")
    button_frame.pack(pady=10, padx=20, fill="x")

    # Action functions for the buttons
    def do_quarantine():
        full_path = threat_info.get('full_path')
        if not full_path:
            messagebox.showwarning("No File", "This alert is not associated with a specific file that can be quarantined.", parent=popup)
            return

        if os.path.exists(full_path):
            try:
                dest_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(full_path))
                counter = 1
                while os.path.exists(dest_path):
                    name, ext = os.path.splitext(os.path.basename(full_path))
                    dest_path = os.path.join(QUARANTINE_FOLDER, f"{name}_{counter}{ext}")
                    counter += 1
                shutil.move(full_path, dest_path)
                messagebox.showinfo("Success", f"File '{threat_info['file']}' has been moved to quarantine.", parent=popup)
                popup.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to quarantine file: {e}", parent=popup)
        else:
            messagebox.showwarning("Not Found", "The file no longer exists.", parent=popup)

    def do_open_location():
        full_path = threat_info.get('full_path')
        if not full_path:
            messagebox.showwarning("No Location", "This alert is not associated with a file location.", parent=popup)
            return

        directory = os.path.dirname(full_path)
        try:
            if sys.platform == "win32": os.startfile(directory)
            elif sys.platform == "darwin": subprocess.call(["open", directory])
            else: subprocess.call(["xdg-open", directory])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}", parent=popup)

    def do_view_summary():
        popup.destroy()
        open_realtime_summary()
    
    # Buttons
    tk.Button(button_frame, text="Quarantine File", command=do_quarantine, bg="#FFC107", fg="black").pack(side=tk.LEFT, expand=True, padx=5, pady=5)
    tk.Button(button_frame, text="Open Location", command=do_open_location).pack(side=tk.LEFT, expand=True, padx=5, pady=5)
    tk.Button(button_frame, text="View Summary", command=do_view_summary, bg="#007BFF", fg="white").pack(side=tk.LEFT, expand=True, padx=5, pady=5)
    tk.Button(button_frame, text="Ignore", command=popup.destroy).pack(side=tk.LEFT, expand=True, padx=5, pady=5)

    popup.update_idletasks()
    x = root.winfo_x() + (root.winfo_width() // 2) - (popup.winfo_width() // 2)
    y = root.winfo_y() + (root.winfo_height() // 2) - (popup.winfo_height() // 2)
    popup.geometry(f"+{x}+{y}")
    
    root.wait_window(popup)

def check_for_threat_alerts():
    """Periodically check the queue for new threats from the background monitor."""
    try:
        threat_info = threat_alert_queue.get(block=False)
        show_threat_popup(threat_info)
    except queue.Empty:
        pass
    finally:
        root.after(200, check_for_threat_alerts)


# Main Window
root = tk.Tk()
root.title("Ransomware Detection Dashboard")
root.geometry("800x800")
root.minsize(600, 600)

# Background 
bg_label = tk.Label(root)
bg_label.place(x=0, y=0, relwidth=1, relheight=1)
dynamic_widgets = []
def update_background():
    try:
        width, height = root.winfo_width(), root.winfo_height()
        if width <= 1 or height <= 1: return
        img = Image.open("assets/background.png").resize((width, height), Image.Resampling.LANCZOS)
        bg_tk = ImageTk.PhotoImage(img)
        bg_label.config(image=bg_tk)
        bg_label.image = bg_tk
    except Exception as e:
        root.config(bg="#2B2B2B")
def create_lift_button(parent, text, command, x_pos, y_pos, glow_color, shadow_color):
    HOVER_BG = "#f0f8ff"
    shadow_frame = tk.Frame(parent, bg=shadow_color, bd=0)
    button_frame = tk.Frame(parent, bg=shadow_color, relief="flat", bd=0)
    button_label = tk.Label(button_frame, text=text, bg=shadow_color, fg="white", wraplength=1)
    button_label.pack(fill="both", expand=True, padx=5, pady=5)
    dynamic_widgets.append({'widget': button_frame, 'shadow': shadow_frame, 'label': button_label, 'type': 'button', 'x_base': x_pos, 'y_base': y_pos})
    leave_job = None
    def on_enter(event):
        nonlocal leave_job
        if leave_job: root.after_cancel(leave_job); leave_job = None
        button_frame.config(bg=glow_color, relief="raised", bd=2)
        button_label.config(bg=HOVER_BG, fg="black")
        font = tkFont.Font(font=button_label['font']); font.config(weight='bold'); button_label.config(font=font)
        button_frame.place_configure(x=-3, y=-3)
    def perform_leave():
        button_frame.config(bg=shadow_color, relief="flat", bd=0)
        button_label.config(bg=shadow_color, fg="white")
        font = tkFont.Font(font=button_label['font']); font.config(weight='normal'); button_label.config(font=font)
        button_frame.place_configure(x=0, y=0)
    def on_leave(event):
        nonlocal leave_job
        leave_job = root.after(15, perform_leave)
    def on_click(event):
        button_frame.config(relief="sunken")
        button_label.after(100, lambda: [button_frame.config(relief="raised"), command()])
    for widget in [shadow_frame, button_frame, button_label]:
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)
        widget.bind("<Button-1>", on_click)
    return button_frame
title = tk.Label(root, text="🛡️ Ransomware Detection Dashboard", fg="white", bg="#1a1a1c", padx=10, pady=5)
dynamic_widgets.append({'widget': title, 'label': title, 'type': 'title', 'y_base': 0.1})
def on_window_resize(event):
    update_background()
    win_w = root.winfo_width(); win_h = root.winfo_height(); side_length = int(min(win_w, win_h) * 0.20)
    title_font_size = max(16, int(min(win_w, win_h) / 28)); button_font_size = max(9, int(side_length / 10))
    for item in dynamic_widgets:
        widget = item['widget']; current_font = tkFont.Font(font=item['label']['font']) if 'label' in item else None
        if item['type'] == 'title':
            current_font.config(size=title_font_size, weight='bold'); item['label'].config(font=current_font); widget.place_configure(relx=0.5, rely=item['y_base'], anchor="center")
        elif item['type'] == 'button':
            current_font.config(size=button_font_size); item['label'].config(font=current_font, wraplength=side_length - 20); widget.place_configure(relx=item['x_base'], rely=item['y_base'], anchor="center", width=side_length, height=side_length); item['shadow'].place_configure(relx=item['x_base'], rely=item['y_base'], anchor="center", width=side_length, height=side_length)
        elif item['type'] == 'grid_line':
            spacing_x = win_w * (item['grid_rel_width'] / item['grid_cols']) - side_length; spacing_y = win_h * (item['grid_rel_height'] / item['grid_rows']) - side_length
            if item['orientation'] == 'h': widget.place_configure(relx=item['x_base'], rely=item['y_base'], anchor="center", width=spacing_x + side_length, height=3)
            else: widget.place_configure(relx=item['x_base'], rely=item['y_base'], anchor="center", width=3, height=spacing_y + side_length)
def safe_open(func, name):
    try: root.withdraw(); func()
    except Exception as e: root.deiconify(); messagebox.showerror("Error", f"Failed to open {name}:\n{str(e)}")
def open_scan(): safe_open(lambda: open_scan_page(root, open_summary_page), "Scan Page")
def open_summary(): safe_open(lambda: open_summary_page(root), "Scan Summary Page")
def open_realtime_summary(): safe_open(lambda: open_realtime_summary_page(root), "Real-Time Monitor Summary")
def open_statistics(): safe_open(lambda: open_statistics_page(root), "Statistics Page")
def open_restore(): safe_open(lambda: open_restore_page(root), "Restore Page")
def open_simulate(): safe_open(lambda: open_simulate_page(root), "Simulation Page")

aurora_palette = [{'glow': '#00b4d8', 'shadow': '#03045e'}, {'glow': '#06d6a0', 'shadow': '#073b4c'}, {'glow': '#ef476f', 'shadow': '#580c1f'}, {'glow': '#ffd166', 'shadow': '#7f5539'}, {'glow': '#8338ec', 'shadow': '#3a0ca3'}, {'glow': '#ff9f1c', 'shadow': '#e76f51'}, {'glow': '#4cc9f0', 'shadow': '#4361ee'}]
GRID_COLS = 3
buttons_to_create = [("📁 Scan", open_scan), ("📄 Recent Scan Summary", open_summary), ("🕵️ Real-Time Monitor Summary", open_realtime_summary), ("📈 Threat Statistics", open_statistics), ("♻️ Restore Quarantine", open_restore), ("🧪 Simulate", open_simulate)]
GRID_ROWS = (len(buttons_to_create) + GRID_COLS - 1) // GRID_COLS
GRID_REL_X_START = 0.15; GRID_REL_Y_START = 0.25; GRID_REL_WIDTH = 0.70; GRID_REL_HEIGHT = 0.70; LINE_COLOR = "#2c2c2e"
button_map = {}
for i, (text, command) in enumerate(buttons_to_create):
    row, col = divmod(i, GRID_COLS)
    if i == len(buttons_to_create) - 1 and col == 0: col = 1
    button_map[(row, col)] = (text, command)
for r in range(GRID_ROWS):
    for c in range(GRID_COLS):
        if (r, c) in button_map and (r, c + 1) in button_map:
            x_pos = GRID_REL_X_START + (c + 1) * (GRID_REL_WIDTH / GRID_COLS); y_pos = GRID_REL_Y_START + (r + 0.5) * (GRID_REL_HEIGHT / GRID_ROWS); line = tk.Frame(root, bg=LINE_COLOR, width=3, relief='flat'); dynamic_widgets.append({'widget': line, 'type': 'grid_line', 'orientation': 'v', 'x_base': x_pos, 'y_base': y_pos, 'grid_rel_width': GRID_REL_WIDTH, 'grid_rel_height': GRID_REL_HEIGHT, 'grid_cols': GRID_COLS, 'grid_rows': GRID_ROWS})
        if (r, c) in button_map and (r + 1, c) in button_map:
            x_pos = GRID_REL_X_START + (c + 0.5) * (GRID_REL_WIDTH / GRID_ROWS); y_pos = GRID_REL_Y_START + (r + 1) * (GRID_REL_HEIGHT / GRID_ROWS); line = tk.Frame(root, bg=LINE_COLOR, height=3, relief='flat'); dynamic_widgets.append({'widget': line, 'type': 'grid_line', 'orientation': 'h', 'x_base': x_pos, 'y_base': y_pos, 'grid_rel_width': GRID_REL_WIDTH, 'grid_rel_height': GRID_REL_HEIGHT, 'grid_cols': GRID_COLS, 'grid_rows': GRID_ROWS})
color_index = 0
for r in range(GRID_ROWS):
    for c in range(GRID_COLS):
        if (r, c) in button_map:
            text, command = button_map[(r, c)]; x_pos = GRID_REL_X_START + (c + 0.5) * (GRID_REL_WIDTH / GRID_COLS); y_pos = GRID_REL_Y_START + (r + 0.5) * (GRID_REL_HEIGHT / GRID_ROWS); colors = aurora_palette[color_index % len(aurora_palette)]; create_lift_button(root, text, command, x_pos, y_pos, glow_color=colors['glow'], shadow_color=colors['shadow']); color_index += 1
title.lift()
root.bind("<Configure>", on_window_resize)
root.after(50, lambda: on_window_resize(None))

# Start polling the threat queue
check_for_threat_alerts()

root.mainloop()