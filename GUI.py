import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import subprocess
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_FILE = os.path.join(SCRIPT_DIR, "scan_current.txt")
LOG_FILE = os.path.join(SCRIPT_DIR, "scan_changes.log")
IP_FILE = os.path.join(SCRIPT_DIR, "IP.txt")
DEVICE_LIST_FILE = os.path.join(SCRIPT_DIR, "deviceList.txt")
RUN_SCAN_SCRIPT = os.path.join(SCRIPT_DIR, "run_scan.py")

# Get IP scan range from file
def get_scan_range():
    with open(IP_FILE, "r") as f:
        return f.read().strip()

# Get MAC address using arp -a
def get_mac_address(ip):
    try:
        output = subprocess.check_output(["arp", "-a"], encoding='utf-8')
        for line in output.splitlines():
            if ip in line:
                match = re.search(r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", line)
                if match:
                    return match.group(1)
    except Exception as e:
        print(f"Failed to get MAC for {ip}: {e}")
    return "Unknown"

# Load known devices from deviceList.txt
def load_known_devices():
    known = {}
    if os.path.exists(DEVICE_LIST_FILE):
        with open(DEVICE_LIST_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(" | ")
                if len(parts) == 4:
                    ip, hostname, mac, timestamp = parts
                    known[ip] = (hostname, mac, timestamp)
    return known

# Update deviceList.txt with new or updated devices
def update_device_list(devices):
    existing = load_known_devices()
    # Create a new list to hold all devices
    updated_devices = {ip: (hostname, mac, timestamp) for ip, (hostname, mac, timestamp) in existing.items()}

    for ip, hostname, mac, timestamp in devices:
        # Update the device information if it already exists
        updated_devices[ip] = (hostname, mac, timestamp)

    # Write the updated devices back to the device list file
    with open(DEVICE_LIST_FILE, "w") as f:
        for ip, (hostname, mac, timestamp) in updated_devices.items():
            f.write(f"{ip} | {hostname} | {mac} | {timestamp}\n")

# GUI: Display connected devices
def show_devices():
    def refresh():
        for row in tree.get_children():
            tree.delete(row)
        known = load_known_devices()
        for ip, (hostname, mac, timestamp) in known.items():
            tree.insert("", tk.END, values=(ip, hostname, mac, timestamp))

    device_window = tk.Toplevel(root)
    device_window.title("Connected Devices")

    tree = ttk.Treeview(device_window, columns=("IP", "Hostname", "MAC", "Time"), show="headings")
    for col in ("IP", "Hostname", "MAC", "Time"):
        tree.heading(col, text=col)
        tree.column(col, width=150)
    tree.pack(fill="both", expand=True, padx=10, pady=10)

    tk.Button(device_window, text="Refresh", command=refresh).pack(pady=5)

    refresh()  # Load devices when the window opens

# GUI: View scan log
def show_log():
    log_window = tk.Toplevel(root)
    log_window.title("Scan Log")

    log_text = scrolledtext.ScrolledText(log_window, width=100, height=30)
    log_text.pack(padx=10, pady=10)

    def refresh_log():
        log_text.delete(1.0, tk.END)
        try:
            with open(LOG_FILE, "r") as f:
                log_text.insert(tk.END, f.read())
        except FileNotFoundError:
            log_text.insert(tk.END, "Log file not found.")

    tk.Button(log_window, text="Refresh", command=refresh_log).pack(pady=5)

    refresh_log()

# GUI: Manual scan
def run_scan_now():
    try:
        subprocess.run(["python3", RUN_SCAN_SCRIPT], check=True)
        messagebox.showinfo("Scan Complete", "Manual scan completed successfully.")
        show_devices()  # Refresh the device list after the scan
    except subprocess.CalledProcessError as e:

        messagebox.showerror("Scan Failed", f"Scan script returned error:\n{e}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not run scan: {e}")

# Clear the scan log
def clear_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("")
        messagebox.showinfo("Log Cleared", "Scan log has been cleared.")
    else:
        messagebox.showinfo("No Log File", "No log file found to clear.")

# GUI: Main menu
root = tk.Tk()
root.title("Network Scanner Menu")

tk.Label(root, text="Choose an option:", font=("Arial", 14)).pack(pady=10)

tk.Button(root, text="View Connected Devices", width=30, command=show_devices).pack(pady=5)
tk.Button(root, text="View ChangeLog", width=30, command=show_log).pack(pady=5)
tk.Button(root, text="Run Scan Now", width=30, command=run_scan_now).pack(pady=5)
tk.Button(root, text="Clear Log", width=30, command=clear_log).pack(pady=5)

root.mainloop()
