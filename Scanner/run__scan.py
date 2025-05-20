from datetime import datetime
import subprocess
import os
import re

# Define paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_FILE = os.path.join(SCRIPT_DIR, "scan_current.txt")
LOG_FILE = os.path.join(SCRIPT_DIR, "scan_changes.log")
IP_FILE = os.path.join(SCRIPT_DIR, "IP.txt")
DEVICE_LIST_FILE = os.path.join(SCRIPT_DIR, "deviceList.txt")

# Get IP scan range from file
def get_scan_range():
    try:
        with open(IP_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("IP.txt not found.")
        return ""

# Load known devices
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

# Add new devices to the device list
def update_device_list(devices):
    existing = load_known_devices()
    with open(DEVICE_LIST_FILE, "a") as f:
        for ip, hostname, mac, timestamp in devices:
            if ip not in existing:
                f.write(f"{ip} | {hostname} | {mac} | {timestamp}\n")

# Run the Nmap scan
def run_scan():
    ip_range = get_scan_range()
    if not ip_range:
        print("No scan range specified.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        subprocess.run(["nmap", "-sn", ip_range, "-oN", SCAN_FILE], check=True)

        devices = []
        current_ip = None
        hostname = "Unknown"
        mac = "Unknown"

        with open(SCAN_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if line.startswith("Nmap scan report for"):
                    parts = line.split(" ")
                    # Example: "Nmap scan report for hostname (192.168.0.1)" or just IP
                    if "(" in line and ")" in line:
                        hostname_match = re.search(r"Nmap scan report for (.+) \(([\d\.]+)\)", line)
                        if hostname_match:
                            hostname = hostname_match.group(1)
                            current_ip = hostname_match.group(2)
                    else:
                        current_ip = parts[-1]
                        hostname = "Unknown"
                    mac = "Unknown"  # reset for each host

                elif "MAC Address:" in line and current_ip:
                    mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})( \((.+)\))?", line)
                    if mac_match:
                        mac = mac_match.group(1).lower()
                        manufacturer = mac_match.group(3) if mac_match.group(3) else "Unknown"
                        if hostname == "Unknown":
                            hostname = manufacturer
                        else:
                            hostname += f" ({manufacturer})"

                    devices.append((current_ip, hostname, mac, timestamp))
                    current_ip = None  # ready for next host

        # Log the scan and results
        with open(LOG_FILE, "a") as log:
            log.write(f"\n==== Scan at {timestamp} ====\n")
            with open(SCAN_FILE, "r") as scan:
                log.write(scan.read())
            log.write("\nDetected Devices:\n")
            for ip, hostname, mac, ts in devices:
                log.write(f"{ip} | {hostname} | {mac} | {ts}\n")

        # Save new devices
        update_device_list(devices)

        print(f"Scan complete at {timestamp}. Found {len(devices)} device(s):")
        for ip, hostname, mac, ts in devices:
            print(f"{ip} | {hostname} | {mac} | {ts}")

    except subprocess.CalledProcessError as e:
        print(f"Scan failed: {e}")

if __name__ == "__main__":
    run_scan()
