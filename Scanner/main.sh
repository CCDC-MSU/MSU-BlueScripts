#!/bin/bash

# to setup run the following in the terminal:
# chmod +x LockIn.sh update_scan.sh
# ./LockIn.sh

userInput=""
chmod +x LockIn.sh run_scan.py

echo "Hello, BullDogs! Let's grab a scan of the network..."

# Get local IP (CIDR format)
IP=$(ip -4 -o addr show | awk '$2 != "lo" {print $4; exit}')


echo "My IP is: $IP"
echo "Is this correct? [yes/no]"
read userInput
if [ "$userInput" = "no" ]; then
    read -p "Enter your IP address (e.g. 192.168.0.0/24): " IP
fi

# Save IP to file
echo "$IP" > IP.txt

# Create necessary files
touch scan_output.txt
touch scan_previous.txt
touch scan_current.txt
LOGFILE="scan_changes.log"
touch "$LOGFILE"

# Script to run every minute
TARGET_SCRIPT="./run_scan.py"

# Add cron entry if not already present
(crontab -l 2>/dev/null; echo "* * * * * $(pwd)/$TARGET_SCRIPT") | sort -u | crontab -
echo "Cron job scheduled. Scans will run every minute."

# Run an initial scan right now
PREV="scan_previous.txt"
CURR="scan_current.txt"
IP=$(cat IP.txt)

python GUI.py
echo "Initial scan complete at $(date)"
