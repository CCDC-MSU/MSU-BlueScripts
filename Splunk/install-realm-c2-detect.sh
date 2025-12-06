#!/bin/sh
# Installation script for Realm C2 Detection
# Works on: Arch Linux, CentOS, Ubuntu

echo "[*] Installing Realm C2 Detection..."

# Detect OS and install tcpdump if needed
if command -v pacman >/dev/null 2>&1; then
    echo "[*] Detected Arch Linux"
    sudo pacman -S --noconfirm tcpdump grep 2>/dev/null
    LOG_FILE="/var/log/syslog"
elif command -v apt >/dev/null 2>&1; then
    echo "[*] Detected Ubuntu/Debian"
    sudo apt update && sudo apt install -y tcpdump grep 2>/dev/null
    LOG_FILE="/var/log/syslog"
elif command -v yum >/dev/null 2>&1; then
    echo "[*] Detected CentOS/RHEL"
    sudo yum install -y tcpdump grep 2>/dev/null
    LOG_FILE="/var/log/messages"
else
    echo "[!] Unknown OS - please install tcpdump manually"
    exit 1
fi

# Create detection script WITH RECURSIVE LOOP FIX
echo "[*] Creating detection script..."
sudo tee /usr/local/bin/realm-c2-detect.sh > /dev/null << 'SCRIPT_EOF'

#!/bin/sh
# Realm/Imix C2 Beacon Detection via tcpdump
# Monitors TCP traffic for Realm signatures
# EXCLUDES Splunk forwarder traffic to prevent loops

tcpdump -i any -l -n -A -s 512 'tcp and not port 9997 and not port 8089' 2>/dev/null | \
grep -iE --line-buffered "imix|realm|tavern|eldritch|spellshift" | \
grep -v "realm_c2_detect" | \
grep -v "_path./var/log" | \
while IFS= read -r line; do
    logger -p local0.warning -t realm_c2_detect "REALM_C2_DETECTED: $line"
done

SCRIPT_EOF

sudo chmod +x /usr/local/bin/realm-c2-detect.sh

# Start with nohup
echo "[*] Starting detection service with nohup..."
nohup /usr/local/bin/realm-c2-detect.sh > /dev/null 2>&1 &
DETECTION_PID=$!
echo "[✓] Started with PID: $DETECTION_PID"

# Add to crontab for auto-start on reboot
echo "[*] Adding to crontab for auto-start on reboot..."
(crontab -l 2>/dev/null | grep -v realm-c2-detect; echo "@reboot /usr/local/bin/realm-c2-detect.sh > /dev/null 2>&1 &") | crontab -

# Add to Splunk monitoring if Splunk forwarder exists
if [ -f /opt/splunkforwarder/bin/splunk ]; then
    echo "[*] Configuring Splunk to monitor Realm C2 logs..."
    
    # Check if already monitoring this log file
    if ! sudo /opt/splunkforwarder/bin/splunk list monitor | grep -q "$LOG_FILE"; then
        sudo /opt/splunkforwarder/bin/splunk add monitor "$LOG_FILE" \
            -index network \
            -sourcetype syslog 2>/dev/null
        sudo /opt/splunkforwarder/bin/splunk restart 2>/dev/null
        echo "[✓] Splunk configured to monitor $LOG_FILE"
    else
        echo "[✓] Splunk already monitoring $LOG_FILE"
    fi
else
    echo "[!] Splunk forwarder not found - skipping Splunk configuration"
fi

echo ""
echo "============================================"
echo "   Realm C2 Detection Installation Complete"
echo "============================================"
echo ""
echo "Status:"
echo "  ✓ Detection script: /usr/local/bin/realm-c2-detect.sh"
echo "  ✓ Logs going to: $LOG_FILE (tagged: realm_c2_detect)"
echo "  ✓ Running with PID: $DETECTION_PID"
echo "  ✓ Auto-start on reboot: ENABLED"
echo "  ✓ Recursive loop protection: ENABLED"
echo ""
echo "Commands:"
echo "  Check status:  pgrep -fa realm-c2-detect"
echo "  View logs:     tail -f $LOG_FILE | grep realm_c2_detect"
echo "  Stop:          pkill -f realm-c2-detect.sh"
echo "  Start:         nohup /usr/local/bin/realm-c2-detect.sh > /dev/null 2>&1 &"
echo ""
