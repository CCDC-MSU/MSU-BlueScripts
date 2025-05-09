!/bin/bash

#sudo nmap -A  $IP > scan_output.txt
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IP_DIR="$SCRIPT_DIR/IP.txt"
# I used chatgpt for the next part because im out of dr peper
echo "the script ran on its own!" >> test.txt
PREV="$SCRIPT_DIR/scan_previous.txt"
CURR="$SCRIPT_DIR/scan_current.txt"


IP=$(cat $IP_DIR)

LOGFILE="$SCRIPT_DIR/scan_output.txt"

{
    echo "==== Running scan at $(date) ===="
    echo "IP from file: $IP"
    echo "nmap command: nmap -sn $IP -oG $CURR"
    nmap -sn "$IP" -oG "$CURR"
    echo "Scan output:"
    cat "$CURR"
} >> "$LOGFILE" 2>&1

# Run scan
nmap -sn $IP -oG "$CURR"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Compare and log results
{
    echo "==== Scan at $TIMESTAMP ====" # i got more dr peper and am locked in

    if [ -f "$PREV" ]; then
        echo "New Devices:"
        diff "$PREV" "$CURR" | grep '^>' || echo "None"

        echo "Removed Devices:"
        diff "$PREV" "$CURR" | grep '^<' || echo "None"
    else
        echo "No previous scan to compare."
    fi

    echo ""
} | tee -a "$LOGFILE"


# Update scan snapshot
mv "$CURR" "$PREV"
echo "Scan ran at $(date)"
