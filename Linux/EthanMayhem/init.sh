#!/bin/sh

# CCDC Initial Audit & Backup Script
# Author: Ethan (with improvements)
# P.S. Thank you TTU for "inspiration"
# POSIX-compliant for maximum compatibility

#set -e # Exit on error (remove if you want it to continue on errors)

### DEFINE LOG FILE FIRST ###
LOG_FILE="/tmp/log.txt"
: > "$LOG_FILE"  # Clear/create log file

### ROOT CHECK ###
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Not running as root, checking for sudo access..." | tee -a "$LOG_FILE"
    if ! sudo -n true 2>/dev/null; then
        echo "ERROR: This script requires root privileges. Run with sudo." | tee -a "$LOG_FILE"
        exit 1
    fi
    echo "[+] Sudo access confirmed, re-executing with sudo..." | tee -a "$LOG_FILE"
    exec sudo "$0" "$@"
fi

### START LOGGING ###
echo "========================================" | tee -a "$LOG_FILE"
echo "CCDC Initialization Script" | tee -a "$LOG_FILE"
echo "Hostname: $(hostname)" | tee -a "$LOG_FILE"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "" >> "$LOG_FILE"

### INSTALLING DEPENDENCIES ###
echo "[*] Installing dependencies..." | tee -a "$LOG_FILE"

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y sudo net-tools iproute2 curl wget rsyslog auditd vim git gcc gzip
    echo "[+] Installed packages via apt-get" | tee -a "$LOG_FILE"
elif command -v dnf >/dev/null 2>&1; then
    dnf check-update -y
    dnf install -y sudo net-tools iproute curl wget procps-ng rsyslog audit vim git gcc gzip
    echo "[+] Installed packages via dnf" | tee -a "$LOG_FILE"
elif command -v yum >/dev/null 2>&1; then
    yum check-update -y
    yum install -y epel-release sudo net-tools iproute curl wget procps-ng rsyslog audit vim git gcc gzip
    echo "[+] Installed packages via yum" | tee -a "$LOG_FILE"
elif command -v zypper >/dev/null 2>&1; then
    zypper refresh -y
    zypper install -y sudo net-tools iproute2 curl wget rsyslog auditd vim git gcc gzip
    echo "[+] Installed packages via zypper" | tee -a "$LOG_FILE"
elif command -v pacman >/dev/null 2>&1; then
    pacman -Syu --noconfirm
    pacman -Sy --noconfirm sudo net-tools iproute2 curl wget rsyslog audit vim git gcc gzip
    echo "[+] Installed packages via pacman" | tee -a "$LOG_FILE"
elif command -v apk >/dev/null 2>&1; then
    apk update
    apk add --no-cache sudo iproute2 net-tools curl wget rsyslog audit vim git gcc gzip
    echo "[+] Installed packages via apk" | tee -a "$LOG_FILE"
elif command -v pkg >/dev/null 2>&1; then
    pkg update
    pkg install -y sudo rsyslog vim git gcc gzip
    echo "[+] Installed packages via pkg (FreeBSD)" | tee -a "$LOG_FILE"
else
    echo "[-] ERROR: Could not detect a supported package manager." | tee -a "$LOG_FILE"
    exit 1
fi

echo "" >> "$LOG_FILE"

### SETUP BACKUP DIRECTORY ###
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/root/ccdc_backup_${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
echo "[+] Created backup directory: $BACKUP_DIR" | tee -a "$LOG_FILE"
echo "" >> "$LOG_FILE"

### USER ENUMERATION ###
echo "========================================" >> "$LOG_FILE"
echo "USER ENUMERATION" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

echo "[*] Backing up /etc/passwd..." | tee -a "$LOG_FILE"
cp /etc/passwd "$BACKUP_DIR/passwd.bak"
echo "" >> "$LOG_FILE"

echo "--- Users with Valid Shells ---" >> "$LOG_FILE"
awk -F: '$7 ~ /(bash|sh|zsh|tcsh|csh|ksh)$/ && $7 !~ /nologin/ {print $1 " -> " $7}' /etc/passwd >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo "--- Users with UID 0 (Root Privileges) ---" >> "$LOG_FILE"
awk -F: '$3 == 0 {print $1 " (UID: " $3 ")"}' /etc/passwd >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

### GROUP ENUMERATION ###
echo "========================================" >> "$LOG_FILE"
echo "GROUP ENUMERATION" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

echo "[*] Backing up /etc/group..." | tee -a "$LOG_FILE"
cp /etc/group "$BACKUP_DIR/group.bak"
echo "" >> "$LOG_FILE"

echo "--- Sudo/Wheel Group Members ---" >> "$LOG_FILE"
grep -E "^(sudo|wheel|admin):" /etc/group >> "$LOG_FILE" 2>&1 || echo "No sudo/wheel/admin groups found" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

### SHADOW FILE BACKUP ###
echo "[*] Backing up /etc/shadow..." | tee -a "$LOG_FILE"
if [ -f /etc/shadow ]; then
    cp /etc/shadow "$BACKUP_DIR/shadow.bak"
    chmod 600 "$BACKUP_DIR/shadow.bak"
    echo "[+] Shadow file backed up" >> "$LOG_FILE"
fi
echo "" >> "$LOG_FILE"

### NETWORK ENUMERATION ###
echo "========================================" >> "$LOG_FILE"
echo "NETWORK ENUMERATION" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

echo "--- IP Addresses ---" >> "$LOG_FILE"
if command -v ip >/dev/null 2>&1; then
    ip addr show >> "$LOG_FILE" 2>&1
elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig >> "$LOG_FILE" 2>&1
fi
echo "" >> "$LOG_FILE"

echo "--- Listening Connections ---" >> "$LOG_FILE"
if command -v ss >/dev/null 2>&1; then
    ss -tulpn >> "$LOG_FILE" 2>&1
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn >> "$LOG_FILE" 2>&1
else
    sockstat -l >> "$LOG_FILE" 2>&1 || echo "No network tools available" >> "$LOG_FILE"
fi
echo "" >> "$LOG_FILE"

### PROCESS ENUMERATION ###
echo "========================================" >> "$LOG_FILE"
echo "PROCESS ENUMERATION" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

echo "--- Root Processes (excluding kernel threads) ---" >> "$LOG_FILE"
ps aux | grep "^root" | grep -v "\[" >> "$LOG_FILE" 2>&1
echo "" >> "$LOG_FILE"

### SERVICE ENUMERATION ###
echo "========================================" >> "$LOG_FILE"
echo "SERVICE ENUMERATION" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

if command -v systemctl >/dev/null 2>&1; then
    echo "--- Running Services (systemd) ---" >> "$LOG_FILE"
    systemctl list-units --type=service --state=running >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
elif command -v service >/dev/null 2>&1; then
    echo "--- Running Services (sysvinit) ---" >> "$LOG_FILE"
    service --status-all >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
fi

### CRON JOBS ###
echo "========================================" >> "$LOG_FILE"
echo "SCHEDULED TASKS (CRON)" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

echo "[*] Backing up cron files..." | tee -a "$LOG_FILE"
mkdir -p "$BACKUP_DIR/cron"
[ -d /etc/cron.d ] && cp -r /etc/cron.d "$BACKUP_DIR/cron/" 2>/dev/null
[ -f /etc/crontab ] && cp /etc/crontab "$BACKUP_DIR/cron/" 2>/dev/null
[ -d /var/spool/cron ] && cp -r /var/spool/cron "$BACKUP_DIR/cron/" 2>/dev/null

echo "--- System Crontab ---" >> "$LOG_FILE"
[ -f /etc/crontab ] && cat /etc/crontab >> "$LOG_FILE" 2>&1 || echo "No /etc/crontab" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo "--- Cron.d Directory ---" >> "$LOG_FILE"
[ -d /etc/cron.d ] && ls -la /etc/cron.d/ >> "$LOG_FILE" 2>&1 || echo "No /etc/cron.d" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo "--- User Crontabs ---" >> "$LOG_FILE"
cut -f1 -d: /etc/passwd | while read -r user; do
    crontab -u "$user" -l >> "$LOG_FILE" 2>&1 && echo "Crontab for $user found" >> "$LOG_FILE"
done
echo "" >> "$LOG_FILE"

### SSH CONFIGURATION ###
echo "========================================" >> "$LOG_FILE"
echo "SSH CONFIGURATION" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

if [ -f /etc/ssh/sshd_config ]; then
    echo "[*] Backing up SSH config..." | tee -a "$LOG_FILE"
    mkdir -p "$BACKUP_DIR/ssh"
    cp /etc/ssh/sshd_config "$BACKUP_DIR/ssh/sshd_config.bak"
    [ -d /etc/ssh/sshd_config.d ] && cp -r /etc/ssh/sshd_config.d "$BACKUP_DIR/ssh/" 2>/dev/null
    
    echo "--- SSH Configuration ---" >> "$LOG_FILE"
    grep -v "^#" /etc/ssh/sshd_config | grep -v "^$" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
fi

### SUDO CONFIGURATION ###
echo "========================================" >> "$LOG_FILE"
echo "SUDO CONFIGURATION" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

if [ -f /etc/sudoers ]; then
    echo "[*] Backing up sudoers..." | tee -a "$LOG_FILE"
    mkdir -p "$BACKUP_DIR/sudo"
    cp /etc/sudoers "$BACKUP_DIR/sudo/sudoers.bak"
    [ -d /etc/sudoers.d ] && cp -r /etc/sudoers.d "$BACKUP_DIR/sudo/" 2>/dev/null
    
    echo "--- Sudoers Configuration ---" >> "$LOG_FILE"
    grep -v "^#" /etc/sudoers | grep -v "^$" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
fi

### PAM CONFIGURATION ###
echo "[*] Backing up PAM configuration..." | tee -a "$LOG_FILE"
if [ -d /etc/pam.d ]; then
    mkdir -p "$BACKUP_DIR/pam"
    cp -r /etc/pam.d "$BACKUP_DIR/pam/" 2>/dev/null
    echo "[+] PAM configuration backed up" >> "$LOG_FILE"
fi
echo "" >> "$LOG_FILE"

### FIREWALL STATUS ###
echo "========================================" >> "$LOG_FILE"
echo "FIREWALL STATUS" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

if command -v iptables >/dev/null 2>&1; then
    echo "--- iptables Rules ---" >> "$LOG_FILE"
    iptables -L -n -v >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
fi

if command -v ufw >/dev/null 2>&1; then
    echo "--- UFW Status ---" >> "$LOG_FILE"
    ufw status verbose >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
fi

if command -v firewall-cmd >/dev/null 2>&1; then
    echo "--- firewalld Status ---" >> "$LOG_FILE"
    firewall-cmd --list-all >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
fi

### SUSPICIOUS FILES ###
echo "========================================" >> "$LOG_FILE"
echo "SUSPICIOUS FILE CHECK" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

echo "--- SUID Binaries ---" >> "$LOG_FILE"
find / -perm -4000 -type f 2>/dev/null >> "$LOG_FILE" || echo "SUID search failed" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo "--- SGID Binaries ---" >> "$LOG_FILE"
find / -perm -2000 -type f 2>/dev/null >> "$LOG_FILE" || echo "SGID search failed" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo "--- World-Writable Files (sample from /tmp) ---" >> "$LOG_FILE"
find /tmp -type f -perm -002 2>/dev/null | head -20 >> "$LOG_FILE" || echo "No world-writable files in /tmp" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

### COMPLETION ###
echo "========================================" >> "$LOG_FILE"
echo "INITIALIZATION COMPLETE" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"
echo "Backup location: $BACKUP_DIR" >> "$LOG_FILE"
echo "Completion time: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo "[+] Initialization complete!" | tee -a "$LOG_FILE"
echo "[+] Backup stored in: $BACKUP_DIR" | tee -a "$LOG_FILE"
echo "[+] Log file: $LOG_FILE" | tee -a "$LOG_FILE"