#!/bin/bash

echo "==============================================================="
echo "All scripts (currently) need a log file that will be extracted."
echo "All remote log files to be extracted should be /tmp/log.txt"
echo "==============================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Check if sshpass is installed and install if not
if ! command -v sshpass &>/dev/null; then
    echo "[*] sshpass not found — attempting to install..."

    if command -v apt-get &>/dev/null; then
        apt-get update -y && apt-get install -y sshpass # Debian/Ubuntu
    elif command -v dnf &>/dev/null; then
        dnf install -y sshpass # RHEL/Rocky/Alma/CentOS/Fedora
    elif command -v yum &>/dev/null; then
        yum install -y epel-release sshpass # RHEL/Rocky/Alma/CentOS/Fedora
    elif command -v zypper &>/dev/null; then
        zypper install -y sshpass # openSUSE
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm sshpass # Arch
    elif command -v apk &>/dev/null; then
        apk add --no-cache sshpass # Alpine
    elif command -v pkg &>/dev/null; then
        pkg install -y sshpass # FreeBSD
    else
        echo "ERROR: Could not detect a supported package manager to install sshpass."
        echo "Please install sshpass manually and re-run this script."
        exit 1
    fi

    if ! command -v sshpass &>/dev/null; then
        echo "ERROR: sshpass installation failed."
        exit 1
    fi

    echo "[+] sshpass successfully installed."
fi

# Get Information

read -rp "Script to transfer: " SCRIPT
read -rp "Target Host: " TARGET
read -rp "SSH User: " USERNAME
read -s -rp "Password for ${USERNAME}@${TARGET}: " PASSWORD

# End Get Information

# Initialize File Paths

LOCAL_SCRIPT=$SCRIPT
REMOTE_SCRIPT=/tmp/script.sh

LOCAL_LOG="script-${SCRIPT}-${TARGET}-$(date +%Y-%m-%d_%H-%M-%S).txt"
REMOTE_LOG="/tmp/log.txt"

# End Initialization


# Copy script over
sshpass -p "$PASSWORD" scp -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no "$LOCAL_SCRIPT" "${USERNAME}@${TARGET}:${REMOTE_SCRIPT}"

# Making Executable
sshpass -p "$PASSWORD" ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no "${USERNAME}@${TARGET}" "echo '${PASSWORD}' | sudo -S chmod +x ${REMOTE_SCRIPT}"

# Run Script
sshpass -p "$PASSWORD" ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no "${USERNAME}@${TARGET}" "echo '${PASSWORD}' | sudo -S /bin/bash ${REMOTE_SCRIPT}" <<< "${PASSWORD}"

# Extracting file
sshpass -p "$PASSWORD" scp -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no "${USERNAME}@${TARGET}:${REMOTE_LOG}" "${LOCAL_LOG}"

# Cleanup
sshpass -p "$PASSWORD" ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no "${USERNAME}@${TARGET}" "echo '${PASSWORD}' | sudo -S shred -uz ${REMOTE_LOG} || rm -f ${REMOTE_LOG}"
sshpass -p "$PASSWORD" ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no "${USERNAME}@${TARGET}" "echo '${PASSWORD}' | sudo -S rm ${REMOTE_SCRIPT}"

echo "[*] Done. Log File saved locally at: ${LOCAL_LOG}"

