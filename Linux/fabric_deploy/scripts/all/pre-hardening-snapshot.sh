#!/bin/sh
#
# System State Backup Script
# Creates comprehensive backup before system hardening
#

BACKUP_ROOT="/root/pre-hardening-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
FILES_DIR="${BACKUP_DIR}/files"
STATE_DIR="${BACKUP_DIR}/state"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

# Create backup directories
log_info "Creating backup directories..."
mkdir -p "${FILES_DIR}" "${STATE_DIR}"

# Backup function for files
backup_file() {
    src="$1"
    if [ -f "$src" ] || [ -d "$src" ]; then
        dest_dir="${FILES_DIR}$(dirname "$src")"
        mkdir -p "$dest_dir"
        cp -a "$src" "$dest_dir/" 2>/dev/null || log_warn "Failed to backup: $src"
        log_info "Backed up: $src"
    else
        log_warn "Not found: $src"
    fi
}

# ============================================================================
# USER AND AUTHENTICATION FILES
# ============================================================================
log_info "Backing up user and authentication files..."
backup_file /etc/passwd
backup_file /etc/shadow
backup_file /etc/group
backup_file /etc/gshadow
backup_file /etc/sudoers
backup_file /etc/sudoers.d

# ============================================================================
# SSH CONFIGURATION
# ============================================================================
log_info "Backing up SSH configuration..."
backup_file /etc/ssh/sshd_config
backup_file /etc/ssh/ssh_config
backup_file /etc/ssh/sshd_config.d
backup_file /etc/ssh/ssh_config.d

# ============================================================================
# PAM CONFIGURATION
# ============================================================================
log_info "Backing up PAM configuration..."
backup_file /etc/pam.d
backup_file /etc/security

# ============================================================================
# NETWORK CONFIGURATION
# ============================================================================
log_info "Backing up network configuration..."
backup_file /etc/network/interfaces
backup_file /etc/network/interfaces.d
backup_file /etc/sysconfig/network-scripts
backup_file /etc/netplan
backup_file /etc/hosts
backup_file /etc/hosts.allow
backup_file /etc/hosts.deny
backup_file /etc/resolv.conf

# ============================================================================
# SELINUX CONFIGURATION
# ============================================================================
log_info "Backing up SELinux configuration..."
backup_file /etc/selinux
backup_file /etc/sysconfig/selinux

# ============================================================================
# APPARMOR CONFIGURATION
# ============================================================================
log_info "Backing up AppArmor configuration..."
backup_file /etc/apparmor.d
backup_file /etc/apparmor

# ============================================================================
# SYSTEMD CONFIGURATION
# ============================================================================
log_info "Backing up systemd configuration..."
backup_file /etc/systemd
backup_file /etc/default

# ============================================================================
# CRON JOBS
# ============================================================================
log_info "Backing up cron jobs..."
backup_file /etc/crontab
backup_file /etc/cron.d
backup_file /etc/cron.daily
backup_file /etc/cron.hourly
backup_file /etc/cron.weekly
backup_file /etc/cron.monthly
backup_file /var/spool/cron

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================
log_info "Backing up firewall configuration..."
backup_file /etc/sysconfig/iptables
backup_file /etc/iptables

# ============================================================================
# OTHER SECURITY FILES
# ============================================================================
log_info "Backing up other security files..."
backup_file /etc/login.defs
backup_file /etc/securetty
backup_file /etc/profile
backup_file /etc/profile.d
backup_file /etc/bash.bashrc
backup_file /etc/bashrc
backup_file /etc/skel

# ============================================================================
# CAPTURE CURRENT STATE
# ============================================================================
log_info "Capturing current system state..."

# System information
log_info "Capturing system information..."
uname -a > "${STATE_DIR}/uname.txt" 2>&1
hostname > "${STATE_DIR}/hostname.txt" 2>&1
uptime > "${STATE_DIR}/uptime.txt" 2>&1
date > "${STATE_DIR}/date.txt" 2>&1

# Running processes
log_info "Capturing running processes..."
ps auxf > "${STATE_DIR}/processes.txt" 2>&1

# Open ports and connections
log_info "Capturing network connections..."
if command -v ss >/dev/null 2>&1; then
    ss -tulpn > "${STATE_DIR}/listening_ports.txt" 2>&1
    ss -tupn > "${STATE_DIR}/established_connections.txt" 2>&1
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn > "${STATE_DIR}/listening_ports.txt" 2>&1
    netstat -tupn > "${STATE_DIR}/established_connections.txt" 2>&1
else
    log_warn "Neither ss nor netstat found"
fi

# Network configuration state
log_info "Capturing network configuration state..."
if command -v ip >/dev/null 2>&1; then
    ip addr show > "${STATE_DIR}/ip_addresses.txt" 2>&1
    ip route show > "${STATE_DIR}/ip_routes.txt" 2>&1
    ip link show > "${STATE_DIR}/ip_links.txt" 2>&1
elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig -a > "${STATE_DIR}/ifconfig.txt" 2>&1
    route -n > "${STATE_DIR}/routes.txt" 2>&1
fi

# Firewall rules (iptables)
log_info "Capturing iptables rules..."
if command -v iptables >/dev/null 2>&1; then
    iptables -L -n -v --line-numbers > "${STATE_DIR}/iptables_filter.txt" 2>&1
    iptables -t nat -L -n -v --line-numbers > "${STATE_DIR}/iptables_nat.txt" 2>&1
    iptables -t mangle -L -n -v --line-numbers > "${STATE_DIR}/iptables_mangle.txt" 2>&1
    iptables -t raw -L -n -v --line-numbers > "${STATE_DIR}/iptables_raw.txt" 2>&1
    iptables-save > "${STATE_DIR}/iptables_save.txt" 2>&1
fi

if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -L -n -v --line-numbers > "${STATE_DIR}/ip6tables_filter.txt" 2>&1
    ip6tables-save > "${STATE_DIR}/ip6tables_save.txt" 2>&1
fi

# SELinux status
log_info "Capturing SELinux status..."
if command -v getenforce >/dev/null 2>&1; then
    getenforce > "${STATE_DIR}/selinux_mode.txt" 2>&1
fi
if command -v sestatus >/dev/null 2>&1; then
    sestatus > "${STATE_DIR}/selinux_status.txt" 2>&1
fi
if command -v semanage >/dev/null 2>&1; then
    semanage boolean -l > "${STATE_DIR}/selinux_booleans.txt" 2>&1
    semanage port -l > "${STATE_DIR}/selinux_ports.txt" 2>&1
fi

# AppArmor status
log_info "Capturing AppArmor status..."
if command -v aa-status >/dev/null 2>&1; then
    aa-status > "${STATE_DIR}/apparmor_status.txt" 2>&1
fi

# Systemd services
log_info "Capturing systemd services..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service --all > "${STATE_DIR}/systemd_services.txt" 2>&1
    systemctl list-unit-files --type=service > "${STATE_DIR}/systemd_service_files.txt" 2>&1
    systemctl list-units --type=socket --all > "${STATE_DIR}/systemd_sockets.txt" 2>&1
    systemctl list-units --type=timer --all > "${STATE_DIR}/systemd_timers.txt" 2>&1
fi

# Init scripts (for non-systemd systems)
if [ -d /etc/init.d ]; then
    ls -la /etc/init.d > "${STATE_DIR}/initd_scripts.txt" 2>&1
fi

# Loaded kernel modules
log_info "Capturing loaded kernel modules..."
lsmod > "${STATE_DIR}/loaded_modules.txt" 2>&1

# Kernel parameters
log_info "Capturing kernel parameters..."
sysctl -a > "${STATE_DIR}/sysctl.txt" 2>&1

# Installed packages
log_info "Capturing installed packages..."
if command -v dpkg >/dev/null 2>&1; then
    dpkg -l > "${STATE_DIR}/packages_dpkg.txt" 2>&1
elif command -v rpm >/dev/null 2>&1; then
    rpm -qa > "${STATE_DIR}/packages_rpm.txt" 2>&1
fi

# User login history
log_info "Capturing login history..."
last -F > "${STATE_DIR}/last_logins.txt" 2>&1
lastlog > "${STATE_DIR}/lastlog.txt" 2>&1
who > "${STATE_DIR}/currently_logged_in.txt" 2>&1
w > "${STATE_DIR}/who_what.txt" 2>&1

# File permissions for critical directories
log_info "Capturing file permissions..."
{
    ls -laR /etc 2>/dev/null
} > "${STATE_DIR}/etc_permissions.txt"

{
    ls -la /bin /sbin /usr/bin /usr/sbin 2>/dev/null
} > "${STATE_DIR}/bin_permissions.txt"

{
    find /etc -type f -perm /022 2>/dev/null
} > "${STATE_DIR}/world_writable_etc.txt"

# SUID/SGID files
log_info "Capturing SUID/SGID files..."
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > "${STATE_DIR}/suid_sgid_files.txt"

# Environment variables
log_info "Capturing environment variables..."
env > "${STATE_DIR}/environment.txt" 2>&1

# Disk usage and mounts
log_info "Capturing disk information..."
df -h > "${STATE_DIR}/disk_usage.txt" 2>&1
mount > "${STATE_DIR}/mounts.txt" 2>&1
cat /etc/fstab > "${STATE_DIR}/fstab.txt" 2>&1

# ============================================================================
# CREATE METADATA
# ============================================================================
log_info "Creating metadata..."
{
    echo "Backup created: $(date)"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "Distribution: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "Backup location: ${BACKUP_DIR}"
} > "${BACKUP_DIR}/metadata.txt"

# Create a symlink to latest backup
log_info "Creating symlink to latest backup..."
ln -sfn "${BACKUP_DIR}" "${BACKUP_ROOT}/latest"

if [ -L "${BACKUP_ROOT}/latest" ]; then
    log_info "Symlink created successfully: ${BACKUP_ROOT}/latest -> ${BACKUP_DIR}"
else
    log_error "Failed to create symlink at ${BACKUP_ROOT}/latest"
fi

# ============================================================================
# SUMMARY
# ============================================================================
log_info "========================================"
log_info "Backup completed successfully!"
log_info "Backup location: ${BACKUP_DIR}"
log_info "Latest symlink: ${BACKUP_ROOT}/latest"
log_info "========================================"
log_info ""
log_info "To compare with current state after hardening, run:"
log_info "  ./compare-system-state.sh"
log_info ""

exit 0