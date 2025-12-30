#!/bin/sh
#
# System State Comparison Script
# Compares current system state with pre-hardening backup
#

BACKUP_ROOT="/root/pre-hardening-backups"
LATEST_BACKUP="${BACKUP_ROOT}/latest"
TEMP_STATE="/tmp/current-state-$$"

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_TYPE="Linux";;
    FreeBSD*)   OS_TYPE="FreeBSD";;
    OpenBSD*)   OS_TYPE="OpenBSD";;
    NetBSD*)    OS_TYPE="NetBSD";;
    *)          OS_TYPE="Unknown";;
esac

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_section() {
    printf "\n${BOLD}${BLUE}========================================${NC}\n"
    printf "${BOLD}${BLUE}%s${NC}\n" "$1"
    printf "${BOLD}${BLUE}========================================${NC}\n\n"
}

log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

log_change() {
    printf "${CYAN}[CHANGED]${NC} %s\n" "$1"
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

# Argument parsing
FORCE_LATEST=0
if [ "$1" = "--latest" ]; then
    FORCE_LATEST=1
fi

# Function to select backup
select_backup() {
    # Check if backup root exists
    if [ ! -d "$BACKUP_ROOT" ]; then
        log_error "Backup directory $BACKUP_ROOT does not exist."
        exit 1
    fi

    # Get list of backups (directories starting with 20)
    # BSD find doesn't support -printf, using simple ls loop
    backups=$(find "$BACKUP_ROOT" -maxdepth 1 -type d -name "20*" | sort -r)
    
    if [ -z "$backups" ]; then
        log_error "No backups found in $BACKUP_ROOT"
        exit 1
    fi

    # Count backups
    count=$(echo "$backups" | wc -l)

    # If only one backup or forcing latest, use the first one
    if [ "$count" -eq 1 ] || [ "$FORCE_LATEST" -eq 1 ]; then
        LATEST_BACKUP=$(echo "$backups" | head -n 1)
        log_info "Using backup: $LATEST_BACKUP"
        return
    fi

    # Interactive selection
    log_info "Multiple snapshots found. Please select one:"
    i=1
    echo "$backups" | while read -r line; do
        dirname=$(basename "$line")
        echo "  $i) $dirname"
        i=$((i + 1))
    done
    
    printf "Enter number (default 1): "
    read -r choice
    
    if [ -z "$choice" ]; then
        choice=1
    fi
    
    # Validate input (basic check)
    if [ "$choice" -lt 1 ] || [ "$choice" -gt "$count" ] 2>/dev/null; then
        log_error "Invalid selection: $choice"
        exit 1
    fi
    
    LATEST_BACKUP=$(echo "$backups" | sed -n "${choice}p")
    log_info "Using selected backup: $LATEST_BACKUP"
}

select_backup

BACKUP_FILES="${LATEST_BACKUP}/files"
BACKUP_STATE="${LATEST_BACKUP}/state"

log_info "Using backup from: $(readlink -f "$LATEST_BACKUP")"
log_info "Creating temporary directory for current state..."
mkdir -p "$TEMP_STATE"

# Function to capture current state (similar to backup script)
capture_current_state() {
    log_info "Capturing current system state..."
    
    if [ "$OS_TYPE" = "Linux" ]; then
        ps auxf > "${TEMP_STATE}/processes.txt" 2>&1
    else
        ps aux > "${TEMP_STATE}/processes.txt" 2>&1
    fi
    
    if [ "$OS_TYPE" = "Linux" ]; then
        if command -v ss >/dev/null 2>&1; then
            ss -tulpn > "${TEMP_STATE}/listening_ports.txt" 2>&1
            ss -tupn > "${TEMP_STATE}/established_connections.txt" 2>&1
        elif command -v netstat >/dev/null 2>&1; then
            netstat -tulpn > "${TEMP_STATE}/listening_ports.txt" 2>&1
            netstat -tupn > "${TEMP_STATE}/established_connections.txt" 2>&1
        fi
    elif [ "$OS_TYPE" = "FreeBSD" ]; then
        sockstat -46l > "${TEMP_STATE}/listening_ports.txt" 2>&1
        sockstat -46c > "${TEMP_STATE}/established_connections.txt" 2>&1
    elif [ "$OS_TYPE" = "OpenBSD" ]; then
        netstat -na -f inet | grep LISTEN > "${TEMP_STATE}/listening_ports.txt" 2>&1
        netstat -na -f inet | grep ESTABLISHED > "${TEMP_STATE}/established_connections.txt" 2>&1
    else
        if command -v netstat >/dev/null 2>&1; then
            netstat -na > "${TEMP_STATE}/network_connections.txt" 2>&1
        fi
    fi
    
    if [ "$OS_TYPE" = "Linux" ]; then
        if command -v ip >/dev/null 2>&1; then
            ip addr show > "${TEMP_STATE}/ip_addresses.txt" 2>&1
            ip route show > "${TEMP_STATE}/ip_routes.txt" 2>&1
            ip link show > "${TEMP_STATE}/ip_links.txt" 2>&1
        elif command -v ifconfig >/dev/null 2>&1; then
            ifconfig -a > "${TEMP_STATE}/ifconfig.txt" 2>&1
            route -n > "${TEMP_STATE}/routes.txt" 2>&1
        fi
    else
        ifconfig -a > "${TEMP_STATE}/ifconfig.txt" 2>&1
        netstat -rn > "${TEMP_STATE}/routes.txt" 2>&1
    fi
    
    if [ "$OS_TYPE" = "Linux" ]; then
        if command -v iptables >/dev/null 2>&1; then
            iptables -L -n -v --line-numbers > "${TEMP_STATE}/iptables_filter.txt" 2>&1
            iptables -t nat -L -n -v --line-numbers > "${TEMP_STATE}/iptables_nat.txt" 2>&1
            iptables -t mangle -L -n -v --line-numbers > "${TEMP_STATE}/iptables_mangle.txt" 2>&1
            iptables -t raw -L -n -v --line-numbers > "${TEMP_STATE}/iptables_raw.txt" 2>&1
            iptables-save > "${TEMP_STATE}/iptables_save.txt" 2>&1
        fi
        
        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -L -n -v --line-numbers > "${TEMP_STATE}/ip6tables_filter.txt" 2>&1
            ip6tables-save > "${TEMP_STATE}/ip6tables_save.txt" 2>&1
        fi
        
        if command -v getenforce >/dev/null 2>&1; then
            getenforce > "${TEMP_STATE}/selinux_mode.txt" 2>&1
        fi
        if command -v sestatus >/dev/null 2>&1; then
            sestatus > "${TEMP_STATE}/selinux_status.txt" 2>&1
        fi
        if command -v semanage >/dev/null 2>&1; then
            semanage boolean -l > "${TEMP_STATE}/selinux_booleans.txt" 2>&1
            semanage port -l > "${TEMP_STATE}/selinux_ports.txt" 2>&1
        fi
        
        if command -v aa-status >/dev/null 2>&1; then
            aa-status > "${TEMP_STATE}/apparmor_status.txt" 2>&1
        fi
    elif [ "$OS_TYPE" = "FreeBSD" ] || [ "$OS_TYPE" = "OpenBSD" ]; then
        if command -v pfctl >/dev/null 2>&1; then
            pfctl -sa > "${TEMP_STATE}/pf_rules.txt" 2>&1
        fi
        if command -v ipfw >/dev/null 2>&1; then
            ipfw list > "${TEMP_STATE}/ipfw_rules.txt" 2>&1
        fi
    fi
    
    if [ "$OS_TYPE" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --all > "${TEMP_STATE}/systemd_services.txt" 2>&1
        systemctl list-unit-files --type=service > "${TEMP_STATE}/systemd_service_files.txt" 2>&1
        systemctl list-units --type=socket --all > "${TEMP_STATE}/systemd_sockets.txt" 2>&1
        systemctl list-units --type=timer --all > "${TEMP_STATE}/systemd_timers.txt" 2>&1
    elif [ "$OS_TYPE" = "FreeBSD" ]; then
        service -e > "${TEMP_STATE}/services_enabled.txt" 2>&1
        if command -v sockstat >/dev/null 2>&1; then
            sockstat -46l > "${TEMP_STATE}/listening_services.txt" 2>&1
        fi
    elif [ "$OS_TYPE" = "OpenBSD" ]; then
        rcctl ls started > "${TEMP_STATE}/services_started.txt" 2>&1
        rcctl ls on > "${TEMP_STATE}/services_enabled.txt" 2>&1
    fi
    
    if command -v lsmod >/dev/null 2>&1; then
        lsmod > "${TEMP_STATE}/loaded_modules.txt" 2>&1
    elif command -v kldstat >/dev/null 2>&1; then
        kldstat > "${TEMP_STATE}/loaded_modules.txt" 2>&1
    fi

    sysctl -a > "${TEMP_STATE}/sysctl.txt" 2>&1
    
    last -F > "${TEMP_STATE}/last_logins.txt" 2>&1
    who > "${TEMP_STATE}/currently_logged_in.txt" 2>&1
    w > "${TEMP_STATE}/who_what.txt" 2>&1
    
    find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > "${TEMP_STATE}/suid_sgid_files.txt"
    
    ls -laR /etc 2>/dev/null > "${TEMP_STATE}/etc_permissions.txt"
    ls -la /bin /sbin /usr/bin /usr/sbin 2>/dev/null > "${TEMP_STATE}/bin_permissions.txt"
    find /etc -type f -perm /022 2>/dev/null > "${TEMP_STATE}/world_writable_etc.txt"
}

# Function to compare a single state file
compare_state_file() {
    filename="$1"
    description="$2"
    
    backup_file="${BACKUP_STATE}/${filename}"
    current_file="${TEMP_STATE}/${filename}"
    
    if [ ! -f "$backup_file" ] && [ ! -f "$current_file" ]; then
        return
    fi
    
    if [ ! -f "$backup_file" ]; then
        log_change "$description: NEW FILE (didn't exist in backup)"
        return
    fi
    
    if [ ! -f "$current_file" ]; then
        log_change "$description: FILE REMOVED (existed in backup)"
        return
    fi
    
    if ! diff -q "$backup_file" "$current_file" >/dev/null 2>&1; then
        log_change "$description"
        printf "${YELLOW}"
        diff -u "$backup_file" "$current_file" | head -n 100
        printf "${NC}"
        printf "\n"
    fi
}

# Function to compare configuration files
compare_config_file() {
    filepath="$1"
    backup_file="${BACKUP_FILES}${filepath}"
    
    if [ ! -f "$backup_file" ] && [ ! -f "$filepath" ]; then
        return 0
    fi
    
    if [ ! -f "$backup_file" ]; then
        log_change "$filepath: NEW FILE"
        return 1
    fi
    
    if [ ! -f "$filepath" ]; then
        log_change "$filepath: FILE REMOVED"
        return 1
    fi
    
    if ! diff -q "$backup_file" "$filepath" >/dev/null 2>&1; then
        log_change "$filepath"
        printf "${YELLOW}"
        diff -u "$backup_file" "$filepath" | head -n 100
        printf "${NC}"
        printf "\n"
        return 1
    fi
    
    return 0
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$TEMP_STATE"
}

trap cleanup EXIT

# Start comparison
log_section "SYSTEM STATE COMPARISON REPORT"

echo "Backup date: $(cat "${LATEST_BACKUP}/metadata.txt" | grep "Backup created" | cut -d: -f2-)"
echo "Current date: $(date)"
echo ""

# Capture current state
capture_current_state


# ============================================================================
# COMPARE CRITICAL CONFIGURATION FILES
# ============================================================================
log_section "CONFIGURATION FILE CHANGES"

log_info "Checking user and authentication files..."
compare_config_file /etc/passwd
compare_config_file /etc/group
compare_config_file /etc/sudoers

if [ "$OS_TYPE" = "Linux" ]; then
    compare_config_file /etc/shadow
elif [ "$OS_TYPE" = "FreeBSD" ] || [ "$OS_TYPE" = "OpenBSD" ] || [ "$OS_TYPE" = "NetBSD" ]; then
    compare_config_file /etc/master.passwd
    compare_config_file /etc/login.conf
fi

log_info "Checking SSH configuration..."
compare_config_file /etc/ssh/sshd_config

log_info "Checking important security files..."
compare_config_file /etc/login.defs
compare_config_file /etc/securetty

log_info "Checking network configuration..."
compare_config_file /etc/hosts
compare_config_file /etc/resolv.conf

if [ "$OS_TYPE" = "FreeBSD" ] || [ "$OS_TYPE" = "NetBSD" ]; then
    compare_config_file /etc/rc.conf
    compare_config_file /etc/rc.conf.local
elif [ "$OS_TYPE" = "OpenBSD" ]; then
    compare_config_file /etc/rc.conf
    compare_config_file /etc/rc.conf.local
    compare_config_file /etc/netstart
fi

# Check for new/removed files in sudoers.d
if [ -d /etc/sudoers.d ]; then
    if [ -d "${BACKUP_FILES}/etc/sudoers.d" ]; then
        for file in /etc/sudoers.d/*; do
            [ -e "$file" ] || continue
            filename=$(basename "$file")
            if [ ! -f "${BACKUP_FILES}/etc/sudoers.d/$filename" ]; then
                log_change "/etc/sudoers.d/$filename: NEW FILE"
            fi
        done
    fi
fi

# ============================================================================
# COMPARE SYSTEM STATE
# ============================================================================
log_section "FIREWALL RULES CHANGES"
compare_state_file "iptables_filter.txt" "iptables filter table"
compare_state_file "iptables_nat.txt" "iptables NAT table"
compare_state_file "iptables_save.txt" "iptables (full ruleset)"

if [ "$OS_TYPE" = "FreeBSD" ] || [ "$OS_TYPE" = "OpenBSD" ]; then
    compare_state_file "pf_rules.txt" "PF Rules"
    compare_state_file "ipfw_rules.txt" "IPFW Rules"
fi

log_section "LISTENING PORTS CHANGES"
compare_state_file "listening_ports.txt" "Open/Listening Ports"

log_section "NETWORK CONFIGURATION CHANGES"
compare_state_file "ip_addresses.txt" "IP Addresses"
compare_state_file "ip_routes.txt" "Routing Table"
compare_state_file "ifconfig.txt" "Interface Config (ifconfig)"
compare_state_file "routes.txt" "Routing Table (netstat)"

log_section "SELINUX CHANGES"
compare_state_file "selinux_mode.txt" "SELinux Mode"
compare_state_file "selinux_status.txt" "SELinux Status"
compare_state_file "selinux_booleans.txt" "SELinux Booleans"

log_section "APPARMOR CHANGES"
compare_state_file "apparmor_status.txt" "AppArmor Status"

log_section "SYSTEM SERVICES CHANGES"
compare_state_file "systemd_services.txt" "Running Services (Systemd)"
compare_state_file "systemd_service_files.txt" "Service Unit Files"
compare_state_file "services_enabled.txt" "Enabled Services (BSD)"
compare_state_file "services_started.txt" "Started Services (OpenBSD)"
compare_state_file "listening_services.txt" "Listening Services (FreeBSD)"

log_section "KERNEL MODULES CHANGES"
compare_state_file "loaded_modules.txt" "Loaded Kernel Modules"

log_section "KERNEL PARAMETERS CHANGES"
compare_state_file "sysctl.txt" "Kernel Parameters (sysctl)"

log_section "SUID/SGID FILES CHANGES"
compare_state_file "suid_sgid_files.txt" "SUID/SGID Files"

log_section "FILE PERMISSIONS CHANGES"
compare_state_file "etc_permissions.txt" "/etc Directory Permissions"
compare_state_file "world_writable_etc.txt" "World-writable files in /etc"


log_info "Comparison complete!"

exit 0