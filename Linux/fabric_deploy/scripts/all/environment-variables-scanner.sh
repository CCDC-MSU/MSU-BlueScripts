#!/bin/sh
# Environment Variable Threat Hunting Script
# POSIX compliant - detects suspicious environment variables
# Usage: sudo ./env_threat_hunter.sh [options]

set -u

# Color codes (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    YELLOW=''
    GREEN=''
    BLUE=''
    NC=''
fi

# Suspicious environment variables to check
SUSPICIOUS_VARS="LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_VERSIONED_LIBRARY_PATH PYTHONPATH PERL5LIB PERLLIB RUBYLIB NODE_PATH JAVA_TOOL_OPTIONS _JAVA_OPTIONS PROMPT_COMMAND BASH_ENV ENV"

# Additional suspicious patterns
SUSPICIOUS_PATHS="/tmp /var/tmp /dev/shm /dev/mqueue .hidden"

log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_alert() {
    printf "${RED}[ALERT]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_warn "Not running as root. Some processes may not be accessible."
        log_warn "Run with sudo for complete scanning."
    fi
}

# Scan running processes
# Scan running processes
scan_processes() {
    log_info "Scanning running processes for suspicious environment variables..."
    printf "\n"
    
    found_count=0
    
    OS_TYPE=$(uname)
    
    if [ "$OS_TYPE" = "Linux" ]; then
        scan_processes_linux
    elif [ "$OS_TYPE" = "FreeBSD" ]; then
        scan_processes_freebsd
    else
        log_warn "Process scanning not fully supported on $OS_TYPE"
        # Attempt generic scanning if possible or skip
    fi
    
    if [ "$found_count" -eq 0 ]; then
        log_success "No suspicious environment variables found in running processes"
    else
        log_alert "Found $found_count suspicious environment variable(s) in running processes"
    fi
    printf "\n"
}

scan_processes_linux() {
    total_procs=0
    
    for proc_dir in /proc/[0-9]*; do
        [ -d "$proc_dir" ] || continue
        
        pid="${proc_dir##*/}"
        environ_file="$proc_dir/environ"
        cmdline_file="$proc_dir/cmdline"
        
        # Skip if we can't read the environ file
        [ -r "$environ_file" ] || continue
        
        total_procs=$((total_procs + 1))
        
        # Read command line
        if [ -r "$cmdline_file" ]; then
            cmdline=$(tr '\0' ' ' < "$cmdline_file" 2>/dev/null | cut -c1-100)
        else
            cmdline="<unavailable>"
        fi
        
        # Read process owner
        if [ -r "$proc_dir/status" ]; then
            proc_user=$(awk '/^Uid:/ {print $2}' "$proc_dir/status" 2>/dev/null)
            proc_user=$(getent passwd "$proc_user" 2>/dev/null | cut -d: -f1)
            [ -z "$proc_user" ] && proc_user="<unknown>"
        else
            proc_user="<unknown>"
        fi
        
        # Check each suspicious variable
        for var in $SUSPICIOUS_VARS; do
            # Use grep -z for null-separated environ
            if value=$(grep -z "^${var}=" "$environ_file" 2>/dev/null | tr '\0' '\n'); then
                check_suspicious_var "$pid" "$proc_user" "$var" "${value#*=}" "$cmdline"
            fi
        done
    done
    
    log_info "Scanned $total_procs Linux processes"
}

scan_processes_freebsd() {
    total_procs=0
    
    # Check if procstat is available
    if ! command -v procstat >/dev/null 2>&1; then
        log_warn "procstat not found. Required for scanning processes on FreeBSD."
        return
    fi
    
    # Iterate over all PIDs using ps
    for pid in $(ps -ax -o pid | grep -v PID); do
        total_procs=$((total_procs + 1))
        
        # Get process info
        proc_user=$(ps -o user -p "$pid" | tail -n 1)
        cmdline=$(ps -o command -p "$pid" | tail -n 1 | cut -c1-100)
        
        # Get environment using procstat -e
        # procstat -e output format: PID  ENV  KEY  VALUE (approximately, usually:  PID  VAR  VALUE)
        # We need to parse this carefully
        
        # Fetch environment for the PID
        # Output looks like: "  PID COMM             ENVIRONMENT"
        #                    "12345 sh               HOME=/home/user"
        # It's cleaner to capture the output block
        
        env_output=$(procstat -e "$pid" 2>/dev/null)
        
        for var in $SUSPICIOUS_VARS; do
            # Grep for the variable assignment in procstat output
            # Look for line ending with variable definition
            if value=$(echo "$env_output" | grep "[[:space:]]${var}="); then
                # Extract value. procstat format: PID COMM VAR=VAL
                # We can try to extract everything after VAR=
                value_content=$(echo "$value" | sed "s/.*[[:space:]]${var}=//")
                
                check_suspicious_var "$pid" "$proc_user" "$var" "$value_content" "$cmdline"
            fi
        done
    done
    
    log_info "Scanned $total_procs FreeBSD processes (via procstat)"
}

check_suspicious_var() {
    local pid="$1"
    local user="$2"
    local var="$3"
    local value="$4"
    local cmd="$5"
    
    [ -z "$value" ] && return
    
    # Alert on finding
    log_alert "Suspicious environment variable detected!"
    printf "  ${YELLOW}PID:${NC} %s\n" "$pid"
    printf "  ${YELLOW}User:${NC} %s\n" "$user"
    printf "  ${YELLOW}Variable:${NC} %s\n" "$var"
    printf "  ${YELLOW}Value:${NC} %s\n" "$value"
    printf "  ${YELLOW}Command:${NC} %s\n" "$cmd"
    
    # Check if value contains suspicious paths
    for susp_path in $SUSPICIOUS_PATHS; do
        if echo "$value" | grep -q "$susp_path"; then
            log_alert "  ⚠ Value contains suspicious path: $susp_path"
        fi
    done
    
    printf "\n"
    found_count=$((found_count + 1))
}


# Scan system-wide environment files
scan_system_files() {
    log_info "Scanning system-wide environment configuration files..."
    printf "\n"
    
    found_count=0
    
    # List of system files to check
    system_files="/etc/environment /etc/profile /etc/bash.bashrc /etc/zsh/zshenv /etc/zsh/zprofile"
    
    for file in $system_files; do
        [ -f "$file" ] || continue
        
        for var in $SUSPICIOUS_VARS; do
            if grep -n "^[[:space:]]*export[[:space:]]*${var}=" "$file" 2>/dev/null || \
               grep -n "^[[:space:]]*${var}=" "$file" 2>/dev/null; then
                log_alert "Suspicious variable in system file!"
                printf "  ${YELLOW}File:${NC} %s\n" "$file"
                printf "  ${YELLOW}Variable:${NC} %s\n" "$var"
                printf "  ${YELLOW}Content:${NC}\n"
                grep -n "${var}=" "$file" 2>/dev/null | sed 's/^/    /'
                printf "\n"
                found_count=$((found_count + 1))
            fi
        done
    done
    
    # Check /etc/profile.d/ directory
    if [ -d /etc/profile.d ]; then
        for file in /etc/profile.d/*.sh; do
            [ -f "$file" ] || continue
            
            for var in $SUSPICIOUS_VARS; do
                if grep -n "${var}=" "$file" 2>/dev/null | grep -qv '^[[:space:]]*#'; then
                    log_alert "Suspicious variable in profile.d script!"
                    printf "  ${YELLOW}File:${NC} %s\n" "$file"
                    printf "  ${YELLOW}Variable:${NC} %s\n" "$var"
                    printf "  ${YELLOW}Content:${NC}\n"
                    grep -n "${var}=" "$file" 2>/dev/null | sed 's/^/    /'
                    printf "\n"
                    found_count=$((found_count + 1))
                fi
            done
        done
    fi
    
    if [ "$found_count" -eq 0 ]; then
        log_success "No suspicious environment variables found in system files"
    else
        log_alert "Found $found_count suspicious environment variable(s) in system files"
    fi
    printf "\n"
}

# Scan user home directories
scan_user_homes() {
    log_info "Scanning user home directory configuration files..."
    printf "\n"
    
    found_count=0
    
    # User shell config files to check
    user_files=".profile .bashrc .bash_profile .zshrc .zshenv .zprofile .bash_login"
    
    # Get list of users with home directories
    while IFS=: read -r username _ _ _ _ homedir _; do
        [ -d "$homedir" ] || continue
        [ "$homedir" = "/" ] && continue
        
        for config in $user_files; do
            file="$homedir/$config"
            [ -f "$file" ] || continue
            
            for var in $SUSPICIOUS_VARS; do
                if grep -n "${var}=" "$file" 2>/dev/null | grep -qv '^[[:space:]]*#'; then
                    log_alert "Suspicious variable in user config!"
                    printf "  ${YELLOW}User:${NC} %s\n" "$username"
                    printf "  ${YELLOW}File:${NC} %s\n" "$file"
                    printf "  ${YELLOW}Variable:${NC} %s\n" "$var"
                    printf "  ${YELLOW}Content:${NC}\n"
                    grep -n "${var}=" "$file" 2>/dev/null | sed 's/^/    /'
                    printf "\n"
                    found_count=$((found_count + 1))
                fi
            done
        done
    done < /etc/passwd
    
    if [ "$found_count" -eq 0 ]; then
        log_success "No suspicious environment variables found in user config files"
    else
        log_alert "Found $found_count suspicious environment variable(s) in user config files"
    fi
    printf "\n"
}

# Scan systemd service files
scan_systemd_services() {
    log_info "Scanning systemd service files..."
    printf "\n"
    
    found_count=0
    
    # Check if systemd exists
    if ! command -v systemctl >/dev/null 2>&1; then
        log_info "Systemd not found, skipping service file scan"
        return
    fi
    
    # Directories to check
    service_dirs="/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system"
    
    for dir in $service_dirs; do
        [ -d "$dir" ] || continue
        
        find "$dir" -type f -name "*.service" 2>/dev/null | while read -r file; do
            for var in $SUSPICIOUS_VARS; do
                if grep -n "Environment=\"\?${var}=" "$file" 2>/dev/null; then
                    log_alert "Suspicious variable in systemd service!"
                    printf "  ${YELLOW}File:${NC} %s\n" "$file"
                    printf "  ${YELLOW}Variable:${NC} %s\n" "$var"
                    printf "  ${YELLOW}Content:${NC}\n"
                    grep -n "Environment=.*${var}=" "$file" 2>/dev/null | sed 's/^/    /'
                    printf "\n"
                    found_count=$((found_count + 1))
                fi
            done
        done
    done
    
    if [ "$found_count" -eq 0 ]; then
        log_success "No suspicious environment variables found in systemd services"
    else
        log_alert "Found $found_count suspicious environment variable(s) in systemd services"
    fi
    printf "\n"
}

# Main execution
main() {
    printf "\n"
    log_info "=== Environment Variable Threat Hunter ==="
    log_info "Starting scan at $(date)"
    printf "\n"
    
    check_root
    printf "\n"
    
    # Run all scans
    scan_processes
    scan_system_files
    scan_user_homes
    scan_systemd_services
    
    log_info "=== Scan Complete ==="
    log_info "Finished at $(date)"
    printf "\n"
}

# Run main function
main "$@"