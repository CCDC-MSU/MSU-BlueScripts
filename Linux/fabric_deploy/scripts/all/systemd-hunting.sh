#!/bin/bash
#
# systemd_security_audit.sh - Comprehensive systemd unit file security scanner
# Designed for incident response on potentially compromised systems
#
# Checks performed:
#  1. Units running as root (especially network-facing)
#  2. Recently modified unit files (persistence indicators)
#  3. Execution from suspicious paths (/tmp, /dev/shm, etc.)
#  4. Obfuscated or encoded commands
#  5. Remote content download/execution
#  6. Suspicious timers (high-frequency, orphaned)
#  7. Socket units (network persistence)
#  8. Path units (filesystem triggers)
#  9. Malicious symlinks
# 10. World-writable unit files
# 11. Units in user-writable locations
# 12. Suspicious environment variables (LD_PRELOAD, etc.)
# 13. Unkillable services (KillMode=none)
# 14. Excessive/dangerous capabilities
# 15. Privileged supplementary groups
# 16. Missing security hardening
#
# Usage: ./systemd_security_audit.sh [log_file]
# Default log: /var/log/systemd_audit_$(date +%Y%m%d_%H%M%S).log

set -euo pipefail

# Configuration
LOG_FILE="${1:-/var/log/systemd_audit_$(date +%Y%m%d_%H%M%S).log}"
SUSPICIOUS_PATHS=("/tmp" "/dev/shm" "/var/tmp" "/home" "/root")
DAYS_RECENT=7  # Consider files modified in last N days as "recent"

# Colors for terminal output (stripped in log file)
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Systemd unit file locations
UNIT_LOCATIONS=(
    "/etc/systemd/system"
    "/run/systemd/system"
    "/usr/lib/systemd/system"
    "/lib/systemd/system"
    "/usr/local/lib/systemd/system"
    "/etc/systemd/user"
    "/run/systemd/user"
    "/usr/lib/systemd/user"
    "/home/*/.config/systemd/user"
)

# Initialize log
init_log() {
    {
        echo "=========================================="
        echo "Systemd Security Audit Report"
        echo "=========================================="
        echo "Timestamp: $(date)"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo "Log file: $LOG_FILE"
        echo "=========================================="
        echo ""
    } | tee "$LOG_FILE"
}

# Logging function
log() {
    local level=$1
    shift
    local msg="$*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" | tee -a "$LOG_FILE"
}

# Find all systemd unit files
find_unit_files() {
    local files=()
    for loc in "${UNIT_LOCATIONS[@]}"; do
        # Expand wildcards and check if directory exists
        for expanded_loc in $loc; do
            if [[ -d "$expanded_loc" ]]; then
                while IFS= read -r -d '' file; do
                    files+=("$file")
                done < <(find "$expanded_loc" -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" -o -name "*.path" -o -name "*.mount" \) -print0 2>/dev/null)
            fi
        done
    done
    printf '%s\n' "${files[@]}" | sort -u
}

# Check 1: Units running as root or with elevated privileges
check_root_execution() {
    log "INFO" "Checking for units running as root..."
    local count=0
    
    while IFS= read -r unit; do
        local user=$(grep -E "^User=" "$unit" 2>/dev/null | cut -d= -f2)
        local no_user=$(grep -qE "^User=" "$unit" 2>/dev/null && echo "no" || echo "yes")
        
        # If no User= directive, it runs as root (or the user who starts it)
        if [[ "$no_user" == "yes" ]] || [[ "$user" == "root" ]] || [[ "$user" == "0" ]]; then
            # Check if it's a network-facing service
            local network=$(grep -E "^(After|Wants|Requires)=.*network" "$unit" 2>/dev/null)
            local sockets=$(grep -E "^(ListenStream|ListenDatagram)" "$unit" 2>/dev/null)
            
            if [[ -n "$network" ]] || [[ -n "$sockets" ]]; then
                log "CRITICAL" "Network-facing service running as root: $unit"
                ((count++))
            else
                log "WARNING" "Service running as root: $unit"
                ((count++))
            fi
        fi
    done < <(find_unit_files | grep "\.service$")
    
    log "INFO" "Found $count units running as root"
    echo ""
}

# Check 2: Recently modified/created unit files (potential persistence)
check_recent_modifications() {
    log "INFO" "Checking for recently modified unit files (last $DAYS_RECENT days)..."
    local count=0
    
    while IFS= read -r unit; do
        if [[ -n "$unit" ]]; then
            local mod_time=$(stat -c %Y "$unit" 2>/dev/null || stat -f %m "$unit" 2>/dev/null)
            local current_time=$(date +%s)
            local days_old=$(( (current_time - mod_time) / 86400 ))
            
            if [[ $days_old -le $DAYS_RECENT ]]; then
                log "WARNING" "Recently modified ($days_old days ago): $unit"
                log "INFO" "  Last modified: $(stat -c %y "$unit" 2>/dev/null || stat -f %Sm "$unit" 2>/dev/null)"
                ((count++))
            fi
        fi
    done < <(find_unit_files)
    
    log "INFO" "Found $count recently modified units"
    echo ""
}

# Check 3: Units executing from suspicious paths
check_suspicious_paths() {
    log "INFO" "Checking for units executing from suspicious paths..."
    local count=0
    
    while IFS= read -r unit; do
        for susp_path in "${SUSPICIOUS_PATHS[@]}"; do
            if grep -qE "^Exec(Start|StartPre|StartPost|Stop|Reload)=.*$susp_path" "$unit" 2>/dev/null; then
                log "CRITICAL" "Unit executing from suspicious path ($susp_path): $unit"
                local exec_lines=$(grep -E "^Exec(Start|StartPre|StartPost|Stop|Reload)=" "$unit" 2>/dev/null)
                log "INFO" "  Commands: $exec_lines"
                ((count++))
                break
            fi
        done
    done < <(find_unit_files)
    
    log "INFO" "Found $count units with suspicious execution paths"
    echo ""
}

# Check 4: Units with obfuscated or encoded commands
check_obfuscated_commands() {
    log "INFO" "Checking for obfuscated or suspicious commands..."
    local count=0
    
    while IFS= read -r unit; do
        # Check for base64, hex encoding, curl/wget with pipes, eval, etc.
        if grep -qE "^Exec.*\|(bash|sh|python|perl|php)" "$unit" 2>/dev/null || \
           grep -qE "^Exec.*(base64|xxd|eval|exec|\$\(|\\x[0-9a-f]{2})" "$unit" 2>/dev/null || \
           grep -qE "^Exec.*(curl|wget|nc|netcat|ncat).*\|" "$unit" 2>/dev/null; then
            log "CRITICAL" "Potentially obfuscated/malicious command in: $unit"
            local exec_lines=$(grep -E "^Exec" "$unit" 2>/dev/null)
            log "INFO" "  Commands: $exec_lines"
            ((count++))
        fi
    done < <(find_unit_files)
    
    log "INFO" "Found $count units with suspicious command patterns"
    echo ""
}

# Check 5: Units downloading remote content
check_remote_execution() {
    log "INFO" "Checking for units downloading/executing remote content..."
    local count=0
    
    while IFS= read -r unit; do
        if grep -qE "^Exec.*(curl|wget|fetch|ftp).*http" "$unit" 2>/dev/null; then
            log "CRITICAL" "Unit downloading remote content: $unit"
            local exec_lines=$(grep -E "^Exec.*(curl|wget|fetch)" "$unit" 2>/dev/null)
            log "INFO" "  Commands: $exec_lines"
            ((count++))
        fi
    done < <(find_unit_files)
    
    log "INFO" "Found $count units downloading remote content"
    echo ""
}

# Check 6: Missing security hardening options
check_hardening() {
    log "INFO" "Checking for units without security hardening..."
    local count=0
    
    while IFS= read -r unit; do
        local missing=()
        
        # Check for important hardening directives
        grep -q "^NoNewPrivileges=true" "$unit" 2>/dev/null || missing+=("NoNewPrivileges")
        grep -q "^PrivateTmp=true" "$unit" 2>/dev/null || missing+=("PrivateTmp")
        grep -q "^ProtectSystem=" "$unit" 2>/dev/null || missing+=("ProtectSystem")
        grep -q "^ProtectHome=" "$unit" 2>/dev/null || missing+=("ProtectHome")
        grep -q "^ReadOnlyPaths=" "$unit" 2>/dev/null || missing+=("ReadOnlyPaths")
        
        if [[ ${#missing[@]} -ge 4 ]]; then
            log "WARNING" "Unit lacks security hardening: $unit"
            log "INFO" "  Missing: ${missing[*]}"
            ((count++))
        fi
    done < <(find_unit_files | grep "\.service$")
    
    log "INFO" "Found $count units with insufficient hardening"
    echo ""
}

# Check 7: Suspicious timers
check_suspicious_timers() {
    log "INFO" "Checking for suspicious timers..."
    local count=0
    
    while IFS= read -r timer; do
        local service_name=$(basename "$timer" .timer)
        local service_file="${timer%.timer}.service"
        
        # Check if corresponding service exists
        if [[ ! -f "$service_file" ]]; then
            log "WARNING" "Timer without corresponding service: $timer"
            ((count++))
        fi
        
        # Check for very frequent timers (potential DoS or polling)
        if grep -qE "OnCalendar=.*\*(:[0-5]?[0-9]|minutely)" "$timer" 2>/dev/null || \
           grep -qE "OnUnitActiveSec=[0-9]+s" "$timer" 2>/dev/null; then
            log "WARNING" "High-frequency timer detected: $timer"
            local timing=$(grep -E "On(Calendar|UnitActiveSec|BootSec)=" "$timer" 2>/dev/null)
            log "INFO" "  Timing: $timing"
            ((count++))
        fi
    done < <(find_unit_files | grep "\.timer$")
    
    log "INFO" "Found $count suspicious timers"
    echo ""
}

# Check 8: Socket units (can be used for persistence)
check_socket_units() {
    log "INFO" "Checking socket units..."
    local count=0
    
    while IFS= read -r socket; do
        log "INFO" "Socket unit found: $socket"
        local listen=$(grep -E "^Listen" "$socket" 2>/dev/null)
        log "INFO" "  Listening on: $listen"
        ((count++))
    done < <(find_unit_files | grep "\.socket$")
    
    log "INFO" "Found $count socket units (review for legitimacy)"
    echo ""
}

# Check 9: Path units (can trigger on file system events)
check_path_units() {
    log "INFO" "Checking path units..."
    local count=0
    
    while IFS= read -r path; do
        log "INFO" "Path unit found: $path"
        local watched=$(grep -E "^Path" "$path" 2>/dev/null)
        log "INFO" "  Watching: $watched"
        ((count++))
    done < <(find_unit_files | grep "\.path$")
    
    log "INFO" "Found $count path units (review for legitimacy)"
    echo ""
}

# Check 10: Symlinks to unexpected locations
check_symlinks() {
    log "INFO" "Checking for suspicious symlinks..."
    local count=0
    
    for loc in "${UNIT_LOCATIONS[@]}"; do
        for expanded_loc in $loc; do
            if [[ -d "$expanded_loc" ]]; then
                while IFS= read -r -d '' link; do
                    local target=$(readlink -f "$link" 2>/dev/null)
                    
                    # Check if symlink points outside expected systemd directories
                    if [[ ! "$target" =~ ^/usr/(lib|local/lib)/systemd ]] && \
                       [[ ! "$target" =~ ^/lib/systemd ]] && \
                       [[ ! "$target" =~ ^/etc/systemd ]]; then
                        log "WARNING" "Symlink to unusual location: $link -> $target"
                        ((count++))
                    fi
                done < <(find "$expanded_loc" -type l -print0 2>/dev/null)
            fi
        done
    done
    
    log "INFO" "Found $count suspicious symlinks"
    echo ""
}

# Check 11: Units with world-writable components
check_permissions() {
    log "INFO" "Checking for world-writable unit files..."
    local count=0
    
    while IFS= read -r unit; do
        local perms=$(stat -c %a "$unit" 2>/dev/null || stat -f %Lp "$unit" 2>/dev/null)
        
        # Check if world-writable (last digit is 2, 3, 6, or 7)
        if [[ "$perms" =~ [2367]$ ]]; then
            log "CRITICAL" "World-writable unit file: $unit (permissions: $perms)"
            ((count++))
        fi
    done < <(find_unit_files)
    
    log "INFO" "Found $count world-writable unit files"
    echo ""
}

# Check 12: Units in user-writable directories
check_user_writable_locations() {
    log "INFO" "Checking for units in user-writable locations..."
    local count=0
    
    while IFS= read -r unit; do
        if [[ "$unit" =~ ^/home/ ]] || [[ "$unit" =~ ^/tmp/ ]] || [[ "$unit" =~ ^/var/tmp/ ]]; then
            log "CRITICAL" "Unit in user-writable location: $unit"
            ((count++))
        fi
    done < <(find_unit_files)
    
    log "INFO" "Found $count units in user-writable locations"
    echo ""
}

# Check 13: Suspicious environment variables
check_environment_variables() {
    log "INFO" "Checking for suspicious environment variables..."
    local count=0
    local suspicious_vars=("LD_PRELOAD" "LD_LIBRARY_PATH" "LD_AUDIT" "PYTHONPATH" "PERL5LIB" "NODE_PATH" "GEM_PATH" "RUBYLIB")
    
    while IFS= read -r unit; do
        local env_lines=$(grep -E "^Environment=" "$unit" 2>/dev/null)
        
        if [[ -n "$env_lines" ]]; then
            for var in "${suspicious_vars[@]}"; do
                if echo "$env_lines" | grep -qE "${var}="; then
                    log "CRITICAL" "Suspicious environment variable ($var) in: $unit"
                    log "INFO" "  Environment: $env_lines"
                    ((count++))
                    break
                fi
            done
        fi
        
        # Check for EnvironmentFile pointing to suspicious locations
        local env_file=$(grep -E "^EnvironmentFile=" "$unit" 2>/dev/null)
        if [[ -n "$env_file" ]]; then
            for susp_path in "${SUSPICIOUS_PATHS[@]}"; do
                if echo "$env_file" | grep -q "$susp_path"; then
                    log "CRITICAL" "EnvironmentFile in suspicious location: $unit"
                    log "INFO" "  $env_file"
                    ((count++))
                    break
                fi
            done
        fi
    done < <(find_unit_files | grep "\.service$")
    
    log "INFO" "Found $count units with suspicious environment variables"
    echo ""
}

# Check 14: KillMode=none (unkillable services)
check_kill_mode() {
    log "INFO" "Checking for unkillable services (KillMode=none)..."
    local count=0
    
    while IFS= read -r unit; do
        if grep -qE "^KillMode=none" "$unit" 2>/dev/null; then
            log "CRITICAL" "Service cannot be stopped (KillMode=none): $unit"
            
            # Check if it also has Restart directives
            local restart=$(grep -E "^Restart=" "$unit" 2>/dev/null)
            if [[ -n "$restart" ]]; then
                log "INFO" "  WARNING: Also has restart directive: $restart"
            fi
            ((count++))
        fi
    done < <(find_unit_files | grep "\.service$")
    
    log "INFO" "Found $count unkillable services"
    echo ""
}

# Check 15: Excessive or dangerous capabilities
check_capabilities() {
    log "INFO" "Checking for excessive capabilities..."
    local count=0
    local dangerous_caps=("CAP_SYS_ADMIN" "CAP_SYS_MODULE" "CAP_SYS_RAWIO" "CAP_SYS_PTRACE" "CAP_DAC_OVERRIDE" "CAP_DAC_READ_SEARCH" "CAP_SETUID" "CAP_SETGID" "CAP_NET_ADMIN" "CAP_NET_RAW")
    
    while IFS= read -r unit; do
        # Check AmbientCapabilities
        local ambient_caps=$(grep -E "^AmbientCapabilities=" "$unit" 2>/dev/null)
        if [[ -n "$ambient_caps" ]]; then
            for cap in "${dangerous_caps[@]}"; do
                if echo "$ambient_caps" | grep -qE "$cap"; then
                    log "CRITICAL" "Dangerous ambient capability ($cap) in: $unit"
                    log "INFO" "  $ambient_caps"
                    ((count++))
                    break
                fi
            done
        fi
        
        # Check CapabilityBoundingSet (should restrict, not grant)
        local cap_bounding=$(grep -E "^CapabilityBoundingSet=" "$unit" 2>/dev/null)
        if [[ -n "$cap_bounding" ]]; then
            # If it's NOT using '~' to remove capabilities, it might be granting them
            if [[ ! "$cap_bounding" =~ CapabilityBoundingSet=~ ]]; then
                for cap in "${dangerous_caps[@]}"; do
                    if echo "$cap_bounding" | grep -qE "$cap"; then
                        log "WARNING" "Explicit capability in bounding set ($cap): $unit"
                        log "INFO" "  $cap_bounding"
                        ((count++))
                        break
                    fi
                done
            fi
        fi
        
        # Check for SecureBits that might weaken security
        local secure_bits=$(grep -E "^SecureBits=" "$unit" 2>/dev/null)
        if echo "$secure_bits" | grep -qE "(noroot|noroot-locked)"; then
            log "WARNING" "SecureBits modifying root behavior: $unit"
            log "INFO" "  $secure_bits"
        fi
    done < <(find_unit_files | grep "\.service$")
    
    log "INFO" "Found $count units with concerning capabilities"
    echo ""
}

# Check 16: Suspicious supplementary groups
check_supplementary_groups() {
    log "INFO" "Checking for suspicious supplementary groups..."
    local count=0
    local privileged_groups=("root" "wheel" "sudo" "admin" "docker" "lxd" "disk" "shadow" "adm" "sys" "kmem" "tty" "audio" "video" "plugdev")
    
    while IFS= read -r unit; do
        local supp_groups=$(grep -E "^SupplementaryGroups=" "$unit" 2>/dev/null)
        
        if [[ -n "$supp_groups" ]]; then
            # Extract group names from the directive
            local groups=$(echo "$supp_groups" | sed 's/SupplementaryGroups=//' | tr ' ' '\n')
            
            for group in $groups; do
                for priv_group in "${privileged_groups[@]}"; do
                    if [[ "$group" == "$priv_group" ]]; then
                        log "CRITICAL" "Service granted privileged group ($priv_group): $unit"
                        log "INFO" "  $supp_groups"
                        
                        # Check what user this service runs as
                        local user=$(grep -E "^User=" "$unit" 2>/dev/null | cut -d= -f2)
                        if [[ -z "$user" ]] || [[ "$user" == "root" ]]; then
                            log "INFO" "  Running as: root (default)"
                        else
                            log "INFO" "  Running as: $user"
                        fi
                        ((count++))
                        break 2
                    fi
                done
            done
        fi
    done < <(find_unit_files | grep "\.service$")
    
    log "INFO" "Found $count units with privileged supplementary groups"
    echo ""
}

# Summary report
generate_summary() {
    log "INFO" "=========================================="
    log "INFO" "Audit Complete"
    log "INFO" "=========================================="
    log "INFO" "Full report saved to: $LOG_FILE"
    log "INFO" ""
    log "INFO" "NEXT STEPS:"
    log "INFO" "1. Review all CRITICAL findings immediately"
    log "INFO" "2. Investigate recently modified units"
    log "INFO" "3. Verify legitimacy of network-facing root services"
    log "INFO" "4. Check enabled units: systemctl list-unit-files --state=enabled"
    log "INFO" "5. Review active timers: systemctl list-timers --all"
    log "INFO" "6. Check for masked units: systemctl list-unit-files --state=masked"
}

# Main execution
main() {
    # Check if running with sufficient privileges
    if [[ $EUID -ne 0 ]]; then
        echo "WARNING: Not running as root. Some checks may be incomplete."
        echo "Press Enter to continue or Ctrl+C to abort..."
        read -r
    fi
    
    # Check if systemd is available
    if ! command -v systemctl &> /dev/null; then
        echo "ERROR: systemd not found on this system"
        exit 1
    fi
    
    init_log
    
    check_root_execution
    check_recent_modifications
    check_suspicious_paths
    check_obfuscated_commands
    check_remote_execution
    check_suspicious_timers
    check_socket_units
    check_path_units
    check_symlinks
    check_permissions
    check_user_writable_locations
    check_environment_variables
    check_kill_mode
    check_capabilities
    check_supplementary_groups
    check_hardening
    
    generate_summary
}

# Run main function
main "$@"