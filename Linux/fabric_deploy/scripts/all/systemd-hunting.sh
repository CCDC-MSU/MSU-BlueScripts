#!/bin/sh
#
# systemd_security_audit.sh - Comprehensive systemd unit file security scanner
# Designed for incident response on potentially compromised systems
# POSIX-compatible version (works with sh, ash, dash, etc.)
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

set -eu

# Configuration
LOG_FILE="${1:-/var/log/systemd_audit_$(date +%Y%m%d_%H%M%S).log}"
SUSPICIOUS_PATHS="/tmp /dev/shm /var/tmp /home /root"
DAYS_RECENT=7  # Consider files modified in last N days as "recent"

# Colors for terminal output (stripped in log file)
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Systemd unit file locations (space-separated)
UNIT_LOCATIONS="/etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system /usr/local/lib/systemd/system /etc/systemd/user /run/systemd/user /usr/lib/systemd/user"

# Temporary file for unit list
UNIT_LIST_FILE=""

# Cleanup function
cleanup() {
    if [ -n "$UNIT_LIST_FILE" ] && [ -f "$UNIT_LIST_FILE" ]; then
        rm -f "$UNIT_LIST_FILE"
    fi
}

trap cleanup EXIT INT TERM

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
    level=$1
    shift
    msg="$*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" | tee -a "$LOG_FILE"
}

# Find all systemd unit files and store in temp file
find_unit_files() {
    UNIT_LIST_FILE=$(mktemp)
    
    for loc in $UNIT_LOCATIONS; do
        if [ -d "$loc" ]; then
            find "$loc" -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" -o -name "*.path" -o -name "*.mount" \) 2>/dev/null
        fi
    done | sort -u > "$UNIT_LIST_FILE"
    
    # Also check user directories
    for user_dir in /home/*/.config/systemd/user; do
        if [ -d "$user_dir" ]; then
            find "$user_dir" -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" -o -name "*.path" -o -name "*.mount" \) 2>/dev/null
        fi
    done >> "$UNIT_LIST_FILE" 2>/dev/null || true
    
    sort -u "$UNIT_LIST_FILE" -o "$UNIT_LIST_FILE"
}

# Get unit files filtered by extension
get_units_by_ext() {
    ext="$1"
    grep "\.${ext}\$" "$UNIT_LIST_FILE" 2>/dev/null || true
}

# Check if string contains substring
contains() {
    string="$1"
    substring="$2"
    case "$string" in
        *"$substring"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Check if string matches pattern (using grep)
matches_pattern() {
    echo "$1" | grep -qE "$2" 2>/dev/null
}

# Get file modification time in seconds since epoch (portable)
get_mod_time() {
    file="$1"
    # Try GNU stat first, then BSD stat
    stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null || echo 0
}

# Get human-readable modification time
get_mod_time_human() {
    file="$1"
    stat -c %y "$file" 2>/dev/null || stat -f %Sm "$file" 2>/dev/null || echo "unknown"
}

# Get file permissions (portable)
get_permissions() {
    file="$1"
    stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file" 2>/dev/null || echo "000"
}

# Check 1: Units running as root or with elevated privileges
check_root_execution() {
    log "INFO" "Checking for units running as root..."
    count=0
    
    get_units_by_ext "service" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        user=$(grep -E "^User=" "$unit" 2>/dev/null | cut -d= -f2 || true)
        has_user=$(grep -qE "^User=" "$unit" 2>/dev/null && echo "yes" || echo "no")
        
        # If no User= directive, it runs as root (or the user who starts it)
        if [ "$has_user" = "no" ] || [ "$user" = "root" ] || [ "$user" = "0" ]; then
            # Check if it's a network-facing service
            network=$(grep -E "^(After|Wants|Requires)=.*network" "$unit" 2>/dev/null || true)
            sockets=$(grep -E "^(ListenStream|ListenDatagram)" "$unit" 2>/dev/null || true)
            
            if [ -n "$network" ] || [ -n "$sockets" ]; then
                log "CRITICAL" "Network-facing service running as root: $unit"
                count=$((count + 1))
            else
                log "WARNING" "Service running as root: $unit"
                count=$((count + 1))
            fi
        fi
    done
    
    log "INFO" "Completed root execution check"
    echo ""
}

# Check 2: Recently modified/created unit files (potential persistence)
check_recent_modifications() {
    log "INFO" "Checking for recently modified unit files (last $DAYS_RECENT days)..."
    count=0
    current_time=$(date +%s)
    
    cat "$UNIT_LIST_FILE" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        mod_time=$(get_mod_time "$unit")
        if [ "$mod_time" != "0" ]; then
            days_old=$(( (current_time - mod_time) / 86400 ))
            
            if [ "$days_old" -le "$DAYS_RECENT" ]; then
                log "WARNING" "Recently modified ($days_old days ago): $unit"
                log "INFO" "  Last modified: $(get_mod_time_human "$unit")"
                count=$((count + 1))
            fi
        fi
    done
    
    log "INFO" "Completed recent modifications check"
    echo ""
}

# Check 3: Units executing from suspicious paths
check_suspicious_paths() {
    log "INFO" "Checking for units executing from suspicious paths..."
    count=0
    
    cat "$UNIT_LIST_FILE" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        for susp_path in $SUSPICIOUS_PATHS; do
            if grep -qE "^Exec(Start|StartPre|StartPost|Stop|Reload)=.*${susp_path}" "$unit" 2>/dev/null; then
                log "CRITICAL" "Unit executing from suspicious path ($susp_path): $unit"
                exec_lines=$(grep -E "^Exec(Start|StartPre|StartPost|Stop|Reload)=" "$unit" 2>/dev/null || true)
                log "INFO" "  Commands: $exec_lines"
                count=$((count + 1))
                break
            fi
        done
    done
    
    log "INFO" "Completed suspicious paths check"
    echo ""
}

# Check 4: Units with obfuscated or encoded commands
check_obfuscated_commands() {
    log "INFO" "Checking for obfuscated or suspicious commands..."
    count=0
    
    cat "$UNIT_LIST_FILE" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        # Check for base64, hex encoding, curl/wget with pipes, eval, etc.
        if grep -qE "^Exec.*\|(bash|sh|python|perl|php)" "$unit" 2>/dev/null || \
           grep -qE "^Exec.*(base64|xxd|eval|exec)" "$unit" 2>/dev/null || \
           grep -qE "^Exec.*(curl|wget|nc|netcat|ncat).*\|" "$unit" 2>/dev/null; then
            log "CRITICAL" "Potentially obfuscated/malicious command in: $unit"
            exec_lines=$(grep -E "^Exec" "$unit" 2>/dev/null || true)
            log "INFO" "  Commands: $exec_lines"
            count=$((count + 1))
        fi
    done
    
    log "INFO" "Completed obfuscated commands check"
    echo ""
}

# Check 5: Units downloading remote content
check_remote_execution() {
    log "INFO" "Checking for units downloading/executing remote content..."
    count=0
    
    cat "$UNIT_LIST_FILE" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        if grep -qE "^Exec.*(curl|wget|fetch|ftp).*http" "$unit" 2>/dev/null; then
            log "CRITICAL" "Unit downloading remote content: $unit"
            exec_lines=$(grep -E "^Exec.*(curl|wget|fetch)" "$unit" 2>/dev/null || true)
            log "INFO" "  Commands: $exec_lines"
            count=$((count + 1))
        fi
    done
    
    log "INFO" "Completed remote execution check"
    echo ""
}

# Check 6: Missing security hardening options
check_hardening() {
    log "INFO" "Checking for units without security hardening..."
    count=0
    
    get_units_by_ext "service" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        missing_count=0
        missing=""
        
        # Check for important hardening directives
        if ! grep -q "^NoNewPrivileges=true" "$unit" 2>/dev/null; then
            missing_count=$((missing_count + 1))
            missing="$missing NoNewPrivileges"
        fi
        if ! grep -q "^PrivateTmp=true" "$unit" 2>/dev/null; then
            missing_count=$((missing_count + 1))
            missing="$missing PrivateTmp"
        fi
        if ! grep -q "^ProtectSystem=" "$unit" 2>/dev/null; then
            missing_count=$((missing_count + 1))
            missing="$missing ProtectSystem"
        fi
        if ! grep -q "^ProtectHome=" "$unit" 2>/dev/null; then
            missing_count=$((missing_count + 1))
            missing="$missing ProtectHome"
        fi
        if ! grep -q "^ReadOnlyPaths=" "$unit" 2>/dev/null; then
            missing_count=$((missing_count + 1))
            missing="$missing ReadOnlyPaths"
        fi
        
        if [ "$missing_count" -ge 4 ]; then
            log "WARNING" "Unit lacks security hardening: $unit"
            log "INFO" "  Missing:$missing"
            count=$((count + 1))
        fi
    done
    
    log "INFO" "Completed hardening check"
    echo ""
}

# Check 7: Suspicious timers
check_suspicious_timers() {
    log "INFO" "Checking for suspicious timers..."
    count=0
    
    get_units_by_ext "timer" | while IFS= read -r timer; do
        [ -z "$timer" ] && continue
        
        service_file="${timer%.timer}.service"
        
        # Check if corresponding service exists
        if [ ! -f "$service_file" ]; then
            log "WARNING" "Timer without corresponding service: $timer"
            count=$((count + 1))
        fi
        
        # Check for very frequent timers (potential DoS or polling)
        if grep -qE "OnCalendar=.*\*(:[0-5]?[0-9]|minutely)" "$timer" 2>/dev/null || \
           grep -qE "OnUnitActiveSec=[0-9]+s" "$timer" 2>/dev/null; then
            log "WARNING" "High-frequency timer detected: $timer"
            timing=$(grep -E "On(Calendar|UnitActiveSec|BootSec)=" "$timer" 2>/dev/null || true)
            log "INFO" "  Timing: $timing"
            count=$((count + 1))
        fi
    done
    
    log "INFO" "Completed suspicious timers check"
    echo ""
}

# Check 8: Socket units (can be used for persistence)
check_socket_units() {
    log "INFO" "Checking socket units..."
    count=0
    
    get_units_by_ext "socket" | while IFS= read -r socket; do
        [ -z "$socket" ] && continue
        
        log "INFO" "Socket unit found: $socket"
        listen=$(grep -E "^Listen" "$socket" 2>/dev/null || true)
        log "INFO" "  Listening on: $listen"
        count=$((count + 1))
    done
    
    log "INFO" "Completed socket units check (review for legitimacy)"
    echo ""
}

# Check 9: Path units (can trigger on file system events)
check_path_units() {
    log "INFO" "Checking path units..."
    count=0
    
    get_units_by_ext "path" | while IFS= read -r path_unit; do
        [ -z "$path_unit" ] && continue
        
        log "INFO" "Path unit found: $path_unit"
        watched=$(grep -E "^Path" "$path_unit" 2>/dev/null || true)
        log "INFO" "  Watching: $watched"
        count=$((count + 1))
    done
    
    log "INFO" "Completed path units check (review for legitimacy)"
    echo ""
}

# Check 10: Symlinks to unexpected locations
check_symlinks() {
    log "INFO" "Checking for suspicious symlinks..."
    count=0
    
    for loc in $UNIT_LOCATIONS; do
        if [ -d "$loc" ]; then
            find "$loc" -type l 2>/dev/null | while IFS= read -r link; do
                [ -z "$link" ] && continue
                
                target=$(readlink -f "$link" 2>/dev/null || true)
                [ -z "$target" ] && continue
                
                # Check if symlink points outside expected systemd directories
                case "$target" in
                    /usr/lib/systemd/*|/usr/local/lib/systemd/*|/lib/systemd/*|/etc/systemd/*)
                        # Expected location, skip
                        ;;
                    *)
                        log "WARNING" "Symlink to unusual location: $link -> $target"
                        count=$((count + 1))
                        ;;
                esac
            done
        fi
    done
    
    # Also check user directories
    for user_dir in /home/*/.config/systemd/user; do
        if [ -d "$user_dir" ]; then
            find "$user_dir" -type l 2>/dev/null | while IFS= read -r link; do
                [ -z "$link" ] && continue
                
                target=$(readlink -f "$link" 2>/dev/null || true)
                [ -z "$target" ] && continue
                
                case "$target" in
                    /usr/lib/systemd/*|/usr/local/lib/systemd/*|/lib/systemd/*|/etc/systemd/*)
                        ;;
                    *)
                        log "WARNING" "Symlink to unusual location: $link -> $target"
                        count=$((count + 1))
                        ;;
                esac
            done
        fi
    done 2>/dev/null || true
    
    log "INFO" "Completed symlinks check"
    echo ""
}

# Check 11: Units with world-writable components
check_permissions() {
    log "INFO" "Checking for world-writable unit files..."
    count=0
    
    cat "$UNIT_LIST_FILE" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        perms=$(get_permissions "$unit")
        
        # Check if world-writable (last digit is 2, 3, 6, or 7)
        case "$perms" in
            *2|*3|*6|*7)
                log "CRITICAL" "World-writable unit file: $unit (permissions: $perms)"
                count=$((count + 1))
                ;;
        esac
    done
    
    log "INFO" "Completed permissions check"
    echo ""
}

# Check 12: Units in user-writable directories
check_user_writable_locations() {
    log "INFO" "Checking for units in user-writable locations..."
    count=0
    
    cat "$UNIT_LIST_FILE" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        case "$unit" in
            /home/*|/tmp/*|/var/tmp/*)
                log "CRITICAL" "Unit in user-writable location: $unit"
                count=$((count + 1))
                ;;
        esac
    done
    
    log "INFO" "Completed user-writable locations check"
    echo ""
}

# Check 13: Suspicious environment variables
check_environment_variables() {
    log "INFO" "Checking for suspicious environment variables..."
    count=0
    suspicious_vars="LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PERL5LIB NODE_PATH GEM_PATH RUBYLIB"
    
    get_units_by_ext "service" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        env_lines=$(grep -E "^Environment=" "$unit" 2>/dev/null || true)
        
        if [ -n "$env_lines" ]; then
            for var in $suspicious_vars; do
                if echo "$env_lines" | grep -qE "${var}="; then
                    log "CRITICAL" "Suspicious environment variable ($var) in: $unit"
                    log "INFO" "  Environment: $env_lines"
                    count=$((count + 1))
                    break
                fi
            done
        fi
        
        # Check for EnvironmentFile pointing to suspicious locations
        env_file=$(grep -E "^EnvironmentFile=" "$unit" 2>/dev/null || true)
        if [ -n "$env_file" ]; then
            for susp_path in $SUSPICIOUS_PATHS; do
                if echo "$env_file" | grep -q "$susp_path"; then
                    log "CRITICAL" "EnvironmentFile in suspicious location: $unit"
                    log "INFO" "  $env_file"
                    count=$((count + 1))
                    break
                fi
            done
        fi
    done
    
    log "INFO" "Completed environment variables check"
    echo ""
}

# Check 14: KillMode=none (unkillable services)
check_kill_mode() {
    log "INFO" "Checking for unkillable services (KillMode=none)..."
    count=0
    
    get_units_by_ext "service" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        if grep -qE "^KillMode=none" "$unit" 2>/dev/null; then
            log "CRITICAL" "Service cannot be stopped (KillMode=none): $unit"
            
            # Check if it also has Restart directives
            restart=$(grep -E "^Restart=" "$unit" 2>/dev/null || true)
            if [ -n "$restart" ]; then
                log "INFO" "  WARNING: Also has restart directive: $restart"
            fi
            count=$((count + 1))
        fi
    done
    
    log "INFO" "Completed unkillable services check"
    echo ""
}

# Check 15: Excessive or dangerous capabilities
check_capabilities() {
    log "INFO" "Checking for excessive capabilities..."
    count=0
    dangerous_caps="CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID CAP_NET_ADMIN CAP_NET_RAW"
    
    get_units_by_ext "service" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        # Check AmbientCapabilities
        ambient_caps=$(grep -E "^AmbientCapabilities=" "$unit" 2>/dev/null || true)
        if [ -n "$ambient_caps" ]; then
            for cap in $dangerous_caps; do
                if echo "$ambient_caps" | grep -qE "$cap"; then
                    log "CRITICAL" "Dangerous ambient capability ($cap) in: $unit"
                    log "INFO" "  $ambient_caps"
                    count=$((count + 1))
                    break
                fi
            done
        fi
        
        # Check CapabilityBoundingSet (should restrict, not grant)
        cap_bounding=$(grep -E "^CapabilityBoundingSet=" "$unit" 2>/dev/null || true)
        if [ -n "$cap_bounding" ]; then
            # If it's NOT using '~' to remove capabilities, it might be granting them
            case "$cap_bounding" in
                *"CapabilityBoundingSet=~"*)
                    # Using ~ to restrict, this is fine
                    ;;
                *)
                    for cap in $dangerous_caps; do
                        if echo "$cap_bounding" | grep -qE "$cap"; then
                            log "WARNING" "Explicit capability in bounding set ($cap): $unit"
                            log "INFO" "  $cap_bounding"
                            count=$((count + 1))
                            break
                        fi
                    done
                    ;;
            esac
        fi
        
        # Check for SecureBits that might weaken security
        secure_bits=$(grep -E "^SecureBits=" "$unit" 2>/dev/null || true)
        if echo "$secure_bits" | grep -qE "(noroot|noroot-locked)"; then
            log "WARNING" "SecureBits modifying root behavior: $unit"
            log "INFO" "  $secure_bits"
        fi
    done
    
    log "INFO" "Completed capabilities check"
    echo ""
}

# Check 16: Suspicious supplementary groups
check_supplementary_groups() {
    log "INFO" "Checking for suspicious supplementary groups..."
    count=0
    privileged_groups="root wheel sudo admin docker lxd disk shadow adm sys kmem tty audio video plugdev"
    
    get_units_by_ext "service" | while IFS= read -r unit; do
        [ -z "$unit" ] && continue
        
        supp_groups=$(grep -E "^SupplementaryGroups=" "$unit" 2>/dev/null || true)
        
        if [ -n "$supp_groups" ]; then
            # Extract group names from the directive
            groups=$(echo "$supp_groups" | sed 's/SupplementaryGroups=//' | tr ' ' '\n')
            
            for group in $groups; do
                for priv_group in $privileged_groups; do
                    if [ "$group" = "$priv_group" ]; then
                        log "CRITICAL" "Service granted privileged group ($priv_group): $unit"
                        log "INFO" "  $supp_groups"
                        
                        # Check what user this service runs as
                        user=$(grep -E "^User=" "$unit" 2>/dev/null | cut -d= -f2 || true)
                        if [ -z "$user" ] || [ "$user" = "root" ]; then
                            log "INFO" "  Running as: root (default)"
                        else
                            log "INFO" "  Running as: $user"
                        fi
                        count=$((count + 1))
                        break 2
                    fi
                done
            done
        fi
    done
    
    log "INFO" "Completed supplementary groups check"
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
    if [ "$(id -u)" -ne 0 ]; then
        echo "WARNING: Not running as root. Some checks may be incomplete."
        printf "Press Enter to continue or Ctrl+C to abort..."
        read dummy
    fi
    
    # Check if systemd is available
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "ERROR: systemd not found on this system"
        exit 1
    fi
    
    init_log
    
    # Build list of unit files first
    log "INFO" "Building list of unit files..."
    find_unit_files
    log "INFO" "Found $(wc -l < "$UNIT_LIST_FILE") unit files"
    echo ""
    
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