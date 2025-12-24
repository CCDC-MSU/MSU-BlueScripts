#!/bin/sh
#
# Linux/Unix File Permission Auditor and Fixer
# Checks and fixes critical system files for correct permissions
#
#   DRY_RUN - If set to "true", only report issues without fixing (default: false)
#

# Exit codes
EXIT_SUCCESS=0
EXIT_WARNINGS=1
EXIT_ERRORS=2

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
SKIPPED_CHECKS=0
FIXED_CHECKS=0
FIX_FAILED_CHECKS=0

# Get DRY_RUN setting (default to false)
DRY_RUN="${DRY_RUN:-false}"

# Logging functions
log_info() {
    printf "[INFO] %s\n" "$1"
}

log_pass() {
    printf "[PASS] %s\n" "$1"
}

log_fail() {
    printf "[FAIL] %s\n" "$1"
}

log_warn() {
    printf "[WARN] %s\n" "$1"
}

log_skip() {
    printf "[SKIP] %s\n" "$1"
}

log_fix() {
    printf "[FIX] %s\n" "$1"
}

log_fix_failed() {
    printf "[FIX-FAILED] %s\n" "$1"
}

# Check if current permissions are more restrictive than or equal to expected
# Returns 0 if current is OK (equal or more restrictive), 1 if too loose
# Args: current_perm expected_perm
is_perm_acceptable() {
    current="$1"
    expected="$2"
    
    # Convert octal strings to decimal for bit comparison
    current_dec=$((0$current))
    expected_dec=$((0$expected))
    
    # Extract each octal digit (special, user, group, other)
    # For 4755: special=4, user=7, group=5, other=5
    curr_special=$((current_dec / 01000))
    curr_user=$(((current_dec / 0100) % 010))
    curr_group=$(((current_dec / 010) % 010))
    curr_other=$((current_dec % 010))
    
    exp_special=$((expected_dec / 01000))
    exp_user=$(((expected_dec / 0100) % 010))
    exp_group=$(((expected_dec / 010) % 010))
    exp_other=$((expected_dec % 010))
    
    # Check if current has MORE permissions than expected (using bitwise OR)
    # If (current | expected) != expected, then current has extra bits
    if [ $((curr_user | exp_user)) -ne $exp_user ]; then
        return 1  # Too loose
    fi
    if [ $((curr_group | exp_group)) -ne $exp_group ]; then
        return 1  # Too loose
    fi
    if [ $((curr_other | exp_other)) -ne $exp_other ]; then
        return 1  # Too loose
    fi
    if [ $((curr_special | exp_special)) -ne $exp_special ]; then
        return 1  # Too loose (missing setuid/setgid/sticky)
    fi
    
    return 0  # Acceptable (equal or more restrictive)
}

# Check if file exists and has correct permissions
# Args: filepath expected_perm [owner] [group]
check_file_perm() {
    file="$1"
    expected_perm="$2"
    expected_owner="${3:-}"
    expected_group="${4:-}"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    # Check if file exists
    if [ ! -e "$file" ]; then
        SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1))
        return 0
    fi
    
    # Get current permissions (octal format)
    if [ "$(uname)" = "Linux" ]; then
        current_perm=$(stat -c '%a' "$file" 2>/dev/null || echo "")
        current_owner=$(stat -c '%U' "$file" 2>/dev/null || echo "")
        current_group=$(stat -c '%G' "$file" 2>/dev/null || echo "")
    else
        # BSD/Unix systems
        current_perm=$(stat -f '%Lp' "$file" 2>/dev/null || echo "")
        current_owner=$(stat -f '%Su' "$file" 2>/dev/null || echo "")
        current_group=$(stat -f '%Sg' "$file" 2>/dev/null || echo "")
    fi
    
    if [ -z "$current_perm" ]; then
        log_fail "$file: Unable to read permissions"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
    
    # Check permissions
    perm_ok=1
    perm_too_loose=0
    if [ "$current_perm" != "$expected_perm" ]; then
        # Check if current permissions are acceptable (more restrictive is OK)
        if is_perm_acceptable "$current_perm" "$expected_perm"; then
            # Current permissions are more restrictive, which is fine
            perm_ok=1
        else
            # Current permissions are too loose
            perm_ok=0
            perm_too_loose=1
        fi
    fi
    
    # Check owner if specified
    owner_ok=1
    if [ -n "$expected_owner" ] && [ "$current_owner" != "$expected_owner" ]; then
        owner_ok=0
    fi
    
    # Check group if specified
    group_ok=1
    if [ -n "$expected_group" ] && [ "$current_group" != "$expected_group" ]; then
        group_ok=0
    fi
    
    # If everything is correct, just pass (silently)
    if [ $perm_ok -eq 1 ] && [ $owner_ok -eq 1 ] && [ $group_ok -eq 1 ]; then
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    fi
    
    # Build error message only for issues that need fixing
    needs_fix=0
    error_msg="$file: "
    if [ $perm_too_loose -eq 1 ]; then
        error_msg="${error_msg}Permissions too loose: expected $expected_perm, got $current_perm. "
        needs_fix=1
    fi
    if [ $owner_ok -eq 0 ]; then
        error_msg="${error_msg}Expected owner $expected_owner, got $current_owner. "
        needs_fix=1
    fi
    if [ $group_ok -eq 0 ]; then
        error_msg="${error_msg}Expected group $expected_group, got $current_group. "
        needs_fix=1
    fi
    
    # If something needs fixing, report it
    if [ $needs_fix -eq 1 ]; then
        log_fail "$error_msg"
    fi
    
    # Attempt to fix if not in dry run mode
    if [ "$DRY_RUN" = "true" ]; then
        if [ $needs_fix -eq 1 ]; then
            log_warn "$file: DRY_RUN mode - no changes made"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
        return 1
    fi
    
    # Skip fixing if nothing needs to be fixed
    if [ $needs_fix -eq 0 ]; then
        return 0
    fi
    
    fix_success=1
    
    # Fix permissions only if they're too loose
    if [ $perm_too_loose -eq 1 ]; then
        if chmod "$expected_perm" "$file" 2>/dev/null; then
            log_fix "$file: Changed permissions from $current_perm to $expected_perm"
        else
            log_fix_failed "$file: Failed to change permissions to $expected_perm"
            fix_success=0
        fi
    fi
    
    # Fix owner if needed
    if [ $owner_ok -eq 0 ] && [ -n "$expected_owner" ]; then
        if chown "$expected_owner" "$file" 2>/dev/null; then
            log_fix "$file: Changed owner from $current_owner to $expected_owner"
        else
            log_fix_failed "$file: Failed to change owner to $expected_owner"
            fix_success=0
        fi
    fi
    
    # Fix group if needed
    if [ $group_ok -eq 0 ] && [ -n "$expected_group" ]; then
        if chgrp "$expected_group" "$file" 2>/dev/null; then
            log_fix "$file: Changed group from $current_group to $expected_group"
        else
            log_fix_failed "$file: Failed to change group to $expected_group"
            fix_success=0
        fi
    fi
    
    # Update counters based on fix success
    if [ $fix_success -eq 1 ]; then
        FIXED_CHECKS=$((FIXED_CHECKS + 1))
        return 0
    else
        FIX_FAILED_CHECKS=$((FIX_FAILED_CHECKS + 1))
        return 1
    fi
}

# Main audit function
main() {
    log_info "Starting file permission audit..."
    log_info "System: $(uname -s) $(uname -r)"
    echo ""
    
    # === Authentication and Password Files ===
    log_info "=== Checking Authentication Files ==="
    check_file_perm "/etc/passwd" "644" "root"
    check_file_perm "/etc/shadow" "600" "root"
    check_file_perm "/etc/shadow" "640" "root" "shadow"  # Alternative for some systems
    check_file_perm "/etc/group" "644" "root"
    check_file_perm "/etc/gshadow" "600" "root"
    check_file_perm "/etc/gshadow" "640" "root" "shadow"  # Alternative
    check_file_perm "/etc/security/opasswd" "600" "root"
    echo ""
    
    # === SSH Configuration ===
    log_info "=== Checking SSH Configuration ==="
    check_file_perm "/etc/ssh/sshd_config" "600" "root"
    check_file_perm "/etc/ssh/ssh_config" "644" "root"
    check_file_perm "/root/.ssh" "700" "root"
    check_file_perm "/root/.ssh/authorized_keys" "600" "root"
    check_file_perm "/root/.ssh/id_rsa" "600" "root"
    check_file_perm "/root/.ssh/id_dsa" "600" "root"
    check_file_perm "/root/.ssh/id_ecdsa" "600" "root"
    check_file_perm "/root/.ssh/id_ed25519" "600" "root"
    
    # Check SSH host keys
    for key in /etc/ssh/ssh_host_*_key; do
        if [ -f "$key" ]; then
            check_file_perm "$key" "600" "root"
        fi
    done
    
    for key in /etc/ssh/ssh_host_*_key.pub; do
        if [ -f "$key" ]; then
            check_file_perm "$key" "644" "root"
        fi
    done
    echo ""
    
    # === System Configuration ===
    log_info "=== Checking System Configuration Files ==="
    check_file_perm "/etc/fstab" "644" "root"
    check_file_perm "/etc/hosts" "644" "root"
    check_file_perm "/etc/hosts.allow" "644" "root"
    check_file_perm "/etc/hosts.deny" "644" "root"
    check_file_perm "/etc/issue" "644" "root"
    check_file_perm "/etc/issue.net" "644" "root"
    check_file_perm "/etc/motd" "644" "root"
    echo ""
    
    # === Boot Configuration ===
    log_info "=== Checking Boot Configuration ==="
    check_file_perm "/boot/grub/grub.cfg" "600" "root"
    check_file_perm "/boot/grub2/grub.cfg" "600" "root"
    check_file_perm "/etc/default/grub" "644" "root"
    echo ""
    
    # === Sudoers ===
    log_info "=== Checking Sudoers Configuration ==="
    check_file_perm "/etc/sudoers" "440" "root"
    
    if [ -d "/etc/sudoers.d" ]; then
        for sudofile in /etc/sudoers.d/*; do
            if [ -f "$sudofile" ]; then
                check_file_perm "$sudofile" "440" "root"
            fi
        done
    fi
    echo ""
    
    # === Cron Configuration ===
    log_info "=== Checking Cron Configuration ==="
    check_file_perm "/etc/crontab" "644" "root"
    check_file_perm "/etc/cron.d" "755" "root"
    check_file_perm "/etc/cron.daily" "755" "root"
    check_file_perm "/etc/cron.hourly" "755" "root"
    check_file_perm "/etc/cron.weekly" "755" "root"
    check_file_perm "/etc/cron.monthly" "755" "root"
    check_file_perm "/var/spool/cron" "700" "root"
    check_file_perm "/var/spool/cron/crontabs" "700" "root"
    
    # Check individual cron files
    if [ -d "/etc/cron.d" ]; then
        for cronfile in /etc/cron.d/*; do
            if [ -f "$cronfile" ]; then
                check_file_perm "$cronfile" "644" "root"
            fi
        done
    fi
    echo ""
    
    # === Log Files ===
    log_info "=== Checking Log Files ==="
    check_file_perm "/var/log" "755" "root"
    check_file_perm "/var/log/syslog" "640"
    check_file_perm "/var/log/auth.log" "640"
    check_file_perm "/var/log/secure" "600"
    check_file_perm "/var/log/messages" "640"
    check_file_perm "/var/log/wtmp" "664"
    check_file_perm "/var/log/btmp" "600"
    check_file_perm "/var/log/lastlog" "664"
    echo ""
    
    # === PAM Configuration ===
    log_info "=== Checking PAM Configuration ==="
    check_file_perm "/etc/pam.d" "755" "root"
    
    if [ -d "/etc/pam.d" ]; then
        for pamfile in /etc/pam.d/*; do
            if [ -f "$pamfile" ]; then
                check_file_perm "$pamfile" "644" "root"
            fi
        done
    fi
    
    check_file_perm "/etc/security" "755" "root"
    check_file_perm "/etc/security/limits.conf" "644" "root"
    echo ""
    
    # === Network Configuration ===
    log_info "=== Checking Network Configuration ==="
    check_file_perm "/etc/sysctl.conf" "644" "root"
    check_file_perm "/etc/resolv.conf" "644" "root"
    check_file_perm "/etc/network/interfaces" "644" "root"
    check_file_perm "/etc/sysconfig/network-scripts" "755" "root"
    echo ""
    
    # === Important Binaries (SUID/SGID) ===
    log_info "=== Checking Important Binaries ==="
    check_file_perm "/usr/bin/sudo" "4755" "root"
    check_file_perm "/bin/su" "4755" "root"
    check_file_perm "/usr/bin/su" "4755" "root"
    check_file_perm "/usr/bin/passwd" "4755" "root"
    check_file_perm "/bin/passwd" "4755" "root"
    check_file_perm "/usr/bin/chsh" "4755" "root"
    check_file_perm "/usr/bin/chfn" "4755" "root"
    check_file_perm "/usr/bin/newgrp" "4755" "root"
    echo ""
    
    # === World-Writable Files Check ===
    log_info "=== Checking for World-Writable Files ==="
    
    # Directories to check for world-writable files
    sensitive_dirs="/root /home /etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib /lib64 /usr/lib /usr/lib64 /boot /opt"
    
    world_writable_count=0
    for dir in $sensitive_dirs; do
        if [ -d "$dir" ]; then
            # Find world-writable files (excluding symbolic links)
            # Using -not -type l to exclude symlinks
            # Using -perm -o+w to find files with world-write bit set
            world_writable=$(find "$dir" -not -type l -perm -o+w 2>/dev/null || true)
            
            if [ -n "$world_writable" ]; then
                echo "$world_writable" | while IFS= read -r file; do
                    if [ -n "$file" ]; then
                        log_warn "World-writable file found: $file"
                        world_writable_count=$((world_writable_count + 1))
                    fi
                done
            fi
        fi
    done
    
    if [ $world_writable_count -eq 0 ]; then
        log_info "No world-writable files found in sensitive directories"
    else
        log_warn "Found world-writable files in sensitive directories"
    fi
    echo ""
    
    # === Print Summary ===
    echo "========================================"
    log_info "AUDIT SUMMARY"
    echo "========================================"
    echo "Total checks:   $TOTAL_CHECKS"
    echo "Passed:         $PASSED_CHECKS"
    echo "Fixed:          $FIXED_CHECKS"
    echo "Failed to fix:  $FIX_FAILED_CHECKS"
    echo "Skipped:        $SKIPPED_CHECKS"
    echo "========================================"
    
    # Determine exit code
    if [ $FIX_FAILED_CHECKS -gt 0 ]; then
        log_warn "Audit completed with unfixable failures"
        return $EXIT_ERRORS
    elif [ $FIXED_CHECKS -gt 0 ]; then
        log_info "Audit completed - $FIXED_CHECKS issues were fixed"
        return $EXIT_SUCCESS
    elif [ $SKIPPED_CHECKS -gt 0 ]; then
        log_info "Audit completed with some checks skipped"
        return $EXIT_WARNINGS
    else
        log_info "Audit completed successfully - no issues found"
        return $EXIT_SUCCESS
    fi
}

# Run main function
main
exit $?