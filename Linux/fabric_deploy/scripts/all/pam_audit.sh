#!/bin/sh
# pam_audit.sh - PAM Security Auditing Script
# POSIX-compliant, cross-platform (Linux/BSD/Unix)

set -e

# --- Configuration ---
# Directories to search for PAM modules
PAM_LIB_DIRS="/lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /lib/security /lib64/security /usr/lib/security /usr/lib64/security"
PAM_CONF_DIR="/etc/pam.d"
PAM_CONF_FILE="/etc/pam.conf"

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# --- Helper Functions ---
print_header() {
    printf "\n${BLUE}=== %s ===${NC}\n" "$1"
}

print_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

print_fail() {
    printf "${RED}[FAIL]${NC} %s\n" "$1"
}

print_ok() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

print_info() {
    printf "[INFO] %s\n" "$1"
}

# Find PAM library directory
find_pam_lib_dir() {
    for dir in $PAM_LIB_DIRS; do
        if [ -d "$dir" ] && [ -f "$dir/pam_unix.so" ]; then
            echo "$dir"
            return 0
        fi
        # Check subdirectories (e.g., /lib/x86_64-linux-gnu/security)
        for subdir in "$dir"/*/security "$dir"/security; do
            if [ -d "$subdir" ] && [ -f "$subdir/pam_unix.so" ]; then
                echo "$subdir"
                return 0
            fi
        done
    done
    return 1
}

# Get all PAM config files
get_pam_configs() {
    if [ -d "$PAM_CONF_DIR" ]; then
        find "$PAM_CONF_DIR" -type f 2>/dev/null
    fi
    if [ -f "$PAM_CONF_FILE" ]; then
        echo "$PAM_CONF_FILE"
    fi
}

# --- Checks ---

# Check 1: pam_exec.so usage (can run arbitrary commands)
check_pam_exec() {
    print_header "pam_exec.so Usage (Arbitrary Command Execution)"
    found=0
    for cfg in $(get_pam_configs); do
        matches=$(grep -n "pam_exec\.so" "$cfg" 2>/dev/null | grep -v "^#" || true)
        if [ -n "$matches" ]; then
            print_warn "pam_exec.so found in $cfg:"
            echo "$matches" | while IFS= read -r line; do
                printf "    %s\n" "$line"
            done
            found=1
        fi
    done
    if [ "$found" -eq 0 ]; then
        print_ok "No pam_exec.so usage detected."
    fi
}

# Check 2: nullok option (allows empty passwords)
check_nullok() {
    print_header "nullok Option (Empty Passwords Allowed)"
    found=0
    for cfg in $(get_pam_configs); do
        matches=$(grep -n "nullok" "$cfg" 2>/dev/null | grep -v "^#" || true)
        if [ -n "$matches" ]; then
            print_warn "nullok found in $cfg:"
            echo "$matches" | while IFS= read -r line; do
                printf "    %s\n" "$line"
            done
            found=1
        fi
    done
    if [ "$found" -eq 0 ]; then
        print_ok "No nullok usage detected."
    fi
}

# Check 3: pam_permit.so with 'sufficient' (dangerous bypass)
check_permit_sufficient() {
    print_header "pam_permit.so with 'sufficient' (Authentication Bypass)"
    found=0
    for cfg in $(get_pam_configs); do
        matches=$(grep -n "sufficient.*pam_permit\.so\|pam_permit\.so.*sufficient" "$cfg" 2>/dev/null | grep -v "^#" || true)
        if [ -n "$matches" ]; then
            print_fail "DANGEROUS: pam_permit.so with sufficient in $cfg:"
            echo "$matches" | while IFS= read -r line; do
                printf "    %s\n" "$line"
            done
            found=1
        fi
    done
    if [ "$found" -eq 0 ]; then
        print_ok "No dangerous pam_permit.so + sufficient combinations found."
    fi
}

# Check 4: pam_rootok.so usage (allows root without password)
check_rootok() {
    print_header "pam_rootok.so Usage (Root Bypasses Authentication)"
    found=0
    for cfg in $(get_pam_configs); do
        matches=$(grep -n "pam_rootok\.so" "$cfg" 2>/dev/null | grep -v "^#" || true)
        if [ -n "$matches" ]; then
            print_info "pam_rootok.so found in $cfg (review if appropriate):"
            echo "$matches" | while IFS= read -r line; do
                printf "    %s\n" "$line"
            done
            found=1
        fi
    done
    if [ "$found" -eq 0 ]; then
        print_ok "No pam_rootok.so usage detected."
    fi
}

# Check 5: Unknown/non-standard PAM modules
check_unknown_modules() {
    print_header "Non-Standard PAM Modules"
    
    PAM_LIB=$(find_pam_lib_dir)
    if [ -z "$PAM_LIB" ]; then
        print_warn "Could not locate PAM library directory."
        return
    fi
    print_info "PAM library directory: $PAM_LIB"

    # List of common/expected modules (extend as needed)
    KNOWN_MODULES="pam_unix pam_deny pam_permit pam_env pam_limits pam_loginuid pam_nologin pam_securetty pam_selinux pam_namespace pam_keyinit pam_faildelay pam_succeed_if pam_systemd pam_shells pam_motd pam_mail pam_lastlog pam_umask pam_access pam_time pam_group pam_wheel pam_pwhistory pam_pwquality pam_cracklib pam_tally pam_tally2 pam_faillock pam_cap pam_xauth pam_console pam_gnome_keyring pam_kwallet pam_kwallet5 pam_sss pam_ldap pam_krb5 pam_winbind pam_fprintd pam_u2f pam_google_authenticator pam_duo pam_oath pam_yubico pam_ecryptfs pam_mount pam_script pam_exec pam_mkhomedir pam_oddjob_mkhomedir pam_localuser pam_rootok pam_userdb pam_listfile pam_filter pam_ftp pam_issue pam_postgresok pam_rhosts pam_rps pam_sepermit pam_stress pam_timestamp pam_warn pam_debug pam_echo pam_opie pam_opieaccess pam_radius_auth pam_tacplus pam_ssh pam_ssh_agent_auth pam_pkcs11 pam_apparmor"

    found=0
    for mod in "$PAM_LIB"/*.so; do
        [ -f "$mod" ] || continue
        modname=$(basename "$mod" .so)
        known=0
        for k in $KNOWN_MODULES; do
            if [ "$modname" = "$k" ]; then
                known=1
                break
            fi
        done
        if [ "$known" -eq 0 ]; then
            print_warn "Unknown module: $mod"
            found=1
        fi
    done
    if [ "$found" -eq 0 ]; then
        print_ok "All detected PAM modules are known/standard."
    fi
}

# Check 6: PAM config file permissions
check_config_permissions() {
    print_header "PAM Config File Permissions"
    found=0
    for cfg in $(get_pam_configs); do
        # Check if world-writable
        if [ -w "$cfg" ] 2>/dev/null; then
            # More precise: use ls to check permissions
            perms=$(ls -l "$cfg" 2>/dev/null | cut -c1-10)
            if echo "$perms" | grep -q "w.$"; then
                print_fail "World-writable: $cfg ($perms)"
                found=1
            fi
        fi
        # Check owner (should be root)
        owner=$(ls -l "$cfg" 2>/dev/null | awk '{print $3}')
        if [ "$owner" != "root" ]; then
            print_warn "Non-root owner ($owner): $cfg"
            found=1
        fi
    done
    if [ "$found" -eq 0 ]; then
        print_ok "PAM config file permissions look correct."
    fi
}

# Check 7: PAM stack order (deny should come before permit in auth)
check_stack_order() {
    print_header "PAM Stack Order (auth: deny before permit)"
    for cfg in $(get_pam_configs); do
        # Only check files that have both deny and permit
        has_deny=$(grep -c "pam_deny\.so" "$cfg" 2>/dev/null || echo 0)
        has_permit=$(grep -c "pam_permit\.so" "$cfg" 2>/dev/null || echo 0)
        
        if [ "$has_deny" -gt 0 ] && [ "$has_permit" -gt 0 ]; then
            # Get line numbers (only for 'auth' type lines ideally, but simplified here)
            deny_line=$(grep -n "pam_deny\.so" "$cfg" 2>/dev/null | head -n 1 | cut -d: -f1)
            permit_line=$(grep -n "pam_permit\.so" "$cfg" 2>/dev/null | head -n 1 | cut -d: -f1)
            
            if [ -n "$deny_line" ] && [ -n "$permit_line" ]; then
                if [ "$permit_line" -lt "$deny_line" ]; then
                    print_warn "pam_permit.so (line $permit_line) comes before pam_deny.so (line $deny_line) in $cfg"
                fi
            fi
        fi
    done
    print_info "Stack order check complete."
}

# Check 8: pam_wheel.so for su restriction
check_wheel() {
    print_header "pam_wheel.so (su Restriction)"
    su_cfg=""
    if [ -f "$PAM_CONF_DIR/su" ]; then
        su_cfg="$PAM_CONF_DIR/su"
    elif [ -f "$PAM_CONF_DIR/su-l" ]; then
        su_cfg="$PAM_CONF_DIR/su-l"
    fi
    
    if [ -n "$su_cfg" ]; then
        if grep -q "pam_wheel\.so" "$su_cfg" 2>/dev/null; then
            if grep "pam_wheel\.so" "$su_cfg" 2>/dev/null | grep -qv "^#"; then
                print_ok "pam_wheel.so is enabled in $su_cfg (su restricted to wheel group)."
            else
                print_info "pam_wheel.so is commented out in $su_cfg."
            fi
        else
            print_info "pam_wheel.so not found in $su_cfg (su not restricted to wheel group)."
        fi
    else
        print_info "No su PAM config found."
    fi
}

# Check 9: Password quality modules
check_password_quality() {
    print_header "Password Quality Enforcement"
    found=0
    for cfg in $(get_pam_configs); do
        if grep -qE "pam_pwquality\.so|pam_cracklib\.so|pam_passwdqc\.so" "$cfg" 2>/dev/null; then
            matches=$(grep -nE "pam_pwquality\.so|pam_cracklib\.so|pam_passwdqc\.so" "$cfg" 2>/dev/null | grep -v "^#" || true)
            if [ -n "$matches" ]; then
                print_ok "Password quality module found in $cfg:"
                echo "$matches" | while IFS= read -r line; do
                    printf "    %s\n" "$line"
                done
                found=1
            fi
        fi
    done
    if [ "$found" -eq 0 ]; then
        print_warn "No password quality modules (pam_pwquality/pam_cracklib/pam_passwdqc) detected."
    fi
}

# Check 10: Account lockout (faillock/tally2)
check_account_lockout() {
    print_header "Account Lockout (pam_faillock/pam_tally2)"
    found=0
    for cfg in $(get_pam_configs); do
        if grep -qE "pam_faillock\.so|pam_tally2\.so|pam_tally\.so" "$cfg" 2>/dev/null; then
            matches=$(grep -nE "pam_faillock\.so|pam_tally2\.so|pam_tally\.so" "$cfg" 2>/dev/null | grep -v "^#" || true)
            if [ -n "$matches" ]; then
                print_ok "Account lockout module found in $cfg:"
                echo "$matches" | while IFS= read -r line; do
                    printf "    %s\n" "$line"
                done
                found=1
            fi
        fi
    done
    if [ "$found" -eq 0 ]; then
        print_warn "No account lockout modules (pam_faillock/pam_tally2) detected."
    fi
}

# --- Main ---
main() {
    printf "${BLUE}==========================================${NC}\n"
    printf "${BLUE}       PAM Security Audit Report${NC}\n"
    printf "${BLUE}==========================================${NC}\n"
    printf "Date: %s\n" "$(date)"
    printf "Host: %s\n" "$(hostname)"
    printf "OS:   %s\n" "$(uname -s) $(uname -r)"

    check_pam_exec
    check_nullok
    check_permit_sufficient
    check_rootok
    check_unknown_modules
    check_config_permissions
    check_stack_order
    check_wheel
    check_password_quality
    check_account_lockout

    print_header "Audit Complete"
}

main "$@"
