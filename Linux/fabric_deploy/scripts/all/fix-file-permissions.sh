#!/bin/sh
#
# Linux/Unix File Permission Auditor and Fixer
# Checks and fixes critical system files for correct permissions.
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
SKIPPED_CHECKS=0
FIXED_CHECKS=0
FIX_FAILED_CHECKS=0
NEEDS_FIX_CHECKS=0

# Get DRY_RUN setting (default to false)
DRY_RUN="${DRY_RUN:-false}"

# Logging functions
log_info() { printf "[INFO] %s\n" "$1"; }
log_pass() { printf "[PASS] %s\n" "$1"; }
log_fail() { printf "[FAIL] %s\n" "$1"; }
log_warn() { printf "[WARN] %s\n" "$1"; }
log_skip() { printf "[SKIP] %s\n" "$1"; }
log_fix() { printf "[FIX] %s\n" "$1"; }
log_fix_failed() { printf "[FIX-FAILED] %s\n" "$1"; }

# --- Small path helpers (POSIX-ish) ---
path_dirname() {
    p="$1"
    case "$p" in
        */*) printf "%s\n" "${p%/*}" ;;
        *)   printf ".\n" ;;
    esac
}

path_basename() {
    p="$1"
    case "$p" in
        */*) printf "%s\n" "${p##*/}" ;;
        *)   printf "%s\n" "$p" ;;
    esac
}

# Canonicalize "dir/base" to an absolute, physical path if possible
canonicalize_path() {
    p="$1"
    d="$(path_dirname "$p")"
    b="$(path_basename "$p")"
    (cd -P "$d" 2>/dev/null && printf "%s/%s\n" "$(pwd -P)" "$b") || printf "%s\n" "$p"
}

# Resolve symlinks to final target (best-effort, no bashisms).
# Prints resolved path on stdout, returns 0 on success.
# If it cannot resolve (missing readlink), prints original path and returns 0.
resolve_path() {
    p="$1"

    # Not a symlink: just canonicalize for nicer logs.
    if [ ! -L "$p" ]; then
        canonicalize_path "$p"
        return 0
    fi

    # Prefer readlink -f if available
    if command -v readlink >/dev/null 2>&1; then
        if readlink -f "$p" >/dev/null 2>&1; then
            readlink -f "$p"
            return 0
        fi

        # Manual loop: readlink step-by-step, handle relative targets.
        i=0
        while [ -L "$p" ] && [ $i -lt 40 ]; do
            t="$(readlink "$p" 2>/dev/null)" || break
            case "$t" in
                /*) p="$t" ;;
                *)
                    d="$(path_dirname "$p")"
                    p="$d/$t"
                    ;;
            esac
            i=$((i + 1))
        done

        canonicalize_path "$p"
        return 0
    fi

    # No readlink; fall back to original path (stat/chmod will follow on many Linuxes,
    # but not all BSDs; we warn when this happens).
    printf "%s\n" "$p"
    return 0
}

# Returns 0 if group exists
group_exists() {
    g="$1"
    if command -v getent >/dev/null 2>&1; then
        getent group "$g" >/dev/null 2>&1
        return $?
    fi
    # Fallback: parse /etc/group
    [ -r /etc/group ] && grep -q "^$g:" /etc/group 2>/dev/null
}

# Check if current permissions are more restrictive than or equal to expected
# Returns 0 if current is OK (equal or more restrictive), 1 if too loose
# Args: current_perm expected_perm
is_perm_acceptable() {
    current="$1"
    expected="$2"

    current_dec=$((0$current))
    expected_dec=$((0$expected))

    curr_special=$((current_dec / 01000))
    curr_user=$(((current_dec / 0100) % 010))
    curr_group=$(((current_dec / 010) % 010))
    curr_other=$((current_dec % 010))

    exp_special=$((expected_dec / 01000))
    exp_user=$(((expected_dec / 0100) % 010))
    exp_group=$(((expected_dec / 010) % 010))
    exp_other=$((expected_dec % 010))

    # Too loose if current has extra bits not present in expected.
    if [ $((curr_user | exp_user)) -ne $exp_user ]; then return 1; fi
    if [ $((curr_group | exp_group)) -ne $exp_group ]; then return 1; fi
    if [ $((curr_other | exp_other)) -ne $exp_other ]; then return 1; fi
    if [ $((curr_special | exp_special)) -ne $exp_special ]; then return 1; fi

    return 0
}

# Read mode/owner/group in a cross-platform way.
# Prints "perm owner group" on success.
stat_triplet() {
    p="$1"

    # GNU / BusyBox-ish (Linux)
    if stat -c '%a %U %G' "$p" >/dev/null 2>&1; then
        stat -c '%a %U %G' "$p" 2>/dev/null
        return $?
    fi

    # BSD / macOS
    if stat -f '%Lp %Su %Sg' "$p" >/dev/null 2>&1; then
        stat -f '%Lp %Su %Sg' "$p" 2>/dev/null
        return $?
    fi

    return 1
}

# Check if file exists and has correct permissions
# Args: filepath expected_perm [owner] [group] [mode]
#   mode: "exact" requires exact permission match (no "more restrictive is ok").
check_file_perm() {
    file="$1"
    expected_perm="$2"
    expected_owner="${3:-}"
    expected_group="${4:-}"
    match_mode="${5:-}"  # empty or "exact"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    # Handle symlinks: follow to target and audit target perms/ownership.
    target="$file"
    display="$file"

    if [ -L "$file" ]; then
        target="$(resolve_path "$file")"
        display="$file -> $target"

        # If we couldn't truly resolve (no readlink), warn once per use.
        if [ "$target" = "$file" ] && ! command -v readlink >/dev/null 2>&1; then
            log_warn "$file: is a symlink, but 'readlink' is unavailable; may not be able to validate target accurately on this OS"
        fi

        # Broken symlink: treat as failure (not skipped).
        if [ ! -e "$target" ]; then
            log_fail "$display: Broken symlink (target missing)"
            FIX_FAILED_CHECKS=$((FIX_FAILED_CHECKS + 1))
            NEEDS_FIX_CHECKS=$((NEEDS_FIX_CHECKS + 1))
            return 1
        fi
    else
        # Non-symlink: skip if it doesn't exist
        if [ ! -e "$file" ]; then
            SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1))
            return 0
        fi
    fi

    triplet="$(stat_triplet "$target")"
    if [ -z "$triplet" ]; then
        log_fail "$display: Unable to read permissions/owner/group"
        FIX_FAILED_CHECKS=$((FIX_FAILED_CHECKS + 1))
        NEEDS_FIX_CHECKS=$((NEEDS_FIX_CHECKS + 1))
        return 1
    fi

    current_perm="$(printf "%s" "$triplet" | awk '{print $1}')"
    current_owner="$(printf "%s" "$triplet" | awk '{print $2}')"
    current_group="$(printf "%s" "$triplet" | awk '{print $3}')"

    # Permission check
    perm_ok=1
    perm_too_loose=0

    if [ "$match_mode" = "exact" ]; then
        if [ "$current_perm" != "$expected_perm" ]; then
            perm_ok=0
            perm_too_loose=1
        fi
    else
        if [ "$current_perm" != "$expected_perm" ]; then
            if is_perm_acceptable "$current_perm" "$expected_perm"; then
                perm_ok=1
            else
                perm_ok=0
                perm_too_loose=1
            fi
        fi
    fi

    owner_ok=1
    if [ -n "$expected_owner" ] && [ "$current_owner" != "$expected_owner" ]; then
        owner_ok=0
    fi

    group_ok=1
    if [ -n "$expected_group" ] && [ "$current_group" != "$expected_group" ]; then
        group_ok=0
    fi

    if [ $perm_ok -eq 1 ] && [ $owner_ok -eq 1 ] && [ $group_ok -eq 1 ]; then
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    fi

    needs_fix=0
    error_msg="$display: "
    if [ $perm_too_loose -eq 1 ]; then
        if [ "$match_mode" = "exact" ]; then
            error_msg="${error_msg}Permissions mismatch: expected $expected_perm, got $current_perm. "
        else
            error_msg="${error_msg}Permissions too loose: expected max $expected_perm, got $current_perm. "
        fi
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

    if [ $needs_fix -eq 1 ]; then
        log_fail "$error_msg"
        NEEDS_FIX_CHECKS=$((NEEDS_FIX_CHECKS + 1))
    fi

    if [ "$DRY_RUN" = "true" ]; then
        if [ $needs_fix -eq 1 ]; then
            log_warn "$display: DRY_RUN mode - no changes made"
        fi
        return 1
    fi

    if [ $needs_fix -eq 0 ]; then
        return 0
    fi

    fix_success=1

    # Fix permissions
    if [ $perm_too_loose -eq 1 ]; then
        if chmod "$expected_perm" "$target" 2>/dev/null; then
            log_fix "$display: Set permissions to $expected_perm (was $current_perm)"
        else
            log_fix_failed "$display: Failed to set permissions to $expected_perm"
            fix_success=0
        fi
    fi

    if [ $fix_success -eq 1 ]; then
        FIXED_CHECKS=$((FIXED_CHECKS + 1))
        return 0
    fi

    FIX_FAILED_CHECKS=$((FIX_FAILED_CHECKS + 1))
    return 1
}

main() {
    log_info "Starting file permission audit..."
    log_info "System: $(uname -s) $(uname -r)"
    echo ""

    # === Authentication and Password Files ===
    log_info "=== Checking Authentication Files ==="
    check_file_perm "/etc/passwd" "644" "root" "root"
    check_file_perm "/etc/group"  "644" "root" "root"

    # Prefer shadow-group layout if it exists; otherwise require root-only.
    if group_exists "shadow"; then
        check_file_perm "/etc/shadow"  "640" "root" "shadow"
        check_file_perm "/etc/gshadow" "640" "root" "shadow"
        check_file_perm "/etc/shadow-" "640" "root" "shadow"
        check_file_perm "/etc/gshadow-" "640" "root" "shadow"
    else
        check_file_perm "/etc/shadow"  "600" "root" "root"
        check_file_perm "/etc/gshadow" "600" "root" "root"
        check_file_perm "/etc/shadow-" "600" "root" "root"
        check_file_perm "/etc/gshadow-" "600" "root" "root"
    fi

    check_file_perm "/etc/passwd-" "644" "root" "root"
    check_file_perm "/etc/group-"  "644" "root" "root"
    check_file_perm "/etc/security/opasswd" "600" "root" ""
    echo ""

    # === SSH Configuration ===
    log_info "=== Checking SSH Configuration ==="
    check_file_perm "/etc/ssh/sshd_config" "600" "root" "root"
    check_file_perm "/etc/ssh/ssh_config"  "644" "root" "root"
    check_file_perm "/root/.ssh" "700" "root" "root"
    check_file_perm "/root/.ssh/authorized_keys" "600" "root" "root"
    check_file_perm "/root/.ssh/id_rsa"     "600" "root" "root"
    check_file_perm "/root/.ssh/id_dsa"     "600" "root" "root"
    check_file_perm "/root/.ssh/id_ecdsa"   "600" "root" "root"
    check_file_perm "/root/.ssh/id_ed25519" "600" "root" "root"

    for key in /etc/ssh/ssh_host_*_key; do
        [ -f "$key" ] && check_file_perm "$key" "600" "root" "root"
    done
    for key in /etc/ssh/ssh_host_*_key.pub; do
        [ -f "$key" ] && check_file_perm "$key" "644" "root" "root"
    done
    echo ""

    # === System Configuration ===
    log_info "=== Checking System Configuration Files ==="
    check_file_perm "/etc/fstab"       "644" "root" "root"
    check_file_perm "/etc/hosts"       "644" "root" "root"
    check_file_perm "/etc/hosts.allow" "644" "root" "root"
    check_file_perm "/etc/hosts.deny"  "644" "root" "root"
    check_file_perm "/etc/issue"       "644" "root" "root"
    check_file_perm "/etc/issue.net"   "644" "root" "root"
    check_file_perm "/etc/motd"        "644" "root" "root"
    echo ""

    # === Boot Configuration ===
    log_info "=== Checking Boot Configuration ==="
    check_file_perm "/boot/grub/grub.cfg"  "600" "root" "root"
    check_file_perm "/boot/grub2/grub.cfg" "600" "root" "root"
    check_file_perm "/etc/default/grub"    "644" "root" "root"
    echo ""

    # === Sudoers ===
    log_info "=== Checking Sudoers Configuration ==="
    check_file_perm "/etc/sudoers" "440" "root" "root"
    if [ -d "/etc/sudoers.d" ]; then
        for sudofile in /etc/sudoers.d/*; do
            [ -f "$sudofile" ] && check_file_perm "$sudofile" "440" "root" "root"
        done
    fi
    echo ""

    # === Cron Configuration ===
    log_info "=== Checking Cron Configuration ==="
    check_file_perm "/etc/crontab" "644" "root" "root"
    check_file_perm "/etc/cron.d"      "755" "root" "root"
    check_file_perm "/etc/cron.daily"  "755" "root" "root"
    check_file_perm "/etc/cron.hourly" "755" "root" "root"
    check_file_perm "/etc/cron.weekly" "755" "root" "root"
    check_file_perm "/etc/cron.monthly" "755" "root" "root"
    check_file_perm "/var/spool/cron"         "700" "root" ""
    check_file_perm "/var/spool/cron/crontabs" "700" "root" ""

    if [ -d "/etc/cron.d" ]; then
        for cronfile in /etc/cron.d/*; do
            [ -f "$cronfile" ] && check_file_perm "$cronfile" "644" "root" "root"
        done
    fi
    echo ""

    # === Log Files ===
    log_info "=== Checking Log Files ==="
    check_file_perm "/var/log" "755" "root" "root"
    check_file_perm "/var/log/syslog"   "640" "" ""
    check_file_perm "/var/log/auth.log" "640" "" ""
    check_file_perm "/var/log/secure"   "600" "" ""
    check_file_perm "/var/log/messages" "640" "" ""
    check_file_perm "/var/log/wtmp"     "664" "" ""
    check_file_perm "/var/log/btmp"     "600" "" ""
    check_file_perm "/var/log/lastlog"  "664" "" ""
    echo ""

    # === PAM Configuration ===
    log_info "=== Checking PAM Configuration ==="
    check_file_perm "/etc/pam.d" "755" "root" "root"
    if [ -d "/etc/pam.d" ]; then
        for pamfile in /etc/pam.d/*; do
            [ -f "$pamfile" ] && check_file_perm "$pamfile" "644" "root" "root"
        done
    fi
    check_file_perm "/etc/security" "755" "root" "root"
    check_file_perm "/etc/security/limits.conf" "644" "root" "root"
    echo ""

    # === Network Configuration ===
    log_info "=== Checking Network Configuration ==="
    check_file_perm "/etc/sysctl.conf" "644" "root" "root"
    check_file_perm "/etc/resolv.conf" "644" "root" "root"
    check_file_perm "/etc/network/interfaces" "644" "root" "root"
    check_file_perm "/etc/sysconfig/network-scripts" "755" "root" "root"
    echo ""

    # === Important Binaries (SUID/SGID) ===
    # For these, using "exact" can be desirable (tampering can remove/alter bits).
    log_info "=== Checking Important Binaries ==="
    check_file_perm "/usr/bin/sudo"   "4755" "root" "root" "exact"
    check_file_perm "/bin/su"         "4755" "root" "root" "exact"
    check_file_perm "/usr/bin/su"     "4755" "root" "root" "exact"
    check_file_perm "/usr/bin/passwd" "4755" "root" "root" "exact"
    check_file_perm "/bin/passwd"     "4755" "root" "root" "exact"
    check_file_perm "/usr/bin/chsh"   "4755" "root" "root" "exact"
    check_file_perm "/usr/bin/chfn"   "4755" "root" "root" "exact"
    check_file_perm "/usr/bin/newgrp" "4755" "root" "root" "exact"
    echo ""

    # === World-Writable Files Check ===
    log_info "=== Checking for World-Writable Files ==="
    sensitive_dirs="/root /home /etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib /lib64 /usr/lib /usr/lib64 /boot /opt"

    world_writable_count=0
    tmpfile=""
    if command -v mktemp >/dev/null 2>&1; then
        tmpfile="$(mktemp 2>/dev/null || printf "")"
    fi
    [ -z "$tmpfile" ] && tmpfile="/tmp/perm_audit.$$"

    : >"$tmpfile" 2>/dev/null || true

    for dir in $sensitive_dirs; do
        if [ -d "$dir" ]; then
            # -perm -0002 = world-writable
            find "$dir" -not -type l -perm -0002 -print 2>/dev/null >>"$tmpfile" || true
        fi
    done

    if [ -s "$tmpfile" ]; then
        # Print each and count without subshell-counter issues
        while IFS= read -r ww; do
            [ -n "$ww" ] || continue
            log_warn "World-writable file found: $ww"
            world_writable_count=$((world_writable_count + 1))
        done <"$tmpfile"
        log_warn "Found $world_writable_count world-writable files in sensitive directories"
    else
        log_info "No world-writable files found in sensitive directories"
    fi

    rm -f "$tmpfile" >/dev/null 2>&1 || true
    echo ""

    # === Print Summary ===
    echo "========================================"
    log_info "AUDIT SUMMARY"
    echo "========================================"
    echo "Total checks:        $TOTAL_CHECKS"
    echo "Passed:              $PASSED_CHECKS"
    echo "Need fixes:          $NEEDS_FIX_CHECKS"
    echo "Fixed:               $FIXED_CHECKS"
    echo "Failed to fix:       $FIX_FAILED_CHECKS"
    echo "Skipped (not found): $SKIPPED_CHECKS"
    echo "========================================"

    if [ $FIX_FAILED_CHECKS -gt 0 ]; then
        log_warn "Audit completed with unfixable failures"
        return $EXIT_ERRORS
    fi
    if [ "$DRY_RUN" = "true" ] && [ $NEEDS_FIX_CHECKS -gt 0 ]; then
        log_warn "DRY_RUN completed; fixes needed"
        return $EXIT_WARNINGS
    fi
    if [ $SKIPPED_CHECKS -gt 0 ]; then
        log_info "Audit completed with some checks skipped"
        return $EXIT_WARNINGS
    fi

    log_info "Audit completed successfully"
    return $EXIT_SUCCESS
}

main
exit $?
