#!/bin/sh
# POSIX-compliant profile audit script
# Compiles user profiles and checks for security issues

set -e

# Configuration
AUDIT_DIR="/root/profile-audit"
LOG_DIR="/root/profile-audit/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Profile files to check (in order of execution)
SYSTEM_PROFILES="/etc/profile /etc/bash.bashrc /etc/bashrc"
USER_PROFILES=".profile .bash_profile .bash_login .bashrc .zshrc .zshenv .zprofile"

# Colors for output (optional, won't break POSIX)
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Create directories
mkdir -p "$AUDIT_DIR" "$LOG_DIR"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/audit_$TIMESTAMP.log"
}

check_vulnerability() {
    file="$1"
    username="$2"
    vuln_log="$LOG_DIR/vulnerabilities_${username}_$TIMESTAMP.log"
    
    if [ ! -f "$file" ]; then
        return 0
    fi
    
    # Check file permissions
    perms=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file" 2>/dev/null)
    if [ "$perms" ] && [ "$((perms & 022))" -ne 0 ]; then
        echo "${RED}[CRITICAL]${NC} World/group writable: $file (perms: $perms)" | tee -a "$vuln_log"
    fi
    
    # Check for suspicious patterns
    while IFS= read -r line; do
        # Skip comments and empty lines
        case "$line" in
            \#*|"") continue ;;
        esac
        
        # Check for curl/wget piped to shell
        if echo "$line" | grep -qE '(curl|wget|fetch).*\|.*(sh|bash|zsh)'; then
            echo "${RED}[HIGH]${NC} Piping remote content to shell in $file: $line" | tee -a "$vuln_log"
        fi
        
        # Check for eval with variables
        if echo "$line" | grep -qE 'eval.*\$'; then
            echo "${YELLOW}[MEDIUM]${NC} Eval with variable in $file: $line" | tee -a "$vuln_log"
        fi
        
        # Check for suspicious base64
        if echo "$line" | grep -qE 'base64.*-d.*\|.*sh'; then
            echo "${RED}[HIGH]${NC} Decoding base64 to shell in $file: $line" | tee -a "$vuln_log"
        fi
        
        # Check for potential credential exposure
        if echo "$line" | grep -qiE '(password|passwd|pwd|secret|api_key|apikey|token|credential)='; then
            # Exclude common safe patterns
            if ! echo "$line" | grep -qE '(read|prompt|input|\$\{|\$\()'; then
                echo "${YELLOW}[MEDIUM]${NC} Potential credential in $file: $line" | tee -a "$vuln_log"
            fi
        fi
        
        # Check for PATH manipulation with risky directories
        if echo "$line" | grep -qE 'PATH.*(/tmp|/var/tmp|/dev/shm)'; then
            echo "${YELLOW}[MEDIUM]${NC} PATH includes temp directory in $file: $line" | tee -a "$vuln_log"
        fi
        
        # Check for sourcing from world-writable locations
        if echo "$line" | grep -qE '(source|\.).*(/tmp|/var/tmp|/dev/shm)'; then
            echo "${RED}[HIGH]${NC} Sourcing from world-writable location in $file: $line" | tee -a "$vuln_log"
        fi
        
        # Check for suspicious network operations
        if echo "$line" | grep -qE 'nc.*-e|ncat.*-e|/dev/tcp/'; then
            echo "${RED}[CRITICAL]${NC} Suspicious network operation in $file: $line" | tee -a "$vuln_log"
        fi
        
        # Check for chmod 777
        if echo "$line" | grep -qE 'chmod.*(777|a\+rwx)'; then
            echo "${YELLOW}[MEDIUM]${NC} Overly permissive chmod in $file: $line" | tee -a "$vuln_log"
        fi
        
    done < "$file"
}

compile_user_profile() {
    username="$1"
    user_home="$2"
    output_file="$AUDIT_DIR/${username}_profile_$TIMESTAMP.sh"
    
    log_message "Processing user: $username (home: $user_home)"
    
    # Start compilation
    {
        echo "#!/bin/sh"
        echo "# Compiled profile for user: $username"
        echo "# Generated: $(date)"
        echo "# Home directory: $user_home"
        echo ""
        echo "################################################################################"
        echo "# SYSTEM-WIDE PROFILES"
        echo "################################################################################"
        echo ""
    } > "$output_file"
    
    # Add system-wide profiles
    for sys_profile in $SYSTEM_PROFILES; do
        if [ -f "$sys_profile" ]; then
            {
                echo "# --- Source: $sys_profile ---"
                cat "$sys_profile"
                echo ""
            } >> "$output_file"
            check_vulnerability "$sys_profile" "$username"
        fi
    done
    
    # Check /etc/profile.d/
    if [ -d "/etc/profile.d" ]; then
        {
            echo "# --- Source: /etc/profile.d/*.sh ---"
        } >> "$output_file"
        
        for script in /etc/profile.d/*.sh; do
            if [ -f "$script" ]; then
                {
                    echo "# From: $script"
                    cat "$script"
                    echo ""
                } >> "$output_file"
                check_vulnerability "$script" "$username"
            fi
        done
    fi
    
    {
        echo ""
        echo "################################################################################"
        echo "# USER-SPECIFIC PROFILES"
        echo "################################################################################"
        echo ""
    } >> "$output_file"
    
    # Add user-specific profiles
    for user_profile in $USER_PROFILES; do
        full_path="$user_home/$user_profile"
        if [ -f "$full_path" ]; then
            {
                echo "# --- Source: $full_path ---"
                cat "$full_path"
                echo ""
            } >> "$output_file"
            check_vulnerability "$full_path" "$username"
        fi
    done
    
    # Check for .ssh/rc
    if [ -f "$user_home/.ssh/rc" ]; then
        {
            echo "# --- Source: $user_home/.ssh/rc (SSH RC file) ---"
            cat "$user_home/.ssh/rc"
            echo ""
        } >> "$output_file"
        check_vulnerability "$user_home/.ssh/rc" "$username"
    fi
    
    # Make output file read-only
    chmod 400 "$output_file"
    log_message "Created: $output_file"
}

# Main execution
log_message "Starting profile audit"

# Get list of users with login shells
while IFS=: read -r username _ uid _ _ home shell; do
    # Skip system users (UID < 1000) and users with nologin/false shells
    # Adjust UID threshold as needed for your system
    case "$shell" in
        */nologin|*/false) continue ;;
    esac
    
    # Skip if UID is less than 1000 (typical system user threshold)
    # Comment out if you want to audit all users
    if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
        continue
    fi
    
    # Skip if home directory doesn't exist
    if [ ! -d "$home" ]; then
        log_message "Skipping $username: home directory $home does not exist"
        continue
    fi
    
    compile_user_profile "$username" "$home"
    
done < /etc/passwd

# Generate summary report
summary_file="$LOG_DIR/summary_$TIMESTAMP.txt"
{
    echo "Profile Audit Summary"
    echo "====================="
    echo "Date: $(date)"
    echo ""
    echo "Files audited:"
    ls -1 "$AUDIT_DIR"/*_profile_$TIMESTAMP.sh 2>/dev/null | wc -l
    echo ""
    echo "Vulnerabilities found:"
    grep -h "\[CRITICAL\]" "$LOG_DIR"/vulnerabilities_*_$TIMESTAMP.log 2>/dev/null | wc -l | xargs echo "Critical:"
    grep -h "\[HIGH\]" "$LOG_DIR"/vulnerabilities_*_$TIMESTAMP.log 2>/dev/null | wc -l | xargs echo "High:"
    grep -h "\[MEDIUM\]" "$LOG_DIR"/vulnerabilities_*_$TIMESTAMP.log 2>/dev/null | wc -l | xargs echo "Medium:"
    echo ""
    echo "Detailed logs available in: $LOG_DIR"
} > "$summary_file"

cat "$summary_file"
log_message "Audit complete. Summary: $summary_file"

# Optional: Create latest symlinks for easy access
ln -sf "$summary_file" "$LOG_DIR/latest_summary.txt"
log_message "Done. Results in: $AUDIT_DIR"