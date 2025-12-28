#!/bin/bash
#
# blue-sweet-tooth Shell - Logs all commands and prevents escape
#

# Configuration
LOG_FILE="/var/log/blue-sweet-tooth/commands.log"
LOG_DIR="/var/log/blue-sweet-tooth"
FAKE_HOSTNAME="${HOSTNAME:-localhost}"

# Create log directory if it doesn't exist (requires appropriate permissions)
if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR" 2>/dev/null
fi

# Ensure log file exists and is writable
touch "$LOG_FILE" 2>/dev/null

# Function to log commands with metadata
log_command() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local user="${USER:-unknown}"
    local ip="${SSH_CLIENT%% *}"
    [[ -z "$ip" ]] && ip="${SSH_CONNECTION%% *}"
    [[ -z "$ip" ]] && ip="local"
    
    echo "$timestamp | USER=$user | IP=$ip | PWD=$PWD | CMD=$*" >> "$LOG_FILE" 2>/dev/null
}

# Simulate a realistic prompt
show_prompt() {
    echo -n "[$USER@$FAKE_HOSTNAME $(basename "$PWD")]$ "
}

# Simulate command output for common commands
simulate_output() {
    local cmd="$1"
    
    case "$cmd" in
        ls|ls\ *)
            # Simulate some files
            echo "file1.txt  file2.txt  directory1"
            ;;
        pwd)
            echo "$PWD"
            ;;
        whoami)
            echo "$USER"
            ;;
        id)
            echo "uid=1000($USER) gid=1000($USER) groups=1000($USER)"
            ;;
        uname*)
            echo "Linux $FAKE_HOSTNAME 5.10.0-generic #1 SMP $(date '+%a %b %d %H:%M:%S UTC %Y') x86_64 GNU/Linux"
            ;;
        cat\ /etc/passwd|cat\ /etc/shadow|cat\ /etc/group)
            echo "cat: $2: Permission denied"
            ;;
        sudo*)
            echo "[$USER] password required"
            echo "Sorry, try again."
            ;;
        *)
            # For most commands, just return silently as if successful
            ;;
    esac
}

# Display fake welcome message
echo "Last login: $(date '+%a %b %d %H:%M:%S %Y') from ${SSH_CLIENT%% *}"
echo ""

# Disable common escape mechanisms
export SHELL="/bin/blue-sweet-tooth"
unset ENV
unset BASH_ENV

# Main loop - read commands and log them
while true; do
    show_prompt
    
    # Read command with readline if available, plain read otherwise
    if command -v read >/dev/null 2>&1; then
        IFS= read -r command || {
            echo ""
            log_command "SESSION_END"
            exit 0
        }
    else
        IFS= read command || {
            echo ""
            log_command "SESSION_END"
            exit 0
        }
    fi
    
    # Skip empty commands
    [[ -z "$command" ]] && continue
    
    # Log the command
    log_command "$command"
    
    # Check for exit/logout commands
    case "$command" in
        exit|logout|quit)
            echo "logout"
            log_command "USER_LOGOUT"
            exit 0
            ;;
        # Prevent common escape attempts
        */bin/bash|*/bin/sh|bash|sh|exec\ *|source\ *|.\ *)
            simulate_output "$command"
            ;;
        # Handle cd specially to maintain illusion
        cd\ *|cd)
            # Don't actually change directory, just pretend
            simulate_output "$command"
            ;;
        *)
            # Simulate successful execution
            simulate_output "$command"
            ;;
    esac
    
    # Always return success
    true
done