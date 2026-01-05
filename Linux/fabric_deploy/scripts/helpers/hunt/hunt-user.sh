#!/bin/sh
# POSIX-compliant user activity tracking script
# Tracks all activity by a specific user (by username or UID)
# Usage: ./hunt-user.sh <username|uid> [-ts timespec]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
fi

usage() {
    printf "Usage: %s <username|uid> [ausearch options]\n" "$(basename "$0")"
    printf "\nTrack all activity by a specific user.\n"
    printf "\nThis tracks:\n"
    printf "  - Commands executed by the user\n"
    printf "  - Files accessed/modified by the user\n"
    printf "  - Privilege escalation attempts\n"
    printf "  - Network activity by the user\n"
    printf "\nOptions:\n"
    printf "  username|uid     Username or numeric UID to track\n"
    printf "  -ts <timespec>   Start time (e.g., 'today', 'recent')\n"
    printf "\nExamples:\n"
    printf "  %s root                     # Track root activity\n" "$(basename "$0")"
    printf "  %s 1000 -ts today           # Track UID 1000 today\n" "$(basename "$0")"
    printf "  %s www-data -ts recent      # Track www-data recently\n" "$(basename "$0")"
    exit 1
}

check_privileges() {
    if ! ausearch -m SYSCALL --format text > /dev/null 2>&1; then
        printf "${RED}Error: Cannot access audit logs.${NC}\n" >&2
        exit 1
    fi
}

# Resolve username to UID
resolve_user() {
    user="$1"

    # Check if already a UID
    case "$user" in
        ''|*[!0-9]*)
            # Not a number, resolve username
            uid=$(getent passwd "$user" 2>/dev/null | cut -d: -f3)
            if [ -z "$uid" ]; then
                printf "${RED}Error: User '%s' not found${NC}\n" "$user" >&2
                exit 1
            fi
            printf "%s" "$uid"
            ;;
        *)
            # Already a UID
            printf "%s" "$user"
            ;;
    esac
}

# Categorize activity type
categorize_activity() {
    exe="$1"
    key="$2"
    syscall="$3"

    # Check key first
    case "$key" in
        privesc_*|ccdc_passwd)
            printf "${RED}[PRIVESC]${NC}"
            return
            ;;
        c2_*|ccdc_netcat)
            printf "${RED}[C2]${NC}"
            return
            ;;
        persist_*|ccdc_systemd|ccdc_cron)
            printf "${YELLOW}[PERSIST]${NC}"
            return
            ;;
        defense_*)
            printf "${YELLOW}[DEFENSE]${NC}"
            return
            ;;
        exec_shell)
            printf "${BLUE}[SHELL]${NC}"
            return
            ;;
        net_*)
            printf "${MAGENTA}[NETWORK]${NC}"
            return
            ;;
    esac

    # Check syscall
    case "$syscall" in
        execve)
            printf "${BLUE}[EXEC]${NC}"
            return
            ;;
        open*|read|write)
            printf "${GREEN}[FILE]${NC}"
            return
            ;;
        connect|socket|bind|listen)
            printf "${MAGENTA}[NETWORK]${NC}"
            return
            ;;
        chmod|chown|setxattr)
            printf "${YELLOW}[PERM]${NC}"
            return
            ;;
    esac

    # Check executable
    case "$exe" in
        */sudo|*/su|*/pkexec)
            printf "${RED}[PRIVESC]${NC}"
            return
            ;;
        */ssh|*/scp|*/sftp)
            printf "${MAGENTA}[REMOTE]${NC}"
            return
            ;;
        */bash|*/sh|*/zsh|*/fish)
            printf "${BLUE}[SHELL]${NC}"
            return
            ;;
    esac

    printf "${NC}[OTHER]${NC}"
}

process_event() {
    awk -v red="$RED" -v green="$GREEN" -v yellow="$YELLOW" -v blue="$BLUE" -v cyan="$CYAN" -v magenta="$MAGENTA" -v bold="$BOLD" -v nc="$NC" '
    BEGIN {
        time=""; pid=""; ppid=""; uid=""; euid=""; exe=""
        cmdline=""; success=""; key=""; syscall=""; path=""
    }
    /^type=SYSCALL/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^pid=/) { sub(/pid=/, "", $i); pid = $i }
            if ($i ~ /^ppid=/) { sub(/ppid=/, "", $i); ppid = $i }
            if ($i ~ /^uid=/) { sub(/uid=/, "", $i); uid = $i }
            if ($i ~ /^euid=/) { sub(/euid=/, "", $i); euid = $i }
            if ($i ~ /^success=/) { sub(/success=/, "", $i); success = $i }
            if ($i ~ /^syscall=/) { sub(/syscall=/, "", $i); syscall = $i }
            if ($i ~ /^exe=/) {
                sub(/exe=/, "", $i)
                gsub(/"/, "", $i)
                exe = $i
            }
            if ($i ~ /^key=/) {
                sub(/key=/, "", $i)
                gsub(/"/, "", $i)
                key = $i
            }
        }
        if (match($0, /msg=audit\([0-9]+\.[0-9]+:[0-9]+\)/)) {
            ts = substr($0, RSTART, RLENGTH)
            gsub(/msg=audit\(/, "", ts)
            gsub(/:[0-9]+\)/, "", ts)
            cmd = "date -d @" int(ts) " \"+%H:%M:%S\" 2>/dev/null"
            cmd | getline time
            close(cmd)
            if (time == "") time = ts
        }
    }
    /^type=EXECVE/ {
        args = ""
        for (i=1; i<=NF; i++) {
            if ($i ~ /^a[0-9]+=/) {
                val = $i
                sub(/^a[0-9]+=/, "", val)
                gsub(/"/, "", val)
                if (args != "") args = args " "
                args = args val
            }
        }
        if (args != "") cmdline = args
    }
    /^type=PATH/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^name=/) {
                sub(/name=/, "", $i)
                gsub(/"/, "", $i)
                if (length($i) > length(path)) path = $i
            }
        }
    }
    END {
        if (pid != "") {
            # Status
            if (success == "yes") {
                status = green "[OK]" nc
            } else {
                status = red "[FAIL]" nc
            }

            printf "%s %s %-6s", status, cyan time nc, pid

            # Executable (shortened)
            short_exe = exe
            gsub(/.*\//, "", short_exe)
            printf " %s%-12s%s", yellow, short_exe, nc

            # Command or path
            if (cmdline != "") {
                if (length(cmdline) > 50) cmdline = substr(cmdline, 1, 50) "..."
                printf " %s", cmdline
            } else if (path != "") {
                if (length(path) > 50) path = substr(path, 1, 50) "..."
                printf " -> %s", path
            }

            printf "\n"

            # Output for categorization
            printf "CAT|%s|%s|%s\n", exe, key, syscall
        }
    }
    '
}

main() {
    if [ $# -lt 1 ]; then
        usage
    fi

    user="$1"
    shift

    check_privileges

    # Resolve user
    uid=$(resolve_user "$user")
    username=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "uid:$uid")

    printf "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${CYAN}║${NC}          ${BOLD}User Activity Tracker${NC}                           ${CYAN}║${NC}\n"
    printf "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    printf "${BOLD}Target User:${NC} ${YELLOW}%s${NC} (UID: %s)\n\n" "$username" "$uid"

    # Get user info
    user_info=$(getent passwd "$uid" 2>/dev/null)
    if [ -n "$user_info" ]; then
        home=$(echo "$user_info" | cut -d: -f6)
        shell=$(echo "$user_info" | cut -d: -f7)
        printf "${BOLD}Home:${NC}  %s\n" "$home"
        printf "${BOLD}Shell:${NC} %s\n\n" "$shell"
    fi

    # Count events
    exec_count=$(ausearch -ui "$uid" -m SYSCALL "$@" 2>/dev/null | grep "syscall=execve" | wc -l || echo "0")
    file_count=$(ausearch -ui "$uid" -m SYSCALL "$@" 2>/dev/null | grep -E "syscall=(open|read|write|unlink)" | wc -l || echo "0")
    net_count=$(ausearch -ui "$uid" -m SYSCALL "$@" 2>/dev/null | grep -E "syscall=(connect|socket|bind)" | wc -l || echo "0")

    printf "${BOLD}Activity Summary:${NC}\n"
    printf "  Command executions: %s\n" "$exec_count"
    printf "  File operations:    %s\n" "$file_count"
    printf "  Network operations: %s\n\n" "$net_count"

    # Also check auid (audit login ID) - catches su/sudo
    printf "${BOLD}Tracking activity by UID and AUID (catches privilege escalation)...${NC}\n\n"

    # Command executions
    printf "${BOLD}${BLUE}Command Executions:${NC}\n"
    printf "════════════════════════════════════════════════════════════\n"

    {
        ausearch -ui "$uid" -m SYSCALL,EXECVE "$@" 2>/dev/null | grep -A20 "syscall=execve"
        ausearch -ua "$uid" -m SYSCALL,EXECVE "$@" 2>/dev/null | grep -A20 "syscall=execve"
    } | awk '
    /^----/ { if (record != "") print record; record = ""; next }
    { record = record $0 "\n" }
    END { if (record != "") print record }
    ' | sort -u | head -100 | while IFS= read -r record; do
        output=$(printf "%s" "$record" | process_event)
        main_line=$(printf "%s" "$output" | grep -v "^CAT|" | head -1)
        cat_line=$(printf "%s" "$output" | grep "^CAT|" | head -1)

        if [ -n "$main_line" ]; then
            # Get category
            if [ -n "$cat_line" ]; then
                exe=$(printf "%s" "$cat_line" | cut -d'|' -f2)
                key=$(printf "%s" "$cat_line" | cut -d'|' -f3)
                syscall=$(printf "%s" "$cat_line" | cut -d'|' -f4)
                cat=$(categorize_activity "$exe" "$key" "$syscall")
                printf "  %b %s\n" "$cat" "$main_line"
            else
                printf "  %s\n" "$main_line"
            fi
        fi
    done

    # Check for suspicious activity
    printf "\n${BOLD}${RED}Suspicious Activity Check:${NC}\n"
    printf "════════════════════════════════════════════════════════════\n\n"

    suspicious=0

    # Check for privilege escalation
    privesc=$(ausearch -ui "$uid" -k privesc_root_cmd "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
    if [ "$privesc" -gt 0 ]; then
        printf "${RED}[!] Privilege escalation: %d events${NC}\n" "$privesc"
        suspicious=1
    fi

    # Check for C2 tools
    c2=$(ausearch -ui "$uid" -k c2_susp_tools "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
    c2_2=$(ausearch -ui "$uid" -k ccdc_netcat "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
    c2_total=$((c2 + c2_2))
    if [ "$c2_total" -gt 0 ]; then
        printf "${RED}[!] C2/suspicious tools: %d events${NC}\n" "$c2_total"
        suspicious=1
    fi

    # Check for persistence
    persist=$(ausearch -ui "$uid" -m SYSCALL "$@" 2>/dev/null | grep -E "key=\"persist_" | wc -l || echo "0")
    if [ "$persist" -gt 0 ]; then
        printf "${YELLOW}[!] Persistence mechanisms: %d events${NC}\n" "$persist"
        suspicious=1
    fi

    # Check for shell access from tmp
    tmp_exec=$(ausearch -ui "$uid" -m SYSCALL "$@" 2>/dev/null | grep 'exe="/tmp\|exe="/dev/shm\|exe="/var/tmp' | wc -l || echo "0")
    if [ "$tmp_exec" -gt 0 ]; then
        printf "${RED}[!] Execution from temp directories: %d events${NC}\n" "$tmp_exec"
        suspicious=1
    fi

    if [ "$suspicious" -eq 0 ]; then
        printf "${GREEN}No obviously suspicious activity detected.${NC}\n"
    fi

    printf "\n${BOLD}══════════════════════════════════════════════════${NC}\n"
    printf "To trace a specific process: ./trace-parent.sh <pid>\n"
    printf "To export full activity: ausearch -ui %s -i > user_%s_activity.log\n\n" "$uid" "$username"
}

main "$@"
