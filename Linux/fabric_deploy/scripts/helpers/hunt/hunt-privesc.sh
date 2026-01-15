#!/bin/sh
# POSIX-compliant privilege escalation detection script
# Finds sudo, su, setuid abuse, and commands run as root
# Usage: ./hunt-privesc.sh [-ts timespec]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

# Privilege escalation related keys
PRIVESC_KEYS="privesc_root_cmd privesc_sudoers privesc_su privesc privesc_abuse"

usage() {
    printf "Usage: %s [ausearch options]\n" "$(basename "$0")"
    printf "\nDetect privilege escalation attempts and root command execution.\n"
    printf "\nThis script searches for:\n"
    printf "  - Commands executed as root by non-root users\n"
    printf "  - sudo and su usage\n"
    printf "  - Sudoers file modifications\n"
    printf "  - Setuid/setgid abuse\n"
    printf "  - Permission modifications (chmod, chown)\n"
    printf "\nOptions:\n"
    printf "  -ts <timespec>   Start time (e.g., 'today', 'recent')\n"
    printf "\nExamples:\n"
    printf "  %s                   # Search all logs\n" "$(basename "$0")"
    printf "  %s -ts today         # Today's events only\n" "$(basename "$0")"
    exit 1
}

check_privileges() {
    if ! ausearch -m SYSCALL --format text > /dev/null 2>&1; then
        printf "${RED}Error: Cannot access audit logs.${NC}\n" >&2
        exit 1
    fi
}

# Analyze privilege escalation type
analyze_privesc() {
    exe="$1"
    cmdline="$2"
    uid="$3"
    euid="$4"
    auid="$5"

    # Check for sudo
    case "$exe" in
        */sudo)
            if printf "%s" "$cmdline" | grep -qE '(bash|sh|su|\-i|\-s)'; then
                printf "${RED}[SHELL]${NC} Sudo shell access\n"
            else
                printf "${YELLOW}[SUDO]${NC} Privileged command execution\n"
            fi
            return
            ;;
        */su)
            printf "${RED}[SU]${NC} User switch attempt\n"
            return
            ;;
        */pkexec)
            printf "${RED}[PKEXEC]${NC} PolicyKit elevation\n"
            return
            ;;
    esac

    # Check for setuid binaries being abused
    case "$exe" in
        */passwd|*/chsh|*/chfn|*/gpasswd|*/newgrp)
            printf "${YELLOW}[SETUID]${NC} Password/group utility\n"
            return
            ;;
        */mount|*/umount)
            printf "${YELLOW}[MOUNT]${NC} Mount operation\n"
            return
            ;;
    esac

    # Check for suspicious patterns
    case "$cmdline" in
        *"chmod +s"*|*"chmod u+s"*|*"chmod g+s"*)
            printf "${RED}[CRITICAL]${NC} Setting setuid/setgid bit!\n"
            return
            ;;
        *"chmod 4"*|*"chmod 2"*)
            printf "${RED}[CRITICAL]${NC} Numeric setuid/setgid chmod!\n"
            return
            ;;
        *"/etc/passwd"*|*"/etc/shadow"*)
            printf "${RED}[CRITICAL]${NC} Accessing authentication files\n"
            return
            ;;
        *"/etc/sudoers"*)
            printf "${RED}[CRITICAL]${NC} Sudoers file access\n"
            return
            ;;
    esac

    # Root execution by non-root login user
    if [ "$euid" = "0" ] && [ -n "$auid" ] && [ "$auid" != "0" ] && [ "$auid" != "4294967295" ]; then
        printf "${YELLOW}[ELEVATED]${NC} Root execution by user auid=%s\n" "$auid"
        return
    fi

    printf "${BLUE}[INFO]${NC} Privileged operation\n"
}

process_event() {
    awk -v red="$RED" -v green="$GREEN" -v yellow="$YELLOW" -v blue="$BLUE" -v cyan="$CYAN" -v bold="$BOLD" -v nc="$NC" '
    BEGIN {
        time=""; pid=""; ppid=""; uid=""; euid=""; auid=""; exe=""
        cmdline=""; success=""; key=""
    }
    /^type=SYSCALL/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^pid=/) { sub(/pid=/, "", $i); pid = $i }
            if ($i ~ /^ppid=/) { sub(/ppid=/, "", $i); ppid = $i }
            if ($i ~ /^uid=/) { sub(/uid=/, "", $i); uid = $i }
            if ($i ~ /^euid=/) { sub(/euid=/, "", $i); euid = $i }
            if ($i ~ /^auid=/) { sub(/auid=/, "", $i); auid = $i }
            if ($i ~ /^success=/) { sub(/success=/, "", $i); success = $i }
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
            cmd = "date -d @" int(ts) " \"+%Y-%m-%d %H:%M:%S\" 2>/dev/null"
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
    END {
        if (pid != "") {
            # Resolve usernames
            cmd = "getent passwd " uid " 2>/dev/null | cut -d: -f1"
            cmd | getline uname
            close(cmd)
            if (uname == "") uname = "uid:" uid

            aname = ""
            if (auid != "" && auid != "4294967295") {
                cmd = "getent passwd " auid " 2>/dev/null | cut -d: -f1"
                cmd | getline aname
                close(cmd)
                if (aname == "") aname = "auid:" auid
            }

            printf "%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", bold, nc

            # Status indicator
            if (success == "yes") {
                printf "  %s[SUCCESS]%s ", green, nc
            } else {
                printf "  %s[FAILED]%s  ", red, nc
            }
            printf "%s%s%s\n", cyan, time, nc

            printf "  PID: %-8s  PPID: %s\n", pid, ppid
            printf "  Running as: %s%s%s", yellow, uname, nc
            if (euid != "" && euid != uid) {
                printf " -> %seuid=%s%s", red, euid, nc
            }
            printf "\n"

            if (aname != "") {
                printf "  Login user: %s%s%s\n", blue, aname, nc
            }

            printf "  Exec: %s\n", exe

            if (cmdline != "") {
                if (length(cmdline) > 100) cmdline = substr(cmdline, 1, 100) "..."
                printf "  Cmd:  %s\n", cmdline
            }

            printf "  Key:  %s%s%s\n", yellow, key, nc

            # Output for analysis
            printf "ANALYZE|%s|%s|%s|%s|%s\n", exe, cmdline, uid, euid, auid
        }
    }
    '
}

main() {
    case "$1" in
        -h|--help) usage ;;
    esac

    check_privileges

    printf "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${CYAN}║${NC}          ${BOLD}${RED}Privilege Escalation Hunter${NC}                     ${CYAN}║${NC}\n"
    printf "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    printf "${BOLD}Scanning for:${NC}\n"
    printf "  - Root command execution by non-root users\n"
    printf "  - Sudo and su usage\n"
    printf "  - Sudoers modifications\n"
    printf "  - Setuid/setgid changes\n\n"

    total=0

    # Search by privilege escalation keys
    printf "${BOLD}Searching audit keys: ${YELLOW}%s${NC}\n\n" "$PRIVESC_KEYS"

    for key in $PRIVESC_KEYS; do
        count=$(ausearch -k "$key" "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        if [ "$count" -gt 0 ]; then
            printf "${RED}━━━ Key: %s (%d events) ━━━${NC}\n\n" "$key" "$count"
            total=$((total + count))

            ausearch -k "$key" "$@" -i 2>/dev/null | awk '
            /^----/ { if (record != "") print record; record = ""; next }
            { record = record $0 "\n" }
            END { if (record != "") print record }
            ' | while IFS= read -r record; do
                output=$(printf "%s" "$record" | process_event)
                printf "%s" "$output" | grep -v "^ANALYZE|"

                # Extract and analyze
                analyze_line=$(printf "%s" "$output" | grep "^ANALYZE|" | head -1)
                if [ -n "$analyze_line" ]; then
                    exe=$(printf "%s" "$analyze_line" | cut -d'|' -f2)
                    cmdline=$(printf "%s" "$analyze_line" | cut -d'|' -f3)
                    uid=$(printf "%s" "$analyze_line" | cut -d'|' -f4)
                    euid=$(printf "%s" "$analyze_line" | cut -d'|' -f5)
                    auid=$(printf "%s" "$analyze_line" | cut -d'|' -f6)
                    printf "  "
                    analyze_privesc "$exe" "$cmdline" "$uid" "$euid" "$auid"
                fi
                printf "\n"
            done
        fi
    done

    # Also check for permission modifications
    printf "\n${BOLD}Checking permission modifications (defense_perm_mod)...${NC}\n\n"
    perm_count=$(ausearch -k defense_perm_mod "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
    if [ "$perm_count" -gt 0 ]; then
        printf "${YELLOW}Found %d permission modification events${NC}\n" "$perm_count"
        printf "(Use 'hunt-by-key.sh defense_perm_mod' for details)\n"
        total=$((total + perm_count))
    fi

    printf "\n${BOLD}══════════════════════════════════════════════════${NC}\n"
    if [ "$total" -gt 0 ]; then
        printf "${RED}ALERT: %d privilege escalation events detected!${NC}\n\n" "$total"
        printf "Recommended actions:\n"
        printf "  1. Identify which users are escalating privileges\n"
        printf "  2. Check if escalations are authorized\n"
        printf "  3. Review sudoers file for unauthorized entries\n"
        printf "  4. Look for newly created setuid binaries\n"
        printf "  5. Trace suspicious PIDs: ./trace-parent.sh <pid>\n"
    else
        printf "${GREEN}No privilege escalation activity detected.${NC}\n"
    fi
    printf "\n"
}

main "$@"
