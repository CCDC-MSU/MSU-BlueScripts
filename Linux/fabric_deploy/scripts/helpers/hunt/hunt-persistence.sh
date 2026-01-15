#!/bin/sh
# POSIX-compliant persistence mechanism detection script
# Finds modifications to cron, systemd, init scripts, shell configs, etc.
# Usage: ./hunt-persistence.sh [-ts timespec]

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

# Persistence-related audit keys
PERSIST_KEYS="persist_modify persist_cron persist_sched_task persist_boot persist_accounts persist_shell_config persist_webshell persist_event_trigger ccdc_systemd ccdc_initd ccdc_bashrc ccdc_adduser ccdc_useradd"

usage() {
    printf "Usage: %s [ausearch options]\n" "$(basename "$0")"
    printf "\nDetect persistence mechanism modifications.\n"
    printf "\nThis script searches for modifications to:\n"
    printf "  - Cron jobs and scheduled tasks\n"
    printf "  - Systemd services and timers\n"
    printf "  - Init scripts (rc.local, init.d)\n"
    printf "  - Shell configuration files (.bashrc, .profile)\n"
    printf "  - User accounts and SSH keys\n"
    printf "  - Web shells and CGI scripts\n"
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

# Categorize persistence type
categorize_persistence() {
    path="$1"
    key="$2"

    case "$path" in
        */cron*|*/at/*|*/anacron*)
            printf "${RED}[CRON]${NC} Scheduled task modification"
            return
            ;;
        */systemd/system/*|*/systemd/user/*)
            printf "${RED}[SYSTEMD]${NC} Service/timer modification"
            return
            ;;
        */init.d/*|*/rc.local|*/rc.d/*)
            printf "${RED}[INIT]${NC} Boot script modification"
            return
            ;;
        */.bashrc|*/.bash_profile|*/.profile|*/.zshrc|*/bash.bashrc|*/profile)
            printf "${YELLOW}[SHELL]${NC} Shell config modification"
            return
            ;;
        */.ssh/authorized_keys|*/.ssh/config)
            printf "${RED}[SSH]${NC} SSH configuration change"
            return
            ;;
        */passwd|*/shadow|*/group|*/sudoers*)
            printf "${RED}[ACCOUNT]${NC} Account/auth modification"
            return
            ;;
        */www/*|*/html/*|*/cgi-bin/*)
            printf "${RED}[WEBSHELL]${NC} Web directory modification"
            return
            ;;
        */ld.so.preload|*/ld.so.conf*)
            printf "${RED}[HIJACK]${NC} Library preload modification"
            return
            ;;
        */udev/rules.d/*)
            printf "${YELLOW}[UDEV]${NC} Device event trigger"
            return
            ;;
        */modprobe.d/*|*/modules/*)
            printf "${RED}[KERNEL]${NC} Kernel module configuration"
            return
            ;;
    esac

    case "$key" in
        *persist*) printf "${YELLOW}[PERSIST]${NC} Persistence mechanism" ;;
        *ccdc*) printf "${RED}[CCDC]${NC} High-priority modification" ;;
        *) printf "${BLUE}[CONFIG]${NC} Configuration change" ;;
    esac
}

process_event() {
    awk -v red="$RED" -v green="$GREEN" -v yellow="$YELLOW" -v blue="$BLUE" -v cyan="$CYAN" -v bold="$BOLD" -v nc="$NC" '
    BEGIN {
        time=""; pid=""; uid=""; auid=""; exe=""
        success=""; key=""; path=""; nametype=""
    }
    /^type=SYSCALL/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^pid=/) { sub(/pid=/, "", $i); pid = $i }
            if ($i ~ /^uid=/) { sub(/uid=/, "", $i); uid = $i }
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
    /^type=PATH/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^name=/) {
                sub(/name=/, "", $i)
                gsub(/"/, "", $i)
                # Get the most specific path
                if (length($i) > length(path)) path = $i
            }
            if ($i ~ /^nametype=/) {
                sub(/nametype=/, "", $i)
                nametype = $i
            }
        }
    }
    END {
        if (pid != "" && path != "") {
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

            if (success == "yes") {
                printf "  %s[SUCCESS]%s ", green, nc
            } else {
                printf "  %s[FAILED]%s  ", red, nc
            }
            printf "%s%s%s\n", cyan, time, nc

            printf "  Path: %s%s%s", red, path, nc
            if (nametype != "") printf " (%s)", nametype
            printf "\n"

            printf "  User: %s", uname
            if (aname != "") printf " (login: %s)", aname
            printf "\n"

            printf "  Tool: %s\n", exe
            printf "  PID:  %s  Key: %s%s%s\n", pid, yellow, key, nc

            # Output for categorization
            printf "ANALYZE|%s|%s\n", path, key
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
    printf "${CYAN}║${NC}          ${BOLD}${RED}Persistence Mechanism Hunter${NC}                    ${CYAN}║${NC}\n"
    printf "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    printf "${BOLD}Scanning for modifications to:${NC}\n"
    printf "  - Cron jobs, systemd services, init scripts\n"
    printf "  - Shell configs, SSH keys, user accounts\n"
    printf "  - Web directories, library preloads\n\n"

    total=0
    critical=0

    # Search by persistence keys
    printf "${BOLD}Searching audit keys...${NC}\n\n"

    for key in $PERSIST_KEYS; do
        count=$(ausearch -k "$key" "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        if [ "$count" -gt 0 ]; then
            printf "${RED}━━━ Key: %s (%d events) ━━━${NC}\n\n" "$key" "$count"
            total=$((total + count))

            # Check for critical keys
            case "$key" in
                ccdc_*|persist_accounts|persist_shell_config)
                    critical=$((critical + count))
                    ;;
            esac

            ausearch -k "$key" "$@" -i 2>/dev/null | awk '
            /^----/ { if (record != "") print record; record = ""; next }
            { record = record $0 "\n" }
            END { if (record != "") print record }
            ' | while IFS= read -r record; do
                output=$(printf "%s" "$record" | process_event)
                printf "%s" "$output" | grep -v "^ANALYZE|"

                # Extract and categorize
                analyze_line=$(printf "%s" "$output" | grep "^ANALYZE|" | head -1)
                if [ -n "$analyze_line" ]; then
                    path=$(printf "%s" "$analyze_line" | cut -d'|' -f2)
                    akey=$(printf "%s" "$analyze_line" | cut -d'|' -f3)
                    printf "  "
                    categorize_persistence "$path" "$akey"
                    printf "\n"
                fi
                printf "\n"
            done
        fi
    done

    # Summary of critical files
    printf "\n${BOLD}Quick Check - Recently Modified Persistence Locations:${NC}\n"
    printf "════════════════════════════════════════════════════════════\n\n"

    printf "${YELLOW}Crontabs:${NC}\n"
    ls -la /var/spool/cron/* /etc/cron.d/* 2>/dev/null | head -5 || printf "  (none found)\n"
    printf "\n"

    printf "${YELLOW}Systemd user services:${NC}\n"
    find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -1 2>/dev/null | head -5 || printf "  (no recent changes)\n"
    printf "\n"

    printf "\n${BOLD}══════════════════════════════════════════════════${NC}\n"
    if [ "$total" -gt 0 ]; then
        if [ "$critical" -gt 0 ]; then
            printf "${RED}CRITICAL: %d high-priority persistence events!${NC}\n" "$critical"
        fi
        printf "${YELLOW}ALERT: %d total persistence events detected.${NC}\n\n" "$total"
        printf "Recommended actions:\n"
        printf "  1. Review each modified file for malicious content\n"
        printf "  2. Check crontab -l for all users\n"
        printf "  3. List enabled systemd services: systemctl list-unit-files\n"
        printf "  4. Review /etc/passwd and /etc/shadow timestamps\n"
        printf "  5. Check authorized_keys in all home directories\n"
    else
        printf "${GREEN}No persistence modifications detected.${NC}\n"
    fi
    printf "\n"
}

main "$@"
