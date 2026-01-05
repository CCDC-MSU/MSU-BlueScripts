#!/bin/sh
# POSIX-compliant webshell detection script
# Finds commands executed by web server processes (www-data, apache, nginx)
# Usage: ./hunt-webshell.sh [-ts timespec]

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

# Web server UIDs (www-data=33, apache=48, nginx=987)
WEB_UIDS="33 48 987"
WEB_KEYS="ccdc_web_exec ccdc_web_socket webshell_net"

usage() {
    printf "Usage: %s [ausearch options]\n" "$(basename "$0")"
    printf "\nDetect potential webshell activity by monitoring web server process execution.\n"
    printf "\nThis script searches for:\n"
    printf "  - Commands executed by web server users (www-data, apache, nginx)\n"
    printf "  - Network socket creation by web processes\n"
    printf "  - Suspicious command patterns (shells, network tools, encoders)\n"
    printf "\nOptions:\n"
    printf "  -ts <timespec>   Start time (e.g., 'today', 'recent')\n"
    printf "\nExamples:\n"
    printf "  %s                   # Search all logs\n" "$(basename "$0")"
    printf "  %s -ts today         # Today's events only\n" "$(basename "$0")"
    printf "  %s -ts recent        # Last 10 minutes\n" "$(basename "$0")"
    exit 1
}

check_privileges() {
    if ! ausearch -m SYSCALL --format text > /dev/null 2>&1; then
        printf "${RED}Error: Cannot access audit logs.${NC}\n" >&2
        exit 1
    fi
}

# Suspicious commands that shouldn't be run by web servers
SUSPICIOUS_CMDS="sh bash dash zsh ksh csh tcsh nc ncat netcat socat curl wget python perl php ruby lua base64 xxd openssl ssh scp sftp ftp tftp telnet nmap id whoami uname cat less more head tail grep find xargs chmod chown rm mv cp mkdir"

analyze_command() {
    cmdline="$1"
    exe="$2"

    # Check for shell execution
    case "$exe" in
        */sh|*/bash|*/dash|*/zsh|*/ksh|*/csh|*/tcsh|*/ash)
            printf "${RED}[CRITICAL]${NC} Shell execution detected\n"
            return
            ;;
    esac

    # Check for suspicious patterns in command line
    case "$cmdline" in
        *"/dev/tcp/"*|*"/dev/udp/"*)
            printf "${RED}[CRITICAL]${NC} Bash network redirection (reverse shell pattern)\n"
            return
            ;;
        *"| sh"*|*"|sh"*|*"| bash"*|*"|bash"*)
            printf "${RED}[CRITICAL]${NC} Piped shell execution\n"
            return
            ;;
        *"base64 -d"*|*"base64 --decode"*)
            printf "${RED}[CRITICAL]${NC} Base64 decoding (encoded payload)\n"
            return
            ;;
        *"python -c"*|*"perl -e"*|*"ruby -e"*|*"php -r"*)
            printf "${RED}[CRITICAL]${NC} Inline code execution\n"
            return
            ;;
        *"nc -e"*|*"ncat -e"*|*"netcat -e"*)
            printf "${RED}[CRITICAL]${NC} Netcat with execute (backdoor)\n"
            return
            ;;
        *"curl"*"|"*|*"wget"*"|"*)
            printf "${RED}[CRITICAL]${NC} Download and pipe execution\n"
            return
            ;;
        *"/tmp/"*|*"/dev/shm/"*|*"/var/tmp/"*)
            printf "${YELLOW}[WARNING]${NC} Execution from temp directory\n"
            return
            ;;
    esac

    # Check for reconnaissance commands
    for cmd in $SUSPICIOUS_CMDS; do
        case "$exe" in
            *"/$cmd"|*"/$cmd."*)
                printf "${YELLOW}[SUSPICIOUS]${NC} %s execution by web server\n" "$cmd"
                return
                ;;
        esac
    done

    printf "${BLUE}[INFO]${NC} Command execution\n"
}

process_event() {
    awk -v red="$RED" -v green="$GREEN" -v yellow="$YELLOW" -v blue="$BLUE" -v cyan="$CYAN" -v bold="$BOLD" -v nc="$NC" '
    BEGIN {
        time=""; pid=""; ppid=""; uid=""; exe=""
        cmdline=""; success=""; key=""
    }
    /^type=SYSCALL/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^pid=/) { sub(/pid=/, "", $i); pid = $i }
            if ($i ~ /^ppid=/) { sub(/ppid=/, "", $i); ppid = $i }
            if ($i ~ /^uid=/) { sub(/uid=/, "", $i); uid = $i }
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
            # Resolve username
            cmd = "getent passwd " uid " 2>/dev/null | cut -d: -f1"
            cmd | getline uname
            close(cmd)
            if (uname == "") uname = "uid:" uid

            printf "%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", bold, nc
            printf "  %s%s%s | User: %s%s%s | PID: %s\n", cyan, time, nc, red, uname, nc, pid

            # Print executable with highlighting
            if (exe ~ /^\/tmp\// || exe ~ /^\/dev\/shm\// || exe ~ /^\/var\/tmp\//) {
                printf "  Exec: %s%s%s\n", red, exe, nc
            } else {
                printf "  Exec: %s\n", exe
            }

            # Print command line
            if (cmdline != "") {
                if (length(cmdline) > 120) cmdline = substr(cmdline, 1, 120) "..."
                printf "  Cmd:  %s\n", cmdline
            }

            printf "  Key:  %s%s%s | PPID: %s\n", yellow, key, nc, ppid

            # Output exe and cmdline for analysis
            printf "ANALYZE|%s|%s\n", exe, cmdline
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
    printf "${CYAN}║${NC}          ${BOLD}${RED}Webshell Detection Scanner${NC}                      ${CYAN}║${NC}\n"
    printf "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    printf "${BOLD}Scanning for:${NC}\n"
    printf "  - Web server command execution (www-data, apache, nginx)\n"
    printf "  - Network activity by web processes\n"
    printf "  - Suspicious command patterns\n\n"

    total=0
    critical=0
    warning=0

    # Search by keys first
    printf "${BOLD}Searching audit keys: ${YELLOW}%s${NC}\n\n" "$WEB_KEYS"

    for key in $WEB_KEYS; do
        count=$(ausearch -k "$key" "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        if [ "$count" -gt 0 ]; then
            printf "${RED}Found %d events for key '%s'${NC}\n\n" "$count" "$key"
            total=$((total + count))

            ausearch -k "$key" "$@" -i 2>/dev/null | awk '
            /^----/ { if (record != "") print record; record = ""; next }
            { record = record $0 "\n" }
            END { if (record != "") print record }
            ' | while IFS= read -r record; do
                output=$(printf "%s" "$record" | process_event)
                # Print everything except the ANALYZE line
                printf "%s" "$output" | grep -v "^ANALYZE|"

                # Extract and analyze
                analyze_line=$(printf "%s" "$output" | grep "^ANALYZE|" | head -1)
                if [ -n "$analyze_line" ]; then
                    exe=$(printf "%s" "$analyze_line" | cut -d'|' -f2)
                    cmdline=$(printf "%s" "$analyze_line" | cut -d'|' -f3-)
                    printf "  "
                    analyze_command "$cmdline" "$exe"
                fi
                printf "\n"
            done
        fi
    done

    # Also search by UID directly
    printf "\n${BOLD}Searching by web server UIDs...${NC}\n\n"

    for uid in $WEB_UIDS; do
        uname=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "uid:$uid")
        count=$(ausearch -ui "$uid" -m SYSCALL "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")

        if [ "$count" -gt 0 ]; then
            printf "${YELLOW}Found %d executions by %s (uid=%s)${NC}\n\n" "$count" "$uname" "$uid"
            total=$((total + count))
        fi
    done

    printf "\n${BOLD}══════════════════════════════════════════════════${NC}\n"
    if [ "$total" -gt 0 ]; then
        printf "${RED}ALERT: %d potential webshell events detected!${NC}\n\n" "$total"
        printf "Recommended actions:\n"
        printf "  1. Trace process ancestry: ./trace-parent.sh <pid>\n"
        printf "  2. Check web server logs for corresponding requests\n"
        printf "  3. Inspect files in /var/www/ and web directories\n"
        printf "  4. Look for recently modified PHP/CGI files\n"
    else
        printf "${GREEN}No webshell activity detected.${NC}\n"
    fi
    printf "\n"
}

main "$@"
