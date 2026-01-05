#!/bin/sh
# POSIX-compliant audit key search tool
# Search for events by audit key with formatted output
# Usage: ./hunt-by-key.sh <key> [-ts timespec]

set -e

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

usage() {
    printf "Usage: %s <key> [ausearch options]\n" "$(basename "$0")"
    printf "\nSearch audit logs by key and display formatted results.\n"
    printf "\nArguments:\n"
    printf "  key              Audit key to search (e.g., privesc_root_cmd)\n"
    printf "  -ts <timespec>   Start time (e.g., 'today', 'recent', '12/25/2024')\n"
    printf "\nExamples:\n"
    printf "  %s privesc_root_cmd\n" "$(basename "$0")"
    printf "  %s ccdc_web_exec -ts today\n" "$(basename "$0")"
    printf "  %s persist_cron -ts recent\n" "$(basename "$0")"
    printf "\nCommon keys from CCDC rules:\n"
    printf "  ${CYAN}High Priority (ccdc_*):${NC}\n"
    printf "    ccdc_web_exec    - Web server command execution\n"
    printf "    ccdc_netcat      - Netcat usage\n"
    printf "    ccdc_adduser     - User creation\n"
    printf "    ccdc_passwd      - Password changes\n"
    printf "    ccdc_ssh         - SSH config changes\n"
    printf "    ccdc_systemd     - Systemd modifications\n"
    printf "  ${CYAN}Privilege Escalation (privesc_*):${NC}\n"
    printf "    privesc_root_cmd - Commands run as root\n"
    printf "    privesc_sudoers  - Sudoers file changes\n"
    printf "  ${CYAN}Persistence (persist_*):${NC}\n"
    printf "    persist_cron     - Cron modifications\n"
    printf "    persist_boot     - Boot script changes\n"
    printf "    persist_accounts - Account modifications\n"
    printf "  ${CYAN}C2/Exfil (c2_*, exfil_*):${NC}\n"
    printf "    c2_susp_tools    - Suspicious tool execution\n"
    printf "    c2_dns           - DNS modifications\n"
    printf "    exfil_compress   - Compression tools\n"
    exit 1
}

check_privileges() {
    if ! ausearch -m SYSCALL --format text > /dev/null 2>&1; then
        printf "${RED}Error: Cannot access audit logs.${NC}\n" >&2
        printf "Run as root or with CAP_AUDIT_READ capability.\n" >&2
        exit 1
    fi
}

format_event() {
    # Parse and format a single audit event
    awk -v red="$RED" -v green="$GREEN" -v yellow="$YELLOW" -v blue="$BLUE" -v cyan="$CYAN" -v bold="$BOLD" -v nc="$NC" '
    BEGIN {
        time=""; pid=""; ppid=""; uid=""; auid=""; exe=""; key=""
        cmdline=""; success=""; syscall=""
    }
    /^type=SYSCALL/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^pid=/) { sub(/pid=/, "", $i); pid = $i }
            if ($i ~ /^ppid=/) { sub(/ppid=/, "", $i); ppid = $i }
            if ($i ~ /^uid=/) { sub(/uid=/, "", $i); uid = $i }
            if ($i ~ /^auid=/) { sub(/auid=/, "", $i); auid = $i }
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
        # Extract timestamp from msg field
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
    /^type=PATH/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^name=/) {
                sub(/name=/, "", $i)
                gsub(/"/, "", $i)
                if (path == "") path = $i
            }
        }
    }
    END {
        if (pid != "") {
            printf "%s──────────────────────────────────────────────────%s\n", bold, nc
            if (success == "yes") {
                printf "  %s[SUCCESS]%s ", green, nc
            } else {
                printf "  %s[FAILED]%s  ", red, nc
            }
            printf "%s%s%s\n", cyan, time, nc

            printf "  PID: %s%-8s%s  PPID: %s\n", blue, pid, nc, ppid

            # Resolve usernames
            cmd = "getent passwd " uid " 2>/dev/null | cut -d: -f1"
            cmd | getline uname
            close(cmd)
            if (uname == "") uname = uid
            printf "  User: %s (uid=%s)\n", uname, uid

            if (auid != "" && auid != "4294967295") {
                cmd = "getent passwd " auid " 2>/dev/null | cut -d: -f1"
                cmd | getline aname
                close(cmd)
                if (aname == "") aname = auid
                printf "  Login User: %s (auid=%s)\n", aname, auid
            }

            # Highlight suspicious paths
            if (exe ~ /^\/tmp\// || exe ~ /^\/dev\/shm\// || exe ~ /^\/var\/tmp\//) {
                printf "  Exec: %s%s%s %s(SUSPICIOUS PATH!)%s\n", red, exe, nc, yellow, nc
            } else {
                printf "  Exec: %s\n", exe
            }

            if (cmdline != "") {
                if (length(cmdline) > 100) cmdline = substr(cmdline, 1, 100) "..."
                printf "  Args: %s\n", cmdline
            }

            if (path != "" && path != exe) {
                printf "  Path: %s\n", path
            }

            printf "  Key:  %s%s%s\n", yellow, key, nc
        }
    }
    '
}

process_results() {
    key="$1"
    shift

    printf "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${CYAN}║${NC}          ${BOLD}Audit Key Search: ${YELLOW}%s${NC}                \n" "$key"
    printf "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    # Count events first
    count=$(ausearch -k "$key" "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")

    if [ "$count" -eq 0 ]; then
        printf "${YELLOW}No events found for key '%s'${NC}\n\n" "$key"
        printf "Suggestions:\n"
        printf "  - Try a different time range (-ts today, -ts this-week)\n"
        printf "  - Check if the audit rule is active: ausearch -k %s\n" "$key"
        printf "  - List available keys: ausearch -i | grep -oE 'key=[^ ]+' | sort -u\n"
        return 0
    fi

    printf "${GREEN}Found %d events${NC}\n\n" "$count"

    # Process each event
    ausearch -k "$key" "$@" -i 2>/dev/null | awk '
    /^----/ { if (record != "") print record; record = ""; next }
    { record = record $0 "\n" }
    END { if (record != "") print record }
    ' | while IFS= read -r record; do
        printf "%s" "$record" | format_event
    done

    printf "\n${BOLD}══════════════════════════════════════════════════${NC}\n"
    printf "${GREEN}Total: %d events for key '%s'${NC}\n\n" "$count" "$key"
}

main() {
    if [ $# -lt 1 ]; then
        usage
    fi

    key="$1"
    shift

    check_privileges
    process_results "$key" "$@"
}

main "$@"
