#!/bin/sh
# POSIX-compliant security event timeline generator
# Creates a chronological timeline of security-relevant events
# Usage: ./hunt-timeline.sh [-ts timespec] [-te timespec]

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

# High-priority keys for timeline
CRITICAL_KEYS="ccdc_web_exec ccdc_netcat ccdc_adduser ccdc_useradd ccdc_passwd ccdc_ssh ccdc_systemd"
HIGH_KEYS="privesc_root_cmd privesc_sudoers c2_susp_tools c2_tools persist_accounts persist_boot kernel_module"
MEDIUM_KEYS="exec_shell defense_perm_mod net_connect net_listener exfil_compress"

usage() {
    printf "Usage: %s [options]\n" "$(basename "$0")"
    printf "\nGenerate a chronological timeline of security events.\n"
    printf "\nOptions:\n"
    printf "  -ts <time>   Start time (e.g., 'today', '12/25/2024 10:00:00')\n"
    printf "  -te <time>   End time\n"
    printf "  -o <file>    Output to file (CSV format)\n"
    printf "  -v           Verbose - show all events, not just high-priority\n"
    printf "\nExamples:\n"
    printf "  %s -ts today                    # Today's events\n" "$(basename "$0")"
    printf "  %s -ts recent                   # Last 10 minutes\n" "$(basename "$0")"
    printf "  %s -ts today -o timeline.csv    # Export to CSV\n" "$(basename "$0")"
    exit 1
}

check_privileges() {
    if ! ausearch -m SYSCALL --format text > /dev/null 2>&1; then
        printf "${RED}Error: Cannot access audit logs.${NC}\n" >&2
        exit 1
    fi
}

# Get severity level for a key
get_severity() {
    key="$1"

    for k in $CRITICAL_KEYS; do
        if [ "$key" = "$k" ]; then
            printf "CRITICAL"
            return
        fi
    done

    for k in $HIGH_KEYS; do
        if [ "$key" = "$k" ]; then
            printf "HIGH"
            return
        fi
    done

    for k in $MEDIUM_KEYS; do
        if [ "$key" = "$k" ]; then
            printf "MEDIUM"
            return
        fi
    done

    printf "LOW"
}

# Get color for severity
severity_color() {
    case "$1" in
        CRITICAL) printf "%s" "$RED" ;;
        HIGH) printf "%s" "$YELLOW" ;;
        MEDIUM) printf "%s" "$BLUE" ;;
        *) printf "%s" "$NC" ;;
    esac
}

# Process events and build timeline
process_events() {
    verbose="$1"
    shift

    # Build key filter
    if [ "$verbose" = "1" ]; then
        # All keys
        key_filter=""
    else
        # Only important keys
        key_filter="$CRITICAL_KEYS $HIGH_KEYS $MEDIUM_KEYS"
    fi

    # Get all events with keys, sorted by time
    {
        if [ -n "$key_filter" ]; then
            for key in $key_filter; do
                ausearch -k "$key" "$@" -i 2>/dev/null || true
            done
        else
            ausearch "$@" -i 2>/dev/null || true
        fi
    } | awk '
    BEGIN { RS="----\n"; FS="\n" }
    {
        time=""; pid=""; uid=""; exe=""; key=""; cmdline=""
        success=""

        for (i=1; i<=NF; i++) {
            line = $i

            if (line ~ /^type=SYSCALL/) {
                # Extract timestamp
                if (match(line, /msg=audit\([0-9]+\.[0-9]+:/)) {
                    ts = substr(line, RSTART+10)
                    sub(/:.*/, "", ts)
                    time = ts
                }
                # Extract fields
                if (match(line, /pid=[0-9]+/)) {
                    pid = substr(line, RSTART+4, RLENGTH-4)
                }
                if (match(line, /uid=[0-9]+/)) {
                    uid = substr(line, RSTART+4, RLENGTH-4)
                }
                if (match(line, /success=(yes|no)/)) {
                    success = substr(line, RSTART+8, RLENGTH-8)
                }
                if (match(line, /exe="[^"]+"/)) {
                    exe = substr(line, RSTART+5, RLENGTH-6)
                }
                if (match(line, /key="[^"]+"/)) {
                    key = substr(line, RSTART+5, RLENGTH-6)
                } else if (match(line, /key=[^ ]+/)) {
                    key = substr(line, RSTART+4, RLENGTH-4)
                    gsub(/"/, "", key)
                }
            }

            if (line ~ /^type=EXECVE/) {
                # Get first few args
                args = ""
                n = split(line, parts, " ")
                for (j=1; j<=n && j<=5; j++) {
                    if (parts[j] ~ /^a[0-9]+=/) {
                        val = parts[j]
                        sub(/^a[0-9]+=/, "", val)
                        gsub(/"/, "", val)
                        if (args != "") args = args " "
                        args = args val
                    }
                }
                if (args != "") cmdline = args
            }
        }

        if (time != "" && key != "" && key != "(null)") {
            printf "%s|%s|%s|%s|%s|%s|%s\n", time, key, pid, uid, success, exe, cmdline
        }
    }
    ' | sort -t'|' -k1,1n
}

format_timeline() {
    output_file="$1"

    if [ -n "$output_file" ]; then
        # CSV header
        printf "Timestamp,Severity,Key,PID,User,Status,Executable,Command\n" > "$output_file"
    fi

    last_minute=""

    while IFS='|' read -r ts key pid uid success exe cmdline; do
        [ -z "$ts" ] && continue

        # Convert timestamp
        readable_time=$(date -d "@$ts" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$ts")
        minute=$(date -d "@$ts" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "")

        # Get severity
        severity=$(get_severity "$key")
        color=$(severity_color "$severity")

        # Resolve username
        username=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "uid:$uid")

        # Status indicator
        if [ "$success" = "yes" ]; then
            status="${GREEN}OK${NC}"
            status_csv="SUCCESS"
        else
            status="${RED}FAIL${NC}"
            status_csv="FAILED"
        fi

        # Add time separator for new minutes
        if [ -n "$minute" ] && [ "$minute" != "$last_minute" ]; then
            if [ -n "$last_minute" ]; then
                printf "\n"
            fi
            printf "${BOLD}${CYAN}─── %s ───${NC}\n" "$minute"
            last_minute="$minute"
        fi

        # Truncate long commands
        if [ "${#cmdline}" -gt 50 ]; then
            cmdline="${cmdline%"${cmdline#??????????????????????????????????????????????????}"}..."
        fi

        # Display
        printf "%b[%-8s]%s %b%-20s%s %-8s %s\n" \
            "$color" "$severity" "$NC" \
            "$YELLOW" "$key" "$NC" \
            "$username" \
            "$exe"

        if [ -n "$cmdline" ]; then
            printf "           └─ %s\n" "$cmdline"
        fi

        # CSV output
        if [ -n "$output_file" ]; then
            # Escape quotes in command
            cmdline_escaped=$(printf "%s" "$cmdline" | sed 's/"/""/g')
            printf "%s,%s,%s,%s,%s,%s,\"%s\",\"%s\"\n" \
                "$readable_time" "$severity" "$key" "$pid" "$username" "$status_csv" "$exe" "$cmdline_escaped" >> "$output_file"
        fi
    done
}

main() {
    verbose=0
    output_file=""
    args=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help) usage ;;
            -v|--verbose) verbose=1; shift ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            *)
                args="$args $1"
                shift
                ;;
        esac
    done

    check_privileges

    printf "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${CYAN}║${NC}          ${BOLD}Security Event Timeline${NC}                         ${CYAN}║${NC}\n"
    printf "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    printf "${BOLD}Legend:${NC}\n"
    printf "  ${RED}[CRITICAL]${NC} - Immediate attention required\n"
    printf "  ${YELLOW}[HIGH]${NC}     - Suspicious activity\n"
    printf "  ${BLUE}[MEDIUM]${NC}   - Worth investigating\n"
    printf "  [LOW]      - Routine activity\n\n"

    if [ -n "$output_file" ]; then
        printf "${GREEN}Exporting to: %s${NC}\n\n" "$output_file"
    fi

    printf "${BOLD}Timeline:${NC}\n"
    printf "════════════════════════════════════════════════════════════\n\n"

    # Generate timeline
    count=$(process_events "$verbose" $args | tee /dev/stderr | wc -l 2>/dev/null)

    process_events "$verbose" $args | format_timeline "$output_file"

    printf "\n${BOLD}══════════════════════════════════════════════════${NC}\n"

    # Summary by severity
    printf "\n${BOLD}Summary:${NC}\n"

    critical_count=0
    high_count=0

    for key in $CRITICAL_KEYS; do
        c=$(ausearch -k "$key" $args 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        critical_count=$((critical_count + c))
    done

    for key in $HIGH_KEYS; do
        c=$(ausearch -k "$key" $args 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        high_count=$((high_count + c))
    done

    if [ "$critical_count" -gt 0 ]; then
        printf "  ${RED}CRITICAL: %d events${NC}\n" "$critical_count"
    fi
    if [ "$high_count" -gt 0 ]; then
        printf "  ${YELLOW}HIGH: %d events${NC}\n" "$high_count"
    fi

    if [ "$critical_count" -eq 0 ] && [ "$high_count" -eq 0 ]; then
        printf "  ${GREEN}No critical or high-priority events detected.${NC}\n"
    fi

    if [ -n "$output_file" ]; then
        printf "\n${GREEN}Timeline exported to: %s${NC}\n" "$output_file"
    fi

    printf "\n"
}

main "$@"
