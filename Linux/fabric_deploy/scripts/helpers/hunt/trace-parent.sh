#!/bin/sh
# POSIX-compliant process ancestry tracer using auditd logs
# Traces a process back to init, showing the full spawn chain
# Usage: ./trace-parent.sh <PID> [max_depth]

set -e

# Configuration
MAX_DEPTH="${2:-50}"
TEMP_DIR="${TMPDIR:-/tmp}"
TEMP_FILE="${TEMP_DIR}/audit_trace_$$.tmp"
CACHE_FILE="${TEMP_DIR}/audit_cache_$$.tmp"

trap 'rm -f "$TEMP_FILE" "$CACHE_FILE"' EXIT INT TERM

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
    printf "Usage: %s <PID> [max_depth]\n" "$(basename "$0")"
    printf "\nTraces process ancestry from PID up to init (PID 1)\n"
    printf "\nOptions:\n"
    printf "  PID        Process ID to trace\n"
    printf "  max_depth  Maximum ancestor levels (default: 50)\n"
    printf "\nExamples:\n"
    printf "  %s 4444           # Trace PID 4444\n" "$(basename "$0")"
    printf "  %s 4444 100       # Trace with deeper limit\n" "$(basename "$0")"
    exit 1
}

check_privileges() {
    if ! ausearch -m SYSCALL --format text > /dev/null 2>&1; then
        printf "${RED}Error: Cannot access audit logs.${NC}\n" >&2
        printf "Run as root or with CAP_AUDIT_READ capability.\n" >&2
        exit 1
    fi
}

# Get process info from audit logs - searches for the MOST RECENT execve for this PID
get_audit_info() {
    target_pid="$1"

    # Search for execve events for this PID
    # Get the most recent one (last in output)
    ausearch -p "$target_pid" -m SYSCALL,EXECVE -i 2>/dev/null | \
    awk -v pid="$target_pid" '
    BEGIN {
        time=""; ppid=""; exe=""; uid=""; auid=""; key=""
        cmdline=""; in_record=0; record_time=""
    }
    /^----/ { in_record=1; next }
    /^type=SYSCALL/ {
        # Extract fields from SYSCALL record
        for (i=1; i<=NF; i++) {
            if ($i ~ /^msg=audit\(/) {
                # Extract timestamp
                match($i, /audit\(([0-9]+\.[0-9]+)/, arr)
                if (arr[1] != "") record_time = arr[1]
            }
            if ($i ~ /^ppid=/) { sub(/ppid=/, "", $i); ppid = $i }
            if ($i ~ /^uid=/) { sub(/uid=/, "", $i); uid = $i }
            if ($i ~ /^auid=/) { sub(/auid=/, "", $i); auid = $i }
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
        time = record_time
    }
    /^type=EXECVE/ {
        # Build command line from arguments
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
        if (ppid != "") {
            # Convert timestamp to readable format if possible
            if (time != "") {
                cmd = "date -d @" int(time) " \"+%Y-%m-%d %H:%M:%S\" 2>/dev/null"
                cmd | getline readable_time
                close(cmd)
                if (readable_time == "") readable_time = time
                time = readable_time
            }
            printf "%s|%s|%s|%s|%s|%s|%s\n", time, ppid, exe, uid, auid, key, cmdline
        }
    }
    ' > "$TEMP_FILE"

    if [ -s "$TEMP_FILE" ]; then
        cat "$TEMP_FILE"
        return 0
    fi
    return 1
}

# Get process info from /proc (for running processes)
get_proc_info() {
    target_pid="$1"

    if [ ! -d "/proc/$target_pid" ]; then
        return 1
    fi

    ppid=$(awk '/^PPid:/ {print $2}' "/proc/$target_pid/status" 2>/dev/null || echo "")
    exe=$(readlink "/proc/$target_pid/exe" 2>/dev/null || echo "unknown")
    uid=$(awk '/^Uid:/ {print $2}' "/proc/$target_pid/status" 2>/dev/null || echo "")
    cmdline=$(tr '\0' ' ' < "/proc/$target_pid/cmdline" 2>/dev/null | sed 's/ $//' || echo "")

    if [ -n "$ppid" ]; then
        printf "(running)|%s|%s|%s||proc|%s\n" "$ppid" "$exe" "$uid" "$cmdline"
        return 0
    fi
    return 1
}

# Display process in the tree
display_process() {
    depth="$1"
    pid="$2"
    time="$3"
    ppid="$4"
    exe="$5"
    uid="$6"
    auid="$7"
    key="$8"
    cmdline="$9"

    # Create indentation
    indent=""
    i=0
    while [ "$i" -lt "$depth" ]; do
        indent="${indent}  "
        i=$((i + 1))
    done

    # Color coding based on context
    if [ "$pid" = "1" ]; then
        pid_color="${GREEN}"
        label=" (init)"
    elif [ "$depth" -eq 0 ]; then
        pid_color="${RED}"
        label=" (TARGET)"
    else
        pid_color="${BLUE}"
        label=""
    fi

    # Highlight suspicious keys
    key_display=""
    if [ -n "$key" ] && [ "$key" != "(null)" ] && [ "$key" != "proc" ]; then
        case "$key" in
            ccdc_*|privesc_*|c2_*|defense_*|persist_*)
                key_display="${RED}[${key}]${NC}"
                ;;
            *)
                key_display="${YELLOW}[${key}]${NC}"
                ;;
        esac
    fi

    printf "%s${BOLD}├─${NC} ${pid_color}PID %s${NC}%s %b\n" "$indent" "$pid" "$label" "$key_display"
    printf "%s${BOLD}│${NC}  PPID: %s\n" "$indent" "$ppid"

    if [ -n "$time" ] && [ "$time" != "(null)" ]; then
        printf "%s${BOLD}│${NC}  Time: %s\n" "$indent" "$time"
    fi

    if [ -n "$exe" ] && [ "$exe" != "(null)" ]; then
        # Highlight suspicious paths
        case "$exe" in
            /tmp/*|/dev/shm/*|/var/tmp/*)
                printf "%s${BOLD}│${NC}  Exec: ${RED}%s${NC} ${YELLOW}(suspicious path!)${NC}\n" "$indent" "$exe"
                ;;
            *)
                printf "%s${BOLD}│${NC}  Exec: %s\n" "$indent" "$exe"
                ;;
        esac
    fi

    if [ -n "$uid" ] && [ "$uid" != "(null)" ]; then
        # Try to resolve username
        username=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "")
        if [ -n "$username" ]; then
            printf "%s${BOLD}│${NC}  User: %s (%s)\n" "$indent" "$username" "$uid"
        else
            printf "%s${BOLD}│${NC}  UID:  %s\n" "$indent" "$uid"
        fi
    fi

    if [ -n "$auid" ] && [ "$auid" != "(null)" ] && [ "$auid" != "4294967295" ] && [ "$auid" != "-1" ]; then
        auid_name=$(getent passwd "$auid" 2>/dev/null | cut -d: -f1 || echo "")
        if [ -n "$auid_name" ]; then
            printf "%s${BOLD}│${NC}  Login: %s (%s)\n" "$indent" "$auid_name" "$auid"
        else
            printf "%s${BOLD}│${NC}  AUID: %s\n" "$indent" "$auid"
        fi
    fi

    if [ -n "$cmdline" ] && [ "$cmdline" != "(null)" ]; then
        # Truncate long command lines
        if [ "${#cmdline}" -gt 80 ]; then
            cmdline="${cmdline%"${cmdline#????????????????????????????????????????????????????????????????????????????????}"}..."
        fi
        printf "%s${BOLD}│${NC}  Args: %s\n" "$indent" "$cmdline"
    fi

    printf "%s${BOLD}│${NC}\n" "$indent"
}

# Trace ancestry recursively
trace_ancestry() {
    current_pid="$1"
    depth="$2"
    visited="$3"

    # Safety: max depth
    if [ "$depth" -gt "$MAX_DEPTH" ]; then
        printf "${YELLOW}Warning: Maximum depth reached (%d levels)${NC}\n" "$MAX_DEPTH" >&2
        return 1
    fi

    # Safety: cycle detection
    case " $visited " in
        *" $current_pid "*)
            printf "${RED}Error: Cycle detected at PID %s${NC}\n" "$current_pid" >&2
            return 1
            ;;
    esac

    visited="$visited $current_pid"

    # Try audit logs first
    if info=$(get_audit_info "$current_pid"); then
        IFS='|' read -r time ppid exe uid auid key cmdline <<EOF
$info
EOF
        display_process "$depth" "$current_pid" "$time" "$ppid" "$exe" "$uid" "$auid" "$key" "$cmdline"

        # Continue tracing if not at init
        if [ "$current_pid" != "1" ] && [ -n "$ppid" ] && [ "$ppid" != "0" ]; then
            trace_ancestry "$ppid" "$((depth + 1))" "$visited"
        elif [ "$current_pid" = "1" ]; then
            printf "${GREEN}Reached init (PID 1) - ancestry trace complete!${NC}\n\n"
        fi
    # Fallback to /proc
    elif info=$(get_proc_info "$current_pid"); then
        IFS='|' read -r time ppid exe uid auid key cmdline <<EOF
$info
EOF
        printf "${CYAN}(Using /proc - process still running)${NC}\n"
        display_process "$depth" "$current_pid" "$time" "$ppid" "$exe" "$uid" "$auid" "$key" "$cmdline"

        if [ "$current_pid" != "1" ] && [ -n "$ppid" ] && [ "$ppid" != "0" ]; then
            trace_ancestry "$ppid" "$((depth + 1))" "$visited"
        fi
    else
        printf "${YELLOW}Warning: PID %s not found in audit logs or /proc${NC}\n" "$current_pid" >&2
        printf "${YELLOW}Process may have exited before auditing started.${NC}\n\n" >&2
        return 1
    fi

    return 0
}

# Find related processes (children, siblings)
find_related() {
    target_pid="$1"
    printf "\n${BOLD}Related Processes (same parent):${NC}\n"
    printf "════════════════════════════════════════\n"

    # Get parent PID
    ppid=$(ausearch -p "$target_pid" -m SYSCALL -i 2>/dev/null | grep -oE 'ppid=[0-9]+' | head -1 | cut -d= -f2)

    if [ -n "$ppid" ]; then
        # Find siblings (other processes with same parent)
        ausearch -m SYSCALL -i 2>/dev/null | grep "ppid=$ppid" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | while read -r sibling_pid; do
            if [ "$sibling_pid" != "$target_pid" ]; then
                exe=$(ausearch -p "$sibling_pid" -m SYSCALL -i 2>/dev/null | grep -oE 'exe="[^"]+"' | head -1 | cut -d'"' -f2)
                printf "  PID %s: %s\n" "$sibling_pid" "${exe:-unknown}"
            fi
        done
    else
        printf "  ${YELLOW}Could not determine parent${NC}\n"
    fi
}

main() {
    if [ $# -lt 1 ]; then
        usage
    fi

    target_pid="$1"

    # Validate PID
    case "$target_pid" in
        ''|*[!0-9]*)
            printf "${RED}Error: PID must be a positive integer${NC}\n" >&2
            exit 1
            ;;
    esac

    printf "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${CYAN}║${NC}          ${BOLD}Process Ancestry Trace${NC}                          ${CYAN}║${NC}\n"
    printf "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    printf "Target PID:  ${RED}%s${NC}\n" "$target_pid"
    printf "Max Depth:   %s\n" "$MAX_DEPTH"
    printf "Timestamp:   %s\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"

    check_privileges

    printf "${BOLD}Process Tree:${NC}\n"
    printf "════════════════════════════════════════\n\n"

    if trace_ancestry "$target_pid" 0 ""; then
        printf "${GREEN}Trace completed successfully.${NC}\n"
    else
        printf "${YELLOW}Trace completed with warnings.${NC}\n"
    fi
}

main "$@"
