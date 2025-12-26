#!/bin/sh
# POSIX-compliant process ancestry tracer using auditd logs
# Usage: ./trace-proc.sh <PID> [max_depth]

# ====== to use it ======
# auditd must be running
# you know the offenders pid
# run ./trace-proc.sh pid       // default max depth is 10

set -e

# Configuration
MAX_DEPTH="${2:-10}"  # Prevent infinite loops
TEMP_DIR="${TMPDIR:-/tmp}"
TEMP_FILE="${TEMP_DIR}/audit_trace_$$.tmp"

# Cleanup on exit
trap 'rm -f "$TEMP_FILE"' EXIT INT TERM

# Colors (optional, works in most terminals)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'  # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

usage() {
    printf "Usage: %s <PID> [max_depth]\n" "$0"
    printf "  Traces process ancestry from PID up to init (PID 1)\n"
    printf "  max_depth: Maximum ancestor levels to trace (default: 50)\n"
    exit 1
}

# Check if running as root or with audit privileges
check_privileges() {
    if ! ausearch -m EXECVE --format text > /dev/null 2>&1; then
        printf "${RED}Error: Cannot access audit logs. Run as root or with CAP_AUDIT_READ capability.${NC}\n" >&2
        exit 1
    fi
}

# Extract process info from audit logs
get_process_info() {
    target_pid="$1"
    
    # Search audit logs for execve events with this PID
    # Use --format text for easier parsing
    ausearch -p "$target_pid" -m EXECVE -i --format text 2>/dev/null | \
        awk -v pid="$target_pid" '
        BEGIN { found=0; time=""; ppid=""; exe=""; cmdline="" }
        /^type=SYSCALL/ {
            # Extract timestamp
            if (match($0, /time->([^ ]+)/, arr)) {
                time = arr[1]
            }
            # Extract PPID
            if (match($0, /ppid=([^ ]+)/, arr)) {
                ppid = arr[1]
            }
            # Extract executable
            if (match($0, /exe="([^"]+)"/, arr) || match($0, /exe=([^ ]+)/, arr)) {
                exe = arr[1]
            }
            found = 1
        }
        /^type=EXECVE/ {
            # Extract command line arguments
            if (match($0, /a0=(.+)$/, arr)) {
                # Simple extraction of first argument
                cmdline = $0
                sub(/.*a0=/, "", cmdline)
                sub(/a1=.*/, "", cmdline)
            }
        }
        END {
            if (found) {
                printf "%s|%s|%s|%s\n", time, ppid, exe, cmdline
            }
        }
    ' > "$TEMP_FILE"
    
    if [ -s "$TEMP_FILE" ]; then
        cat "$TEMP_FILE"
        return 0
    else
        return 1
    fi
}

# Format and display process information
display_process() {
    depth="$1"
    pid="$2"
    time="$3"
    ppid="$4"
    exe="$5"
    cmdline="$6"
    
    # Create indentation
    indent=""
    i=0
    while [ "$i" -lt "$depth" ]; do
        indent="${indent}  "
        i=$((i + 1))
    done
    
    # Format PID display
    if [ "$pid" = "1" ]; then
        pid_display="${GREEN}PID $pid (init)${NC}"
    elif [ "$depth" -eq 0 ]; then
        pid_display="${RED}PID $pid (target)${NC}"
    else
        pid_display="${BLUE}PID $pid${NC}"
    fi
    
    printf "%s├─ %b\n" "$indent" "$pid_display"
    printf "%s│  PPID: %s\n" "$indent" "$ppid"
    
    if [ -n "$time" ]; then
        printf "%s│  Time: %s\n" "$indent" "$time"
    fi
    
    if [ -n "$exe" ]; then
        printf "%s│  Exec: %s\n" "$indent" "$exe"
    fi
    
    if [ -n "$cmdline" ]; then
        # Truncate very long command lines
        if [ "${#cmdline}" -gt 100 ]; then
            cmdline="${cmdline%"${cmdline#??????????????????????????????????????????????????????????????????????????????????????????????????????????????}"...}"
        fi
        printf "%s│  Args: %s\n" "$indent" "$cmdline"
    fi
    
    printf "%s│\n" "$indent"
}

# Recursive function to trace ancestry
trace_ancestry() {
    current_pid="$1"
    depth="$2"
    visited="$3"
    
    # Safety checks
    if [ "$depth" -gt "$MAX_DEPTH" ]; then
        printf "${YELLOW}Warning: Maximum depth reached (%d levels)${NC}\n" "$MAX_DEPTH" >&2
        return 1
    fi
    
    # Check for cycles (shouldn't happen, but safety first)
    case " $visited " in
        *" $current_pid "*)
            printf "${RED}Error: Cycle detected at PID %s${NC}\n" "$current_pid" >&2
            return 1
            ;;
    esac
    
    # Add current PID to visited list
    visited="$visited $current_pid"
    
    # Get process info from audit logs
    if get_process_info "$current_pid"; then
        # Parse the result
        IFS='|' read -r time ppid exe cmdline < "$TEMP_FILE"
        
        # Display this process
        display_process "$depth" "$current_pid" "$time" "$ppid" "$exe" "$cmdline"
        
        # If we haven't reached init, continue tracing
        if [ "$current_pid" != "1" ] && [ -n "$ppid" ] && [ "$ppid" != "0" ]; then
            trace_ancestry "$ppid" "$((depth + 1))" "$visited"
        elif [ "$current_pid" = "1" ]; then
            printf "${GREEN}Reached init (PID 1) - trace complete!${NC}\n\n"
        else
            printf "${YELLOW}Warning: Parent PID is %s - cannot trace further${NC}\n\n" "$ppid"
        fi
    else
        # Process not found in audit logs
        printf "${YELLOW}Warning: PID %s not found in audit logs${NC}\n" "$current_pid" >&2
        
        # Try to get info from /proc if process is still running
        if [ -d "/proc/$current_pid" ]; then
            ppid=$(awk '/^PPid:/ {print $2}' "/proc/$current_pid/status" 2>/dev/null || echo "")
            exe=$(readlink "/proc/$current_pid/exe" 2>/dev/null || echo "unknown")
            cmdline=$(tr '\0' ' ' < "/proc/$current_pid/cmdline" 2>/dev/null || echo "")
            
            display_process "$depth" "$current_pid" "(running)" "$ppid" "$exe" "$cmdline"
            
            if [ -n "$ppid" ] && [ "$ppid" != "0" ] && [ "$current_pid" != "1" ]; then
                printf "${BLUE}Continuing trace using /proc filesystem...${NC}\n"
                trace_ancestry "$ppid" "$((depth + 1))" "$visited"
            fi
        else
            printf "${RED}Process not found in audit logs or /proc. It may have started before auditing was enabled.${NC}\n\n"
            return 1
        fi
    fi
    
    return 0
}

# Main execution
main() {
    if [ $# -lt 1 ]; then
        usage
    fi
    
    target_pid="$1"
    
    # Validate PID is a number
    case "$target_pid" in
        ''|*[!0-9]*)
            printf "${RED}Error: PID must be a positive integer${NC}\n" >&2
            exit 1
            ;;
    esac
    
    printf "\n${GREEN}=== Process Ancestry Trace ===${NC}\n\n"
    printf "Target PID: ${RED}%s${NC}\n" "$target_pid"
    printf "Tracing ancestry to PID 1 (max depth: %d)...\n\n" "$MAX_DEPTH"
    
    check_privileges
    
    if trace_ancestry "$target_pid" 0 ""; then
        printf "${GREEN}Trace completed successfully.${NC}\n"
    else
        printf "${YELLOW}Trace completed with warnings or errors.${NC}\n"
    fi
}

main "$@"