#!/bin/sh
# POSIX-compliant threat hunting menu for auditd logs
# Usage: ./hunt.sh

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

print_banner() {
    printf "${CYAN}"
    cat << 'EOF'
  _____ _                    _     _   _             _
 |_   _| |__  _ __ ___  __ _| |_  | | | |_   _ _ __ | |_
   | | | '_ \| '__/ _ \/ _` | __| | |_| | | | | '_ \| __|
   | | | | | | | |  __/ (_| | |_  |  _  | |_| | | | | |_
   |_| |_| |_|_|  \___|\__,_|\__| |_| |_|\__,_|_| |_|\__|

EOF
    printf "${NC}"
    printf "${BOLD}CCDC Auditd Threat Hunting Suite${NC}\n"
    printf "═══════════════════════════════════════════════════════════\n\n"
}

print_menu() {
    printf "${BOLD}Available Hunting Tools:${NC}\n\n"

    printf "${GREEN}[1]${NC} ${BOLD}Trace Process Parent${NC}\n"
    printf "    Trace the full ancestry of a process back to init\n\n"

    printf "${GREEN}[2]${NC} ${BOLD}Hunt by Audit Key${NC}\n"
    printf "    Search for events by audit key (e.g., privesc_root_cmd)\n\n"

    printf "${GREEN}[3]${NC} ${BOLD}Hunt Webshells${NC}\n"
    printf "    Find web server processes executing commands\n\n"

    printf "${GREEN}[4]${NC} ${BOLD}Hunt Privilege Escalation${NC}\n"
    printf "    Detect sudo, su, and root command execution\n\n"

    printf "${GREEN}[5]${NC} ${BOLD}Hunt Persistence${NC}\n"
    printf "    Find modifications to cron, systemd, init scripts\n\n"

    printf "${GREEN}[6]${NC} ${BOLD}Hunt C2/Exfil Tools${NC}\n"
    printf "    Detect netcat, curl, wget, and other C2 tools\n\n"

    printf "${GREEN}[7]${NC} ${BOLD}Event Timeline${NC}\n"
    printf "    Generate a timeline of security events\n\n"

    printf "${GREEN}[8]${NC} ${BOLD}Hunt User Activity${NC}\n"
    printf "    Track all activity by a specific user\n\n"

    printf "${GREEN}[9]${NC} ${BOLD}List Audit Keys${NC}\n"
    printf "    Show all available audit keys in current logs\n\n"

    printf "${GREEN}[0]${NC} ${BOLD}Exit${NC}\n\n"
}

check_privileges() {
    if ! ausearch -m SYSCALL --format text > /dev/null 2>&1; then
        printf "${RED}Error: Cannot access audit logs.${NC}\n"
        printf "Run as root or with CAP_AUDIT_READ capability.\n"
        exit 1
    fi
}

prompt_pid() {
    printf "${YELLOW}Enter PID to trace: ${NC}"
    read -r pid
    if [ -z "$pid" ]; then
        printf "${RED}Error: PID is required${NC}\n"
        return 1
    fi
    case "$pid" in
        ''|*[!0-9]*)
            printf "${RED}Error: PID must be a number${NC}\n"
            return 1
            ;;
    esac
    echo "$pid"
}

prompt_key() {
    printf "${YELLOW}Enter audit key to search (e.g., privesc_root_cmd): ${NC}"
    read -r key
    if [ -z "$key" ]; then
        printf "${RED}Error: Key is required${NC}\n"
        return 1
    fi
    echo "$key"
}

prompt_user() {
    printf "${YELLOW}Enter username or UID to track: ${NC}"
    read -r user
    if [ -z "$user" ]; then
        printf "${RED}Error: Username/UID is required${NC}\n"
        return 1
    fi
    echo "$user"
}

prompt_timeframe() {
    printf "\n${BOLD}Select timeframe:${NC}\n"
    printf "  [1] Last 15 minutes\n"
    printf "  [2] Last hour\n"
    printf "  [3] Last 24 hours\n"
    printf "  [4] Today\n"
    printf "  [5] This week\n"
    printf "  [6] All logs\n"
    printf "  [7] Custom (specify start time)\n"
    printf "${YELLOW}Choice [1-7]: ${NC}"
    read -r choice

    case "$choice" in
        1) echo "-ts recent" ;;
        2) echo "-ts $(date -d '1 hour ago' '+%m/%d/%Y %H:%M:%S' 2>/dev/null || date -v-1H '+%m/%d/%Y %H:%M:%S' 2>/dev/null || echo 'recent')" ;;
        3) echo "-ts $(date -d '24 hours ago' '+%m/%d/%Y %H:%M:%S' 2>/dev/null || date -v-24H '+%m/%d/%Y %H:%M:%S' 2>/dev/null || echo 'today')" ;;
        4) echo "-ts today" ;;
        5) echo "-ts this-week" ;;
        6) echo "" ;;
        7)
            printf "${YELLOW}Enter start time (e.g., '12/25/2024 10:00:00' or 'today'): ${NC}"
            read -r custom_time
            echo "-ts $custom_time"
            ;;
        *) echo "-ts today" ;;
    esac
}

list_keys() {
    printf "\n${BOLD}Audit Keys Found in Logs:${NC}\n"
    printf "═══════════════════════════════════════════════════════════\n"
    ausearch -i --format text 2>/dev/null | grep -oE 'key=[^ ]+' | sort | uniq -c | sort -rn | head -50 | \
        awk -v green="$GREEN" -v nc="$NC" '{printf "%s%5d%s  %s\n", green, $1, nc, $2}'
    printf "\n"
}

run_script() {
    script="$1"
    shift
    if [ -x "$SCRIPT_DIR/$script" ]; then
        "$SCRIPT_DIR/$script" "$@"
    else
        printf "${RED}Error: Script $script not found or not executable${NC}\n"
    fi
}

main() {
    clear
    print_banner
    check_privileges

    while true; do
        print_menu
        printf "${YELLOW}Select option [0-9]: ${NC}"
        read -r choice
        printf "\n"

        case "$choice" in
            1)
                pid=$(prompt_pid) || continue
                run_script "trace-parent.sh" "$pid"
                ;;
            2)
                key=$(prompt_key) || continue
                timeframe=$(prompt_timeframe)
                run_script "hunt-by-key.sh" "$key" $timeframe
                ;;
            3)
                timeframe=$(prompt_timeframe)
                run_script "hunt-webshell.sh" $timeframe
                ;;
            4)
                timeframe=$(prompt_timeframe)
                run_script "hunt-privesc.sh" $timeframe
                ;;
            5)
                timeframe=$(prompt_timeframe)
                run_script "hunt-persistence.sh" $timeframe
                ;;
            6)
                timeframe=$(prompt_timeframe)
                run_script "hunt-c2.sh" $timeframe
                ;;
            7)
                timeframe=$(prompt_timeframe)
                run_script "hunt-timeline.sh" $timeframe
                ;;
            8)
                user=$(prompt_user) || continue
                timeframe=$(prompt_timeframe)
                run_script "hunt-user.sh" "$user" $timeframe
                ;;
            9)
                list_keys
                ;;
            0|q|Q)
                printf "${GREEN}Exiting threat hunting suite.${NC}\n"
                exit 0
                ;;
            *)
                printf "${RED}Invalid option. Please select 0-9.${NC}\n"
                ;;
        esac

        printf "\n${YELLOW}Press Enter to continue...${NC}"
        read -r _
        clear
        print_banner
    done
}

main "$@"
