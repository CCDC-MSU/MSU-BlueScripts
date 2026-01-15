#!/bin/sh
# POSIX-compliant C2/exfiltration tool detection script
# Finds netcat, curl, wget, socat, and other suspicious network tools
# Usage: ./hunt-c2.sh [-ts timespec]

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

# C2 and exfiltration related keys
C2_KEYS="c2_susp_tools c2_tools c2_dns c2_dns_mod c2_remote_svc c2_port_knock c2_proxy ccdc_netcat"
EXFIL_KEYS="exfil_compress exfil_anon_file exfil_usb"
NET_KEYS="net_connect net_listener net_socket net_sniff"

usage() {
    printf "Usage: %s [ausearch options]\n" "$(basename "$0")"
    printf "\nDetect Command & Control and data exfiltration tool usage.\n"
    printf "\nThis script searches for:\n"
    printf "  - Netcat, ncat, socat execution\n"
    printf "  - Curl, wget downloads\n"
    printf "  - SSH/SCP/SFTP transfers\n"
    printf "  - DNS modifications\n"
    printf "  - Compression tool usage (tar, gzip, zip)\n"
    printf "  - Network listeners and suspicious connections\n"
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

# Analyze tool threat level
analyze_tool() {
    exe="$1"
    cmdline="$2"

    # Critical - definite C2/backdoor indicators
    case "$exe" in
        */nc|*/ncat|*/netcat|*/nc.openbsd|*/nc.traditional)
            case "$cmdline" in
                *"-e "*|*"-c "*|*"--exec"*|*"--sh-exec"*)
                    printf "${RED}[CRITICAL]${NC} Netcat with shell execution (backdoor)\n"
                    return
                    ;;
                *"-l"*)
                    printf "${RED}[CRITICAL]${NC} Netcat listener (potential backdoor)\n"
                    return
                    ;;
                *)
                    printf "${YELLOW}[WARNING]${NC} Netcat execution\n"
                    return
                    ;;
            esac
            ;;
        */socat)
            case "$cmdline" in
                *"EXEC:"*|*"SYSTEM:"*)
                    printf "${RED}[CRITICAL]${NC} Socat with command execution\n"
                    return
                    ;;
                *"TCP-LISTEN:"*|*"UDP-LISTEN:"*)
                    printf "${RED}[CRITICAL]${NC} Socat listener\n"
                    return
                    ;;
                *)
                    printf "${YELLOW}[WARNING]${NC} Socat execution\n"
                    return
                    ;;
            esac
            ;;
    esac

    # High - data transfer tools
    case "$exe" in
        */curl)
            case "$cmdline" in
                *"| sh"*|*"|sh"*|*"| bash"*|*"|bash"*)
                    printf "${RED}[CRITICAL]${NC} Curl piped to shell\n"
                    return
                    ;;
                *"-o "*|*"--output"*|*"-O"*)
                    printf "${YELLOW}[DOWNLOAD]${NC} Curl file download\n"
                    return
                    ;;
                *"--data"*|*"-d "*|*"--upload"*|*"-T "*)
                    printf "${YELLOW}[EXFIL]${NC} Curl data upload\n"
                    return
                    ;;
                *)
                    printf "${BLUE}[INFO]${NC} Curl request\n"
                    return
                    ;;
            esac
            ;;
        */wget)
            case "$cmdline" in
                *"| sh"*|*"|sh"*|*"| bash"*|*"|bash"*)
                    printf "${RED}[CRITICAL]${NC} Wget piped to shell\n"
                    return
                    ;;
                *)
                    printf "${YELLOW}[DOWNLOAD]${NC} Wget execution\n"
                    return
                    ;;
            esac
            ;;
        */scp|*/sftp|*/rsync)
            printf "${YELLOW}[TRANSFER]${NC} Secure file transfer\n"
            return
            ;;
        */ftp|*/tftp|*/atftpd)
            printf "${RED}[WARNING]${NC} FTP/TFTP (unencrypted transfer)\n"
            return
            ;;
    esac

    # Network tools
    case "$exe" in
        */ssh)
            case "$cmdline" in
                *"-R "*|*"-L "*|*"-D "*)
                    printf "${RED}[TUNNEL]${NC} SSH tunneling/port forwarding\n"
                    return
                    ;;
                *)
                    printf "${BLUE}[SSH]${NC} SSH connection\n"
                    return
                    ;;
            esac
            ;;
        */nmap)
            printf "${YELLOW}[RECON]${NC} Network scanning\n"
            return
            ;;
        */tcpdump|*/tshark|*/wireshark)
            printf "${YELLOW}[CAPTURE]${NC} Packet capture\n"
            return
            ;;
    esac

    # Compression (potential exfil prep)
    case "$exe" in
        */tar|*/gzip|*/bzip2|*/zip|*/7z|*/rar|*/xz)
            printf "${YELLOW}[COMPRESS]${NC} Data compression (exfil prep?)\n"
            return
            ;;
        */base64)
            printf "${YELLOW}[ENCODE]${NC} Base64 encoding\n"
            return
            ;;
    esac

    # DNS modification
    case "$exe" in
        *nsupdate*|*rndc*)
            printf "${YELLOW}[DNS]${NC} DNS modification tool\n"
            return
            ;;
    esac

    printf "${BLUE}[INFO]${NC} Network/transfer tool\n"
}

process_event() {
    awk -v red="$RED" -v green="$GREEN" -v yellow="$YELLOW" -v blue="$BLUE" -v cyan="$CYAN" -v bold="$BOLD" -v nc="$NC" '
    BEGIN {
        time=""; pid=""; ppid=""; uid=""; auid=""; exe=""
        cmdline=""; success=""; key=""
    }
    /^type=SYSCALL/ {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^pid=/) { sub(/pid=/, "", $i); pid = $i }
            if ($i ~ /^ppid=/) { sub(/ppid=/, "", $i); ppid = $i }
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

            if (success == "yes") {
                printf "  %s[OK]%s ", green, nc
            } else {
                printf "  %s[FAIL]%s ", red, nc
            }
            printf "%s%s%s | PID: %s\n", cyan, time, nc, pid

            printf "  User: %s", uname
            if (aname != "") printf " (login: %s)", aname
            printf "\n"

            printf "  Exec: %s%s%s\n", yellow, exe, nc

            if (cmdline != "") {
                if (length(cmdline) > 100) cmdline = substr(cmdline, 1, 100) "..."
                printf "  Cmd:  %s\n", cmdline
            }

            printf "  Key:  %s | PPID: %s\n", key, ppid

            # Output for analysis
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
    printf "${CYAN}║${NC}          ${BOLD}${RED}C2 & Exfiltration Tool Hunter${NC}                  ${CYAN}║${NC}\n"
    printf "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    printf "${BOLD}Scanning for:${NC}\n"
    printf "  - Netcat, socat, ncat (backdoor tools)\n"
    printf "  - Curl, wget (downloaders)\n"
    printf "  - SSH tunneling, SCP/SFTP transfers\n"
    printf "  - Compression tools (exfil preparation)\n"
    printf "  - Network listeners and sniffers\n\n"

    total=0
    critical=0

    # C2 Tools
    printf "${BOLD}${RED}C2 Tools:${NC}\n"
    printf "════════════════════════════════════════════════════════════\n\n"

    for key in $C2_KEYS; do
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

                analyze_line=$(printf "%s" "$output" | grep "^ANALYZE|" | head -1)
                if [ -n "$analyze_line" ]; then
                    exe=$(printf "%s" "$analyze_line" | cut -d'|' -f2)
                    cmdline=$(printf "%s" "$analyze_line" | cut -d'|' -f3-)
                    printf "  "
                    analyze_tool "$exe" "$cmdline"
                fi
                printf "\n"
            done
        fi
    done

    # Exfiltration
    printf "\n${BOLD}${YELLOW}Exfiltration Tools:${NC}\n"
    printf "════════════════════════════════════════════════════════════\n\n"

    for key in $EXFIL_KEYS; do
        count=$(ausearch -k "$key" "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        if [ "$count" -gt 0 ]; then
            printf "${YELLOW}━━━ Key: %s (%d events) ━━━${NC}\n\n" "$key" "$count"
            total=$((total + count))

            ausearch -k "$key" "$@" -i 2>/dev/null | awk '
            /^----/ { if (record != "") print record; record = ""; next }
            { record = record $0 "\n" }
            END { if (record != "") print record }
            ' | head -20 | while IFS= read -r record; do
                output=$(printf "%s" "$record" | process_event)
                printf "%s" "$output" | grep -v "^ANALYZE|"
                printf "\n"
            done

            if [ "$count" -gt 20 ]; then
                printf "  ${YELLOW}... and %d more events (showing first 20)${NC}\n\n" "$((count - 20))"
            fi
        fi
    done

    # Network activity
    printf "\n${BOLD}${BLUE}Network Activity:${NC}\n"
    printf "════════════════════════════════════════════════════════════\n\n"

    for key in $NET_KEYS; do
        count=$(ausearch -k "$key" "$@" 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        if [ "$count" -gt 0 ]; then
            printf "${BLUE}Key: %s - %d events${NC}\n" "$key" "$count"
            total=$((total + count))
        fi
    done

    printf "\n${BOLD}══════════════════════════════════════════════════${NC}\n"
    if [ "$total" -gt 0 ]; then
        printf "${RED}ALERT: %d C2/exfiltration events detected!${NC}\n\n" "$total"
        printf "Recommended actions:\n"
        printf "  1. Check active network connections: ss -tunap\n"
        printf "  2. Look for listening ports: ss -tlnp\n"
        printf "  3. Review outbound connections in firewall logs\n"
        printf "  4. Trace suspicious PIDs: ./trace-parent.sh <pid>\n"
        printf "  5. Check /tmp and /dev/shm for suspicious files\n"
    else
        printf "${GREEN}No C2/exfiltration activity detected.${NC}\n"
    fi
    printf "\n"
}

main "$@"
