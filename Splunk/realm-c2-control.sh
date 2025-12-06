#!/bin/sh
# Control script for Realm C2 Detection

SCRIPT_PATH="/usr/local/bin/realm-c2-detect.sh"

case "$1" in
    start)
        if pgrep -f "realm-c2-detect.sh" > /dev/null 2>&1; then
            echo "[!] Realm C2 detection is already running"
            echo "Running processes:"
            pgrep -fa realm-c2-detect.sh
        else
            echo "[*] Starting Realm C2 detection..."
            nohup $SCRIPT_PATH > /dev/null 2>&1 &
            sleep 1
            if pgrep -f "realm-c2-detect.sh" > /dev/null 2>&1; then
                echo "[✓] Started successfully"
                pgrep -fa realm-c2-detect.sh
            else
                echo "[!] Failed to start"
            fi
        fi
        ;;
    stop)
        if pgrep -f "realm-c2-detect.sh" > /dev/null 2>&1; then
            echo "[*] Stopping Realm C2 detection..."
            pkill -f realm-c2-detect.sh
            sleep 1
            if ! pgrep -f "realm-c2-detect.sh" > /dev/null 2>&1; then
                echo "[✓] Stopped successfully"
            else
                echo "[!] Some processes may still be running:"
                pgrep -fa realm-c2-detect.sh
            fi
        else
            echo "[!] Realm C2 detection is not running"
        fi
        ;;
    status)
        if pgrep -f "realm-c2-detect.sh" > /dev/null 2>&1; then
            echo "[✓] Realm C2 detection is RUNNING"
            echo ""
            echo "Processes:"
            pgrep -fa realm-c2-detect.sh
            echo ""
            echo "Recent detections:"
            if [ -f /var/log/messages ]; then
                sudo tail -5 /var/log/messages | grep realm_c2_detect || echo "  (no recent detections)"
            elif [ -f /var/log/syslog ]; then
                sudo tail -5 /var/log/syslog | grep realm_c2_detect || echo "  (no recent detections)"
            fi
        else
            echo "[!] Realm C2 detection is NOT running"
        fi
        ;;
    restart)
        echo "[*] Restarting Realm C2 detection..."
        $0 stop
        sleep 2
        $0 start
        ;;
    logs)
        if [ -f /var/log/messages ]; then
            echo "[*] Tailing /var/log/messages (Ctrl+C to stop)..."
            sudo tail -f /var/log/messages | grep --color=auto realm_c2_detect
        elif [ -f /var/log/syslog ]; then
            echo "[*] Tailing /var/log/syslog (Ctrl+C to stop)..."
            sudo tail -f /var/log/syslog | grep --color=auto realm_c2_detect
        else
            echo "[!] Could not find system log file"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart|logs}"
        echo ""
        echo "Commands:"
        echo "  start    - Start Realm C2 detection"
        echo "  stop     - Stop Realm C2 detection"
        echo "  status   - Check if running and show recent detections"
        echo "  restart  - Restart Realm C2 detection"
        echo "  logs     - Tail logs in real-time"
        exit 1
        ;;
esac
