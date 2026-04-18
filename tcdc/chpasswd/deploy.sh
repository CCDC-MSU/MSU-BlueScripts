#!/bin/bash

TEAM=4
HOSTS=(11 12 13 14 15)
NAMES=(centurytree aggiedrop bonfire reveille-remote excel)
USER="alice"
PASS="Sets0-Break-Subject"
BINARY="./chpasswd"
SSH_OPTS="-o StrictHostKeyChecking=no"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: $BINARY not found. Build it first."
    exit 1
fi

deploy_box() {
    local IP="10.66.${TEAM}.${1}"
    local NAME="$2"
    local LOG
    LOG=$(
        sshpass -p "$PASS" scp $SSH_OPTS "$BINARY" "${USER}@${IP}:~/chpasswd" 2>&1 &&
        sshpass -p "$PASS" ssh $SSH_OPTS "${USER}@${IP}" "chmod +x ~/chpasswd && echo '$PASS' | sudo -S ~/chpasswd && rm ~/chpasswd" 2>&1
    )
    local STATUS=$?
    echo "=== ${NAME} (${IP}) ==="
    echo "$LOG"
    echo ""
    return $STATUS
}

PIDS=()
for i in "${!HOSTS[@]}"; do
    deploy_box "${HOSTS[$i]}" "${NAMES[$i]}" &
    PIDS+=($!)
done

FAILED=0
for pid in "${PIDS[@]}"; do
    wait "$pid" || ((FAILED++))
done

if [ $FAILED -eq 0 ]; then
    echo "All boxes done."
else
    echo "WARNING: $FAILED box(es) failed."
    exit 1
fi
