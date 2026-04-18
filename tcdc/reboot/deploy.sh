#!/usr/bin/env bash
set -uo pipefail

OUR_TEAM=4
DEPLOY_USER="mike"
DEPLOY_PASS="Bar-Large-Tower1"
BINARY="reboot_bin"

if ! command -v sshpass &>/dev/null; then
    echo "[-] sshpass not found. Install: sudo apt install sshpass"
    exit 1
fi

if ! command -v go &>/dev/null; then
    echo "[-] go not found"
    exit 1
fi

# Build static binary
echo "[*] Building..."
cd "$(dirname "$0")/reboot"
go mod tidy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "../${BINARY}" .
cd ..
echo "[+] Build complete"

deploy() {
    local suffix=$1; shift
    local host="10.66.${OUR_TEAM}.${suffix}"
    local targets="$*"

    sshpass -p "$DEPLOY_PASS" scp -o StrictHostKeyChecking=no \
        "./${BINARY}" "${DEPLOY_USER}@${host}:/tmp/${BINARY}" 2>/dev/null

    sshpass -p "$DEPLOY_PASS" ssh -o StrictHostKeyChecking=no \
        "${DEPLOY_USER}@${host}" "chmod +x /tmp/${BINARY} && /tmp/${BINARY} ${targets}" 2>/dev/null

    echo "[+] ${host}: finished (targets: ${targets})"
}

echo "[*] Deploying to all 5 hosts..."

# 9 other teams distributed across our 5 boxes
deploy 11 1 2  &
deploy 12 3 5  &
deploy 13 6 7  &
deploy 14 8 9  &
deploy 15 10   &

wait
echo "[+] All done"
