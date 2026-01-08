#!/bin/sh
# Check if all uv installer dependencies are present
# Exit 0 if all present, exit 1 with list of missing

set -e

MISSING=""
WARNINGS=""

check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        MISSING="$MISSING $1"
    fi
}

# Required utilities
for cmd in tar gzip uname mktemp chmod awk grep sed cut; do
    check_cmd "$cmd"
done

# Linux-specific
if [ "$(uname -s)" = "Linux" ]; then
    check_cmd ldd
fi

# Need curl OR wget
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    MISSING="$MISSING curl-or-wget"
fi

# Check getent or $HOME
if ! command -v getent >/dev/null 2>&1; then
    if [ -z "$HOME" ]; then
        echo "WARNING: getent missing and \$HOME not set"
        export HOME=/root
    fi
fi

# Check SSL connectivity
if command -v curl >/dev/null 2>&1; then
    if ! curl -sSf https://astral.sh >/dev/null 2>&1; then
        WARNINGS="$WARNINGS ssl-check-failed"
    fi
elif command -v wget >/dev/null 2>&1; then
    if ! wget -q --spider https://astral.sh 2>/dev/null; then
        WARNINGS="$WARNINGS ssl-check-failed"
    fi
fi

if [ -n "$MISSING" ]; then
    echo "MISSING DEPENDENCIES:$MISSING"
    echo ""
    echo "Install missing utilities before proceeding."
    echo "Common package names:"
    echo "  Debian/Ubuntu: apt-get install -y coreutils gzip wget ca-certificates gawk"
    echo "  RHEL/Fedora:   dnf install -y coreutils gzip wget ca-certificates gawk"
    echo "  Alpine:        apk add coreutils gzip wget ca-certificates gawk"
    echo "  Arch:          pacman -S coreutils gzip wget ca-certificates gawk"
    exit 1
fi

if [ -n "$WARNINGS" ]; then
    echo "WARNINGS:$WARNINGS"
fi

echo "All uv installer dependencies present!"
exit 0
