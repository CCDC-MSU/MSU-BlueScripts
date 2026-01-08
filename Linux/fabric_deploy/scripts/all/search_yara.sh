#!/bin/sh
#
# search_yara.sh - Scan filesystem for C2 beacon UUID files
#
# Description:
#   Uses YARA rules to detect potential C2 beacon identifier files (UUIDs).
#   Discovered file paths are written to a watchlist for monitoring by hawk.
#   The hawk daemon uses fanotify to watch these files and detect when
#   processes read them (indicating potential beacon activation).
#
# Usage:
#   sudo ./search_yara.sh
#
# Requirements:
#   - Root privileges (needed for full filesystem access)
#   - yara package installed
#
# Output:
#   Writes discovered file paths to /etc/hawk.watchlist
#

set -e

# Configuration
YARA_RULES_DIR="/etc/yara"
UUID_RULE="${YARA_RULES_DIR}/uuid.yar"
WATCHLIST="/etc/hawk.watchlist"

# Directories to scan for potential UUID files
SCAN_DIRS="
/
"

# Check if yara is installed
if ! command -v yara >/dev/null 2>&1; then
    echo "ERROR: yara command not found. Please install the yara package." >&2
    exit 1
fi

# Check if the UUID rule exists
if [ ! -f "$UUID_RULE" ]; then
    echo "ERROR: YARA rule not found: $UUID_RULE" >&2
    exit 1
fi

# Create empty watchlist (overwrites any existing content)
: > "$WATCHLIST"

# Temporary file for collecting results
TEMP_RESULTS=$(mktemp)
trap 'rm -f "$TEMP_RESULTS"' EXIT

# Scan each directory
for dir in $SCAN_DIRS; do
    # Skip if directory doesn't exist
    if [ ! -d "$dir" ]; then
        continue
    fi
    
    # Run YARA scan:
    #   -r: recursive
    #   -p 4: use 4 threads for performance
    #   -z 100: only scan files <= 100 bytes (UUID files are small)
    #   --no-follow-symlinks: don't follow symlinks
    # Suppress errors (permission denied, broken symlinks, etc.)
    # Extract just the file path (second field, space-separated)
    yara -r -p 4 -z 100 --no-follow-symlinks "$UUID_RULE" "$dir" 2>/dev/null \
        | awk '{print $2}' \
        >> "$TEMP_RESULTS" || true
done

# Write unique paths to watchlist
if [ -s "$TEMP_RESULTS" ]; then
    sort -u "$TEMP_RESULTS" > "$WATCHLIST"
fi

# Report results
count=$(wc -l < "$WATCHLIST" | tr -d ' ')
echo "Scan complete. Found $count potential UUID file(s)."
echo "Watchlist written to: $WATCHLIST"
