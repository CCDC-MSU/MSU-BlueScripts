#!/bin/bash
# update_passwords.sh
# Usage: ./update_passwords.sh user

PASS_FILE="./passwords.conf"
SYSTEM="$1"

if [ -z "$SYSTEM" ] || [ "$SYSTEM" != "user" ]; then
    echo "Usage: $0 user"
    exit 1
fi

# Helper: extract value from passwords.conf
get_pass() {
    local system="$1"
    local field="$2"
    awk -F= -v sys="[$system]" -v fld="$field" '
        $0==sys { in_section=1; next }
        /^\[/ { in_section=0 }
        in_section {
            key=$1; gsub(/^[ \t]+|[ \t]+$/, "", key)
            val=$2; gsub(/^[ \t]+|[ \t]+$/, "", val)
            if (key==fld) { print val; exit }
        }
    ' "$PASS_FILE"
}

get_username() {
    local system="$1"
    awk -F= -v sys="[$system]" '
        $0==sys { in_section=1; next }
        /^\[/ { in_section=0 }
        in_section {
            key=$1; gsub(/^[ \t]+|[ \t]+$/, "", key)
            val=$2; gsub(/^[ \t]+|[ \t]+$/, "", val)
            if (key=="username") { print val; exit }
        }
    ' "$PASS_FILE"
}

NEW_PASS=$(get_pass "user" "new")
LAST_PASS=$(get_pass "user" "last")
USERNAME=$(get_username "user")

if [ -z "$NEW_PASS" ]; then
    echo "Error: No new password for [user] in $PASS_FILE"
    exit 1
fi

if [ -z "$USERNAME" ]; then
    USERNAME="$USER"   # fallback to the connected user
fi

#########################################
# Only user update
#########################################

echo "Updating local user password for $USERNAME..."
echo -e "${LAST_PASS}\n${NEW_PASS}\n${NEW_PASS}" | passwd "$USERNAME"
rc=$?

if [ $rc -ne 0 ]; then
    echo "Password update for [user] failed with exit code $rc."
    exit $rc
fi

echo "Password update for [user] complete."
exit 0
