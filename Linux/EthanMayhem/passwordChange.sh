#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

for user in $(cat /etc/passwd | grep -E "/bin/bash|/bin/sh" | cut -d: -f1); do #Gets the users of anyone who doesnt have nologin or false shells in /etc/passwd
    NEW_PASS=$(openssl rand -base64 64 | tr -dc 'A-Za-z0-9' | head -c 20)
    USER_UID=$(id -u "$user")

    if [ "$USER_UID" -lt 1000 ]; then #Skips system and service accounts
        echo "Skipping system/service account $user with UID $USER_UID"
        continue
    fi

    echo "Changing password for $user"

    echo "$user:$NEW_PASS" >> /tmp/log.txt
    echo "$user:$NEW_PASS" | chpasswd # Generates a random 32 byte string password for user
done
