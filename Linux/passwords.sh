#!/bin/bash

# Usage: ./update_passwords.sh input.csv
INPUT_CSV="$1"
OUTPUT_CSV="updated_passwords.csv"
TMP_CSV="$(mktemp)"

if [[ -z "$INPUT_CSV" || ! -f "$INPUT_CSV" ]]; then
    echo "Usage: $0 input.csv"
    exit 1
fi

# Prepare output CSV
echo "ip,username,new_password" > "$OUTPUT_CSV"

# Skip header and loop through CSV
tail -n +2 "$INPUT_CSV" | while IFS=, read -r IP USER PASS; do
    echo "Processing host $IP with user $USER"

    # Run multi-line password update script on the remote host
    OUTPUT=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$IP" \
        'SUDOPASS="'"$PASS"'" bash -s' <<'ENDSSH'
for u in $(awk -F: '($3==0) || ($3>=1000 && $7!="/sbin/nologin" && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print $1}' /etc/passwd); do
    newpass=$(openssl rand -base64 12 | tr -d "/+=" | cut -c1-15)

    if [ "$(id -u)" -ne 0 ]; then
        # Use sudo if not root
        echo "$SUDOPASS" | sudo -S sh -c "echo \"$u:$newpass\" | chpasswd"
    else
        # Root can run directly
        echo "$u:$newpass" | chpasswd
    fi

    # Output CSV line for this user
    echo "$u,$newpass"
done
ENDSSH
    )

    # Check for SSH failure
    if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to connect or execute commands on $IP"
        continue
    fi

    # Append output to consolidated CSV
    while IFS=, read -r remote_user newpass; do
        echo "$IP,$remote_user,$newpass" >> "$OUTPUT_CSV"

        # Update original CSV if this is the SSH user
        if [[ "$remote_user" == "$USER" ]]; then
            PASS="$newpass"
        fi
    done <<< "$OUTPUT"

    # Update the original CSV with the new SSH user password
    awk -F, -v ip="$IP" -v user="$USER" -v newpass="$PASS" 'BEGIN{OFS=","} {if($1==ip && $2==user) $3=newpass; print}' "$INPUT_CSV" > "$TMP_CSV" && mv "$TMP_CSV" "$INPUT_CSV"

done

echo "Password update complete. Updated passwords written to $OUTPUT_CSV"
