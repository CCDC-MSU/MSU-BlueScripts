#!/bin/bash
# Nuke Logging Tools - Uninstall rsyslog, auditd, logrotate and remove configs
# This allows testing the logging_setup module from a clean state

set -e

echo "=== Nuking Logging Tools ==="
echo "Host: $(hostname)"
echo "Date: $(date)"

# Detect package manager
detect_package_manager() {
    if command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v zypper &>/dev/null; then
        echo "zypper"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v apk &>/dev/null; then
        echo "apk"
    elif command -v emerge &>/dev/null; then
        echo "emerge"
    elif command -v slackpkg &>/dev/null || command -v sbopkg &>/dev/null; then
        echo "slackware"
    else
        echo "unknown"
    fi
}

PM=$(detect_package_manager)
echo "Detected package manager: $PM"

# Stop services first
echo "=== Stopping services ==="
systemctl stop rsyslog 2>/dev/null || service rsyslog stop 2>/dev/null || /etc/init.d/rsyslog stop 2>/dev/null || rc-service rsyslog stop 2>/dev/null || true
systemctl stop auditd 2>/dev/null || service auditd stop 2>/dev/null || /etc/init.d/auditd stop 2>/dev/null || rc-service auditd stop 2>/dev/null || true

# Disable services
echo "=== Disabling services ==="
systemctl disable rsyslog 2>/dev/null || rc-update del rsyslog 2>/dev/null || chkconfig rsyslog off 2>/dev/null || true
systemctl disable auditd 2>/dev/null || rc-update del auditd 2>/dev/null || chkconfig auditd off 2>/dev/null || true

# Uninstall packages based on package manager
echo "=== Uninstalling packages ==="
case $PM in
    dnf)
        dnf remove -y rsyslog audit logrotate 2>/dev/null || true
        ;;
    yum)
        yum remove -y rsyslog audit logrotate 2>/dev/null || true
        ;;
    apt)
        DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge rsyslog auditd logrotate 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null || true
        ;;
    zypper)
        zypper --non-interactive remove rsyslog audit logrotate 2>/dev/null || true
        ;;
    pacman)
        pacman -Rns --noconfirm rsyslog audit logrotate 2>/dev/null || true
        ;;
    apk)
        apk del rsyslog audit logrotate 2>/dev/null || true
        ;;
    emerge)
        emerge --unmerge app-admin/rsyslog sys-process/audit app-admin/logrotate 2>/dev/null || true
        ;;
    slackware)
        # Slackware doesn't have a simple remove, packages are usually not installed anyway
        echo "Slackware: manual package removal needed or packages not installed"
        ;;
    *)
        echo "Unknown package manager, skipping package removal"
        ;;
esac

# Remove configuration files
echo "=== Removing configuration files ==="
rm -f /etc/rsyslog.conf.backup.* 2>/dev/null || true
rm -f /etc/rsyslog.d/ccdc-security.conf 2>/dev/null || true
rm -rf /etc/systemd/journald.conf.d/ccdc.conf 2>/dev/null || true
rm -f /etc/audit/rules.d/ccdc.rules 2>/dev/null || true
rm -f /etc/logrotate.d/ccdc-security 2>/dev/null || true

# Remove bash.bashrc additions (only the CCDC-specific ones)
if [ -f /etc/bash.bashrc ]; then
    sed -i '/HISTTIMEFORMAT/d' /etc/bash.bashrc 2>/dev/null || true
    sed -i '/HISTSIZE=10000/d' /etc/bash.bashrc 2>/dev/null || true
fi

echo "=== Verification ==="
echo "rsyslogd: $(command -v rsyslogd 2>/dev/null || echo 'NOT FOUND')"
echo "auditctl: $(command -v auditctl 2>/dev/null || echo 'NOT FOUND')"
echo "logrotate: $(command -v logrotate 2>/dev/null || echo 'NOT FOUND')"

echo "=== Done ==="
