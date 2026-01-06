#!/bin/bash
# Uninstall logging tools (rsyslog, auditd) and remove CCDC configs

echo "Uninstalling logging tools on $(hostname)..."

if [ -f /etc/redhat-release ] || [ -f /etc/fedora-release ] || [ -f /etc/rocky-release ]; then
  echo "Detected RHEL/CentOS/Rocky/Fedora"
  yum remove -y rsyslog audit || dnf remove -y rsyslog audit
  # Also clean up any yum/dnf cache
  yum clean all || dnf clean all
elif [ -f /etc/debian_version ]; then
  echo "Detected Debian/Ubuntu"
  DEBIAN_FRONTEND=noninteractive apt-get remove -y rsyslog auditd
  DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
elif [ -f /etc/alpine-release ]; then
  echo "Detected Alpine"
  apk del rsyslog audit
elif [ -f /etc/arch-release ]; then
  echo "Detected Arch"
  # -Rns removes recursive, backup files, and unneeded dependencies
  pacman -Rns --noconfirm rsyslog audit
elif [ -f /etc/SuSE-release ] || grep -q openSUSE /etc/os-release; then
  echo "Detected SUSE"
  zypper rm -y rsyslog audit
elif [ -f /etc/gentoo-release ]; then
  echo "Detected Gentoo"
  emerge -C rsyslog audit
elif [ -f /etc/slackware-version ]; then
  echo "Detected Slackware"
  removepkg rsyslog audit
  # Check if they are still there
  if command -v rsyslogd >/dev/null; then echo "rsyslog still present"; fi
elif uname -s | grep -ii "BSD" >/dev/null; then
  echo "Detected BSD"
  pkg delete -y rsyslog auditd
else
  echo "Unknown OS or detection failed"
  # Attempt generic removal?
  exit 0
fi

echo "Removing configuration files..."
rm -f /etc/rsyslog.d/ccdc-security.conf
rm -f /etc/systemd/journald.conf.d/ccdc.conf
rm -f /etc/audit/rules.d/ccdc.rules
rm -f /etc/logrotate.d/ccdc-security
# BSD paths
rm -f /usr/local/etc/rsyslog.d/ccdc-security.conf

# Reset process accounting
if command -v accton >/dev/null; then
    accton off 2>/dev/null || true
    echo "Process accounting disabled"
fi

echo "Uninstallation complete."
