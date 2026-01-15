#!/bin/sh
# Verify logging tools installation

echo "Verifying logging tools on $(hostname)..."

# Helper to find command
find_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        echo "found"
    elif [ -f "/usr/sbin/$1" ]; then
        echo "found"
    elif [ -f "/sbin/$1" ]; then
        echo "found"
    elif [ -f "/usr/local/sbin/$1" ]; then
        echo "found"
    else
        echo "missing"
    fi
}

# Check rsyslog
RSYSLOG_STATUS=$(find_cmd rsyslogd)
if [ "$RSYSLOG_STATUS" = "found" ]; then
    echo "SAFE: rsyslog is installed"
else
    echo "CRITICAL: rsyslog is NOT installed"
fi

# Check auditd (linux only, might be missing on Alpine/BSD if not installed)
if [ "$(uname)" = "Linux" ]; then
    AUDIT_STATUS=$(find_cmd auditctl)
    if [ "$AUDIT_STATUS" = "found" ]; then
        echo "SAFE: auditd is installed"
    else
        echo "CRITICAL: auditd is NOT installed"
    fi
fi

# Check configuration files
if [ -f /etc/rsyslog.d/ccdc-security.conf ] || [ -f /usr/local/etc/rsyslog.d/ccdc-security.conf ]; then
    echo "SAFE: rsyslog security config exists"
else
    echo "WARNING: rsyslog security config missing"
fi

# Check Python
if command -v python3 >/dev/null 2>&1; then
    echo "INFO: python3 is present: $(python3 --version)"
else
    echo "INFO: python3 is MISSING"
fi
