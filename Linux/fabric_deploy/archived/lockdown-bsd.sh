#!/bin/sh
# go_dark_bsd.sh - Locks down a BSD system by trying pf, ipfw, or TCP wrappers.
# Allows SSH only from a hard-coded list of trusted IPs.

# --- CONFIG ---
SSH_PORT=22

# Space-separated / newline-separated list of trusted IPv4 addresses (edit these)
TRUSTED_IPS="
203.0.113.10
198.51.100.7
192.0.2.25
192.0.2.26
198.51.100.42
203.0.113.77
203.0.113.78
198.51.100.99
"
# --- END CONFIG ---

validate_ipv4() {
  # Returns 0 if valid IPv4, 1 otherwise
  echo "$1" | awk -F. '
    NF!=4 { exit 1 }
    {
      for (i=1; i<=4; i++) {
        if ($i !~ /^[0-9]+$/) exit 1
        if ($i < 0 || $i > 255) exit 1
      }
      exit 0
    }' >/dev/null 2>&1
}

# Normalize list (collapse whitespace/newlines to spaces)
TRUSTED_IPS_NORM=$(printf "%s\n" "$TRUSTED_IPS" | awk 'NF {printf "%s ", $1}')

if [ -z "$TRUSTED_IPS_NORM" ]; then
  echo "No trusted IPs configured. Edit TRUSTED_IPS in the script."
  exit 1
fi

# Validate all IPs before doing anything disruptive
for ip in $TRUSTED_IPS_NORM; do
  if ! validate_ipv4 "$ip"; then
    echo "Invalid IP address in TRUSTED_IPS: $ip"
    exit 1
  fi
done

echo "WARNING: In 10 seconds, the system will be locked down."
echo "You will only be able to connect via SSH on port $SSH_PORT from:"
for ip in $TRUSTED_IPS_NORM; do
  echo "  - $ip"
done
echo "Press Ctrl+C to abort."
sleep 10

# --- Check for pf ---
if command -v pfctl >/dev/null 2>&1; then
  echo "[INFO] Using pf to apply firewall rules."
  PF_CONF_FILE="/tmp/pf.conf.lockdown"

  # Build a pf table list: "ip1, ip2, ip3"
  TRUSTED_IPS_PF=$(printf "%s\n" "$TRUSTED_IPS" | awk 'NF{printf "%s, ", $1}' | sed 's/, $//')

  # Create the pf.conf file content
  cat > "$PF_CONF_FILE" << EOF
# pf configuration for 'go dark' mode
table <trusted_ssh> { $TRUSTED_IPS_PF }

set block-policy drop
block in all
pass out all keep state
pass in proto tcp from <trusted_ssh> to any port $SSH_PORT keep state
EOF

  # Load the new ruleset and enable the firewall
  pfctl -f "$PF_CONF_FILE"
  pfctl -e

  echo "Firewall is now in 'go dark' mode. SSH is allowed only from trusted IPs."
  echo "To make these rules permanent, copy $PF_CONF_FILE to /etc/pf.conf."
  exit 0

# --- Check for ipfw ---
elif command -v ipfw >/dev/null 2>&1; then
  echo "[INFO] pf not found. Using ipfw."

  # Flush existing rules
  ipfw -q flush

  # Allow loopback first
  ipfw add 100 allow all from any to any via lo0

  # Allow outbound TCP (creates dynamic state entries for return traffic)
  ipfw add 200 allow all from me to any setup keep-state

  # Allow SSH only from the trusted IPs
  rule=300
  for ip in $TRUSTED_IPS_NORM; do
    ipfw add "$rule" allow tcp from "$ip" to me "$SSH_PORT" setup keep-state
    rule=$((rule + 10))
  done

  # Default deny last
  ipfw add 65534 deny all from any to any

  echo "IPFW rules applied. SSH is allowed only from trusted IPs."
  echo "To make rules permanent, add them to your system's startup configuration."
  exit 0

# --- Fallback to TCP Wrappers ---
else
  echo "[WARNING] No kernel firewall found (pf or ipfw)."
  echo "[INFO] Falling back to TCP Wrappers. This is less secure and only protects services that support it."

  # Backup existing files (if they exist)
  [ -f /etc/hosts.deny ]  && cp /etc/hosts.deny  /etc/hosts.deny.bak."$(date +%s)"
  [ -f /etc/hosts.allow ] && cp /etc/hosts.allow /etc/hosts.allow.bak."$(date +%s)"
  echo "[INFO] Backups of /etc/hosts.deny and /etc/hosts.allow have been created (if files existed)."

  # 1. Deny everything by default
  echo "ALL: ALL" > /etc/hosts.deny

  # 2. Allow SSH from the trusted IPs (space-separated list is OK for libwrap)
  echo "sshd: $TRUSTED_IPS_NORM" > /etc/hosts.allow

  echo "TCP Wrappers configured. SSH should be allowed only from trusted IPs."
  echo "NOTE: This does not affect services that are not compiled with libwrap."
  exit 0
fi
