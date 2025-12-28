sh
#!/bin/sh
# go_dark_linux.sh - Locks down a Linux system by trying iptables, nftables, or TCP wrappers.
# Allows SSH only from a hard-coded list of trusted IPs.

# --- CONFIG ---
SSH_PORT=22

# Space-separated list of trusted IPv4 addresses (edit these)
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

SAFETY_NET_SECONDS=60
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

# Build a normalized list (collapse newlines/tabs into spaces)
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

# --- Check for iptables ---
if command -v iptables >/dev/null 2>&1; then
  echo "[INFO] Using iptables to apply firewall rules."

  # 1. Flush all existing rules and chains
  iptables -F
  iptables -X
  iptables -Z

  # 2. Set default policies to DROP everything
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT # Allow outbound traffic

  # 3. Allow loopback and established connections
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  # 4. Allow SSH only from the trusted IP addresses
  for ip in $TRUSTED_IPS_NORM; do
    iptables -A INPUT -p tcp -s "$ip" --dport "$SSH_PORT" -j ACCEPT
  done

  echo "Firewall is now in 'go dark' mode. SSH is allowed only from trusted IPs."
  echo "These rules are temporary. To make them permanent, use 'iptables-save'."

  # Safety net: flush rules after N seconds
  (
    sleep "$SAFETY_NET_SECONDS"
    echo "SAFETY NET: Flushing firewall rules."
    iptables -F
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
  ) &
  echo "SAFETY NET: Rules will be flushed in $SAFETY_NET_SECONDS seconds. To cancel, run: kill $!"
  exit 0

# --- Check for nftables ---
elif command -v nft >/dev/null 2>&1; then
  echo "[INFO] iptables not found. Using nftables."

  # Flush the entire ruleset
  nft flush ruleset

  # Create a new table and chains with default drop
  nft add table inet filter
  nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
  nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
  nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }

  # Add rules to allow essential traffic
  nft add rule inet filter input iif lo accept
  nft add rule inet filter input ct state established,related accept

  # Allow SSH only from the trusted IP addresses
  for ip in $TRUSTED_IPS_NORM; do
    nft add rule inet filter input ip saddr "$ip" tcp dport "$SSH_PORT" accept
  done

  echo "Nftables rules applied. SSH is allowed only from trusted IPs."
  echo "To make these rules permanent, save the ruleset to /etc/nftables.conf."

  # Optional safety net for nftables as well
  (
    sleep "$SAFETY_NET_SECONDS"
    echo "SAFETY NET: Flushing nftables ruleset."
    nft flush ruleset
  ) &
  echo "SAFETY NET: Ruleset will be flushed in $SAFETY_NET_SECONDS seconds. To cancel, run: kill $!"
  exit 0

# --- Fallback to TCP Wrappers ---
else
  echo "[WARNING] No kernel firewall found (iptables or nftables)."
  echo "[INFO] Falling back to TCP Wrappers. This is less secure and only protects services that support it."

  # Backup existing files (if they exist)
  [ -f /etc/hosts.deny ]  && cp /etc/hosts.deny  /etc/hosts.deny.bak."$(date +%s)"
  [ -f /etc/hosts.allow ] && cp /etc/hosts.allow /etc/hosts.allow.bak."$(date +%s)"
  echo "[INFO] Backups of /etc/hosts.deny and /etc/hosts.allow have been created (if files existed)."

  # 1. Deny everything by default
  echo "ALL: ALL" > /etc/hosts.deny

  # 2. Allow SSH from the trusted IPs
  # libwrap accepts a list of clients on one line (space/comma separated)
  echo "sshd: $TRUSTED_IPS_NORM" > /etc/hosts.allow

  echo "TCP Wrappers configured. SSH should be allowed only from trusted IPs."
  echo "NOTE: This does not affect services that are not compiled with libwrap."
  exit 0
fi
