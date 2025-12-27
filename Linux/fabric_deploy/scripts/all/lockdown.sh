#!/bin/sh
# go_dark_unified.sh - Locks down Linux/BSD by applying the best available firewall backend.
# Backends attempted (by OS preference):
#   Linux: iptables -> nftables -> TCP Wrappers
#   BSD/Darwin: pf -> ipfw -> TCP Wrappers

# --- CONFIG ---
SSH_PORT=22

# Put your trusted IPv4 addresses here (one per line or space-separated)
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

# Safety net: auto-revert after N seconds to prevent lockout (0 disables)
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

norm_ip_list() {
  # Collapse whitespace/newlines to a single space-separated list
  printf "%s\n" "$1" | awk 'NF { printf "%s ", $1 }'
}

print_trusted_ips() {
  for ip in $TRUSTED_IPS_NORM; do
    echo "  - $ip"
  done
}

start_safety_net() {
  backend="$1"
  pid=""

  [ "$SAFETY_NET_SECONDS" -gt 0 ] 2>/dev/null || return 0

  case "$backend" in
    iptables)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Reverting iptables rules (flushing + ACCEPT)."
        iptables -F
        iptables -X
        iptables -Z
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
      ) &
      pid=$!
      ;;
    nft)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Reverting nftables (flush ruleset)."
        nft flush ruleset
      ) &
      pid=$!
      ;;
    pf)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Disabling pf (pfctl -d)."
        pfctl -d >/dev/null 2>&1
      ) &
      pid=$!
      ;;
    ipfw)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Reverting ipfw (flush + allow all)."
        ipfw -q flush
        ipfw add 65535 allow ip from any to any
      ) &
      pid=$!
      ;;
    *)
      return 0
      ;;
  esac

  echo "SAFETY NET: Will auto-revert in $SAFETY_NET_SECONDS seconds. To cancel: kill $pid"
}

apply_iptables() {
  echo "[INFO] Using iptables."

  iptables -F
  iptables -X
  iptables -Z

  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  for ip in $TRUSTED_IPS_NORM; do
    iptables -A INPUT -p tcp -s "$ip" --dport "$SSH_PORT" -j ACCEPT
  done

  echo "Firewall is now in 'go dark' mode (iptables). SSH allowed only from trusted IPs."
  start_safety_net iptables
  return 0
}

apply_nft() {
  echo "[INFO] Using nftables."

  nft flush ruleset

  nft add table inet filter
  nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
  nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
  nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }

  nft add rule inet filter input iif lo accept
  nft add rule inet filter input ct state established,related accept

  for ip in $TRUSTED_IPS_NORM; do
    nft add rule inet filter input ip saddr "$ip" tcp dport "$SSH_PORT" accept
  done

  echo "Firewall is now in 'go dark' mode (nftables). SSH allowed only from trusted IPs."
  start_safety_net nft
  return 0
}

apply_pf() {
  echo "[INFO] Using pf (pfctl)."

  PF_CONF_FILE="/tmp/pf.conf.lockdown"

  # Determine likely loopback interface name for pf rules
  LO_IF="lo0"
  if command -v ifconfig >/dev/null 2>&1; then
    if ! ifconfig lo0 >/dev/null 2>&1; then
      LO_IF="lo"
    fi
  fi

  # Build: "ip1, ip2, ip3"
  TRUSTED_IPS_PF=$(printf "%s\n" "$TRUSTED_IPS" | awk 'NF{printf "%s, ", $1}' | sed 's/, $//')

  cat > "$PF_CONF_FILE" << EOF
# pf configuration for 'go dark' mode
table <trusted_ssh> { $TRUSTED_IPS_PF }

set block-policy drop
set skip on $LO_IF

block in all
pass out all keep state
pass in proto tcp from <trusted_ssh> to any port $SSH_PORT keep state
EOF

  pfctl -f "$PF_CONF_FILE" || return 1
  pfctl -e >/dev/null 2>&1 || true

  echo "Firewall is now in 'go dark' mode (pf). SSH allowed only from trusted IPs."
  echo "To make permanent, copy $PF_CONF_FILE to /etc/pf.conf (and enable pf at boot as appropriate)."
  start_safety_net pf
  return 0
}

apply_ipfw() {
  echo "[INFO] Using ipfw."

  ipfw -q flush

  # State handling (helps return traffic)
  ipfw add 10 check-state

  # Allow loopback
  ipfw add 100 allow ip from any to any via lo0

  # Allow outbound
  ipfw add 200 allow ip from me to any out keep-state

  # Allow SSH only from trusted IPs
  rule=300
  for ip in $TRUSTED_IPS_NORM; do
    ipfw add "$rule" allow tcp from "$ip" to me "$SSH_PORT" in setup keep-state
    rule=$((rule + 10))
  done

  # Default deny last
  ipfw add 65534 deny ip from any to any

  echo "Firewall is now in 'go dark' mode (ipfw). SSH allowed only from trusted IPs."
  start_safety_net ipfw
  return 0
}

apply_tcp_wrappers() {
  echo "[WARNING] No supported kernel firewall found; falling back to TCP Wrappers."
  echo "[INFO] This only affects services compiled with libwrap (often sshd on older systems)."

  [ -f /etc/hosts.deny ]  && cp /etc/hosts.deny  /etc/hosts.deny.bak."$(date +%s)"
  [ -f /etc/hosts.allow ] && cp /etc/hosts.allow /etc/hosts.allow.bak."$(date +%s)"
  echo "[INFO] Backups of /etc/hosts.deny and /etc/hosts.allow created (if files existed)."

  echo "ALL: ALL" > /etc/hosts.deny
  echo "sshd: $TRUSTED_IPS_NORM" > /etc/hosts.allow

  echo "TCP Wrappers configured. SSH should be allowed only from trusted IPs."
  return 0
}

# --- MAIN ---

TRUSTED_IPS_NORM=$(norm_ip_list "$TRUSTED_IPS")

if [ -z "$TRUSTED_IPS_NORM" ]; then
  echo "No trusted IPs configured. Edit TRUSTED_IPS in the script."
  exit 1
fi

for ip in $TRUSTED_IPS_NORM; do
  if ! validate_ipv4 "$ip"; then
    echo "Invalid IP address in TRUSTED_IPS: $ip"
    exit 1
  fi
done

echo "WARNING: In 10 seconds, the system will be locked down."
echo "You will only be able to connect via SSH on port $SSH_PORT from:"
print_trusted_ips
echo "Press Ctrl+C to abort."
sleep 10

OS=$(uname -s 2>/dev/null || echo unknown)

case "$OS" in
  Linux*)
    if command -v iptables >/dev/null 2>&1; then
      apply_iptables && exit 0
    elif command -v nft >/dev/null 2>&1; then
      apply_nft && exit 0
    else
      apply_tcp_wrappers && exit 0
    fi
    ;;
  FreeBSD*|OpenBSD*|NetBSD*|DragonFly*|Darwin*)
    if command -v pfctl >/dev/null 2>&1; then
      apply_pf && exit 0
    elif command -v ipfw >/dev/null 2>&1; then
      apply_ipfw && exit 0
    else
      apply_tcp_wrappers && exit 0
    fi
    ;;
  *)
    # Unknown OS: fall back to “best guess” by command availability
    if command -v pfctl >/dev/null 2>&1; then
      apply_pf && exit 0
    elif command -v ipfw >/dev/null 2>&1; then
      apply_ipfw && exit 0
    elif command -v iptables >/dev/null 2>&1; then
      apply_iptables && exit 0
    elif command -v nft >/dev/null 2>&1; then
      apply_nft && exit 0
    else
      apply_tcp_wrappers && exit 0
    fi
    ;;
esac

echo "Unexpected error: no backend applied."
exit 1
