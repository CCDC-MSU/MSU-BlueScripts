#!/bin/sh
# go_dark_unified.sh
# Default: lockdown (SSH only from trusted, block new outbound; SSH/loopback stateless)
# Flag: --allow-internet (still inbound locked; allow outbound updates statefully)

# ---------------- CONFIG ----------------
SSH_PORT=22

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

# Safety net: auto-revert after N seconds (0 disables)
SAFETY_NET_SECONDS=60

LOG_PREFIX_IN="GO_DARK_DENY_IN "
LOG_PREFIX_OUT="GO_DARK_DENY_OUT "
# -------------- END CONFIG --------------

MODE="lockdown"
case "${1:-}" in
  --allow-internet|-a) MODE="allow_internet" ;;
  --lockdown|-l|"")    MODE="lockdown" ;;
  --help|-h)
    echo "Usage:"
    echo "  $0                 # lockdown (SSH-only, no new outbound; SSH/loopback stateless)"
    echo "  $0 --allow-internet  # allow outbound updates (stateful) while inbound stays locked"
    exit 0
    ;;
  *)
    echo "Unknown argument: $1"
    exit 1
    ;;
esac

# Must be root
if command -v id >/dev/null 2>&1; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must be run as root."
    exit 1
  fi
fi

run_cmd() {
  echo "+ $*"
  "$@"
}

run_cmd_warn() {
  echo "+ $*"
  "$@" || echo "[WARN] command failed (continuing): $*"
}

validate_ipv4() {
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
  printf "%s\n" "$1" | awk 'NF { printf "%s ", $1 }'
}

TRUSTED_IPS_NORM=$(norm_ip_list "$TRUSTED_IPS")
if [ -z "$TRUSTED_IPS_NORM" ]; then
  echo "ERROR: No trusted IPs configured."
  exit 1
fi
for ip in $TRUSTED_IPS_NORM; do
  if ! validate_ipv4 "$ip"; then
    echo "ERROR: Invalid IP in TRUSTED_IPS: $ip"
    exit 1
  fi
done

echo "MODE: $MODE"
echo "SSH allowed only from trusted IPs on port $SSH_PORT:"
for ip in $TRUSTED_IPS_NORM; do echo "  - $ip"; done
echo "WARNING: Applying rules in 10 seconds. Ctrl+C to abort."
sleep 10

# ---------------- SAFETY NET ----------------
start_safety_net() {
  backend="$1"
  [ "$SAFETY_NET_SECONDS" -gt 0 ] 2>/dev/null || return 0

  case "$backend" in
    iptables)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Reverting iptables (flush + ACCEPT all)."
        iptables -F
        iptables -X
        iptables -Z
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
      ) &
      echo "SAFETY NET: Auto-revert in $SAFETY_NET_SECONDS seconds. Cancel: kill $!"
      ;;
    nft)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Reverting nftables (flush ruleset)."
        nft flush ruleset
      ) &
      echo "SAFETY NET: Auto-revert in $SAFETY_NET_SECONDS seconds. Cancel: kill $!"
      ;;
    pf)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Disabling pf (pfctl -d)."
        pfctl -d >/dev/null 2>&1
      ) &
      echo "SAFETY NET: Auto-revert in $SAFETY_NET_SECONDS seconds. Cancel: kill $!"
      ;;
    ipfw)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Reverting ipfw (flush + allow all)."
        ipfw -q flush
        ipfw add 65535 allow ip from any to any
      ) &
      echo "SAFETY NET: Auto-revert in $SAFETY_NET_SECONDS seconds. Cancel: kill $!"
      ;;
    firewalld)
      (
        sleep "$SAFETY_NET_SECONDS"
        echo "SAFETY NET: Reverting firewalld (reload)."
        firewall-cmd --reload >/dev/null 2>&1
      ) &
      echo "SAFETY NET: Auto-revert in $SAFETY_NET_SECONDS seconds. Cancel: kill $!"
      ;;
  esac
}

# ---------------- LINUX: FIREWALLD ----------------
apply_firewalld() {
  echo "[INFO] Backend: firewalld (firewall-cmd)"
  start_safety_net firewalld

  # 1. Clean slate for runtime (reload restores permanent, which is hopefully safe-ish, but we are about to override it)
  # We assume 'reload' clears any previous runtime direct rules we added.
  run_cmd firewall-cmd --reload

  # 2. Set default zone to drop to harden inputs (this doesn't affect direct rules with priority < zone)
  # But it helps ensure nothing slips through if direct rules fail.
  run_cmd firewall-cmd --set-default-zone=drop

  # 3. Direct Rules - Priority 0 (Highest)
  # Loopback
  run_cmd firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -i lo -j ACCEPT
  run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -o lo -j ACCEPT

  # SSH (Stateless - allows surviving state flush effectively)
  # Note: Direct rules bypass zones.
  for ip in $TRUSTED_IPS_NORM; do
    run_cmd firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp -s "$ip" --dport "$SSH_PORT" -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p tcp -d "$ip" --sport "$SSH_PORT" -j ACCEPT
  done

  if [ "$MODE" = "allow_internet" ]; then
    echo "[INFO] Allowing outbound updates statefully (DNS/HTTP/HTTPS/NTP/ICMP)."
    
    # We use priority 1 for these, below the stateless SSH/Loopback
    # Outbound (stateful)
    run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p udp --dport 53  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p tcp --dport 53  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p tcp --dport 80  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p udp --dport 123 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p icmp            -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    # Inbound return traffic (stateful)
    run_cmd firewall-cmd --direct --add-rule ipv4 filter INPUT 1 -p udp --sport 53  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter INPUT 1 -p tcp --sport 53  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter INPUT 1 -p tcp -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter INPUT 1 -p udp --sport 123 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run_cmd firewall-cmd --direct --add-rule ipv4 filter INPUT 1 -p icmp            -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi

  # Logging (Priority 998)
  run_cmd_warn firewall-cmd --direct --add-rule ipv4 filter INPUT 998 -m limit --limit 10/min --limit-burst 20 \
    -j LOG --log-prefix "$LOG_PREFIX_IN" --log-level 4
  run_cmd_warn firewall-cmd --direct --add-rule ipv4 filter OUTPUT 998 -m limit --limit 10/min --limit-burst 20 \
    -j LOG --log-prefix "$LOG_PREFIX_OUT" --log-level 4

  # DROP ALL (Priority 999) - Forces strict containment
  # This severs any existing connections not matched by above rules.
  run_cmd firewall-cmd --direct --add-rule ipv4 filter INPUT 999 -j DROP
  run_cmd firewall-cmd --direct --add-rule ipv4 filter OUTPUT 999 -j DROP

  echo "[INFO] Firewalld configured."
  echo "      Watch: journalctl -k -f | grep 'GO_DARK_'"
  return 0
}

# ---------------- LINUX: IPTABLES ----------------
apply_iptables() {
  echo "[INFO] Backend: iptables"

  # Safer ordering: build rules, then set DROP policies last.
  run_cmd iptables -F
  run_cmd iptables -X
  run_cmd iptables -Z

  run_cmd iptables -P INPUT ACCEPT
  run_cmd iptables -P FORWARD ACCEPT
  run_cmd iptables -P OUTPUT ACCEPT

  # Loopback (stateless)
  run_cmd iptables -A INPUT  -i lo -j ACCEPT
  run_cmd iptables -A OUTPUT -o lo -j ACCEPT

  # SSH (stateless): allow both directions explicitly, NO conntrack.
  for ip in $TRUSTED_IPS_NORM; do
    run_cmd iptables -A INPUT  -p tcp -s "$ip" --dport "$SSH_PORT" -j ACCEPT
    run_cmd iptables -A OUTPUT -p tcp -d "$ip" --sport "$SSH_PORT" -j ACCEPT
  done

  if [ "$MODE" = "allow_internet" ]; then
    echo "[INFO] Allowing outbound updates statefully (DNS/HTTP/HTTPS/NTP/ICMP)."

    # Outbound (stateful) – allow NEW+ESTABLISHED to destination ports
    run_cmd iptables -A OUTPUT -p udp --dport 53  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd iptables -A OUTPUT -p tcp --dport 53  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd iptables -A OUTPUT -p tcp --dport 80  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd iptables -A OUTPUT -p udp --dport 123 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    run_cmd iptables -A OUTPUT -p icmp            -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    # Inbound return traffic (stateful) – restrict to expected source ports/protocols
    run_cmd iptables -A INPUT -p udp --sport 53  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run_cmd iptables -A INPUT -p tcp --sport 53  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run_cmd iptables -A INPUT -p tcp -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run_cmd iptables -A INPUT -p udp --sport 123 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run_cmd iptables -A INPUT -p icmp            -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi

  # Logging for drops (packet-level “failed network requests”)
  run_cmd_warn iptables -A INPUT  -m limit --limit 10/min --limit-burst 20 \
    -j LOG --log-prefix "$LOG_PREFIX_IN" --log-level 4
  run_cmd_warn iptables -A OUTPUT -m limit --limit 10/min --limit-burst 20 \
    -j LOG --log-prefix "$LOG_PREFIX_OUT" --log-level 4

  # Default deny
  run_cmd iptables -P INPUT DROP
  run_cmd iptables -P FORWARD DROP
  run_cmd iptables -P OUTPUT DROP

  echo "[INFO] Denied packet logging enabled (kernel log)."
  echo "      Watch: journalctl -k -f | grep 'GO_DARK_'   (or: dmesg -w)"
  start_safety_net iptables
  return 0
}

# ---------------- LINUX: NFTABLES ----------------
apply_nft() {
  echo "[INFO] Backend: nftables"

  run_cmd nft flush ruleset

  run_cmd nft add table inet filter
  run_cmd sh -c 'nft add chain inet filter input   { type filter hook input priority 0 ; policy drop ; }'
  run_cmd sh -c 'nft add chain inet filter forward { type filter hook forward priority 0 ; policy drop ; }'
  run_cmd sh -c 'nft add chain inet filter output  { type filter hook output priority 0 ; policy drop ; }'

  # Loopback (stateless)
  run_cmd nft add rule inet filter input  iif lo accept
  run_cmd nft add rule inet filter output oif lo accept

  # SSH (stateless): allow both directions explicitly
  for ip in $TRUSTED_IPS_NORM; do
    run_cmd nft add rule inet filter input  ip saddr "$ip" tcp dport "$SSH_PORT" accept
    run_cmd nft add rule inet filter output ip daddr "$ip" tcp sport "$SSH_PORT" accept
  done

  if [ "$MODE" = "allow_internet" ]; then
    echo "[INFO] Allowing outbound updates statefully (DNS/HTTP/HTTPS/NTP/ICMP)."

    # Outbound stateful to update ports
    run_cmd nft add rule inet filter output udp dport 53  ct state new,established accept
    run_cmd nft add rule inet filter output tcp dport 53  ct state new,established accept
    run_cmd nft add rule inet filter output tcp dport 80  ct state new,established accept
    run_cmd nft add rule inet filter output tcp dport 443 ct state new,established accept
    run_cmd nft add rule inet filter output udp dport 123 ct state new,established accept
    run_cmd nft add rule inet filter output icmp         ct state new,established accept

    # Return traffic (restricted)
    run_cmd nft add rule inet filter input udp sport 53  ct state established,related accept
    run_cmd nft add rule inet filter input tcp sport 53  ct state established,related accept
    run_cmd nft add rule inet filter input tcp sport "{ 80, 443 }" ct state established,related accept
    run_cmd nft add rule inet filter input udp sport 123 ct state established,related accept
    run_cmd nft add rule inet filter input icmp          ct state established,related accept
  fi

  # Log drops explicitly (policy drop alone won’t log)
  run_cmd nft add rule inet filter input  limit rate 10/minute log prefix "\"$LOG_PREFIX_IN\""  level warning drop
  run_cmd nft add rule inet filter output limit rate 10/minute log prefix "\"$LOG_PREFIX_OUT\"" level warning drop

  echo "[INFO] Denied packet logging enabled (kernel log)."
  echo "      Watch: journalctl -k -f | grep 'GO_DARK_'   (or: dmesg -w)"
  start_safety_net nft
  return 0
}

# ---------------- BSD/DARWIN: PF ----------------
apply_pf() {
  echo "[INFO] Backend: pf (pfctl)"

  PF_CONF_FILE="/tmp/pf.conf.go_dark"
  LO_IF="lo0"
  if command -v ifconfig >/dev/null 2>&1; then
    if ! ifconfig lo0 >/dev/null 2>&1; then LO_IF="lo"; fi
  fi

  TRUSTED_IPS_PF=$(printf "%s\n" "$TRUSTED_IPS" | awk 'NF{printf "%s, ", $1}' | sed 's/, $//')
  echo "[INFO] Writing pf rules to: $PF_CONF_FILE"

  if [ "$MODE" = "allow_internet" ]; then
    cat > "$PF_CONF_FILE" << EOF
# pf go_dark allow-internet mode
table <trusted_ssh> { $TRUSTED_IPS_PF }

set block-policy drop
set skip on $LO_IF

# Log blocks to pflog0
block log in all
block log out all

# SSH stateless (no state) + explicit return path
pass in  proto tcp from <trusted_ssh> to any port $SSH_PORT no state
pass out proto tcp from any port $SSH_PORT to <trusted_ssh> no state

# Outbound updates stateful
pass out proto { udp tcp } to any port 53 keep state
pass out proto tcp to any port { 80 443 } keep state
pass out proto udp to any port 123 keep state
pass out proto icmp all keep state
EOF
  else
    cat > "$PF_CONF_FILE" << EOF
# pf go_dark lockdown mode (no stateful preservation)
table <trusted_ssh> { $TRUSTED_IPS_PF }

set block-policy drop
set skip on $LO_IF

# Log blocks to pflog0
block log in all
block log out all

# SSH stateless (no state) + explicit return path
pass in  proto tcp from <trusted_ssh> to any port $SSH_PORT no state
pass out proto tcp from any port $SSH_PORT to <trusted_ssh> no state
EOF
  fi

  echo "----- BEGIN $PF_CONF_FILE -----"
  cat "$PF_CONF_FILE"
  echo "----- END $PF_CONF_FILE -----"

  run_cmd pfctl -f "$PF_CONF_FILE"
  run_cmd_warn pfctl -e

  # IMPORTANT: drop any pre-existing stateful connections (malicious or otherwise).
  # SSH is stateless here, so it can survive state flush.
  run_cmd_warn pfctl -F state

  echo "[INFO] pf enabled; denies logged to pflog0."
  echo "      Watch: tcpdump -n -e -ttt -i pflog0"
  start_safety_net pf
  return 0
}

# ---------------- BSD: IPFW ----------------
apply_ipfw() {
  echo "[INFO] Backend: ipfw"

  run_cmd ipfw -q flush

  # Loopback (stateless)
  run_cmd ipfw add 50 allow ip from any to any via lo0

  # SSH stateless: allow both directions explicitly
  rule=100
  for ip in $TRUSTED_IPS_NORM; do
    run_cmd ipfw add "$rule"       allow tcp from "$ip" to me "$SSH_PORT" in
    run_cmd ipfw add "$((rule+1))" allow tcp from me "$SSH_PORT" to "$ip" out
    rule=$((rule + 10))
  done

  if [ "$MODE" = "allow_internet" ]; then
    echo "[INFO] Allowing outbound updates statefully (DNS/HTTP/HTTPS/NTP/ICMP)."

    # States only for update traffic
    run_cmd ipfw add 10 check-state

    run_cmd ipfw add 200 allow udp from me to any 53 out keep-state
    run_cmd ipfw add 210 allow tcp from me to any 53 out setup keep-state
    run_cmd ipfw add 220 allow tcp from me to any 80 out setup keep-state
    run_cmd ipfw add 230 allow tcp from me to any 443 out setup keep-state
    run_cmd ipfw add 240 allow udp from me to any 123 out keep-state
    run_cmd ipfw add 250 allow icmp from me to any out keep-state
  fi

  # Deny+log everything else (packet-level “failed requests”)
  run_cmd ipfw add 65000 deny log ip from any to any in
  run_cmd ipfw add 65010 deny log ip from any to any out

  echo "[INFO] ipfw deny logging enabled (syslog)."
  echo "      Watch (common): tail -f /var/log/security /var/log/messages 2>/dev/null | grep -i ipfw"
  start_safety_net ipfw
  return 0
}

# ---------------- FALLBACK: TCP WRAPPERS ----------------
apply_tcp_wrappers() {
  echo "[WARN] No supported kernel firewall found; falling back to TCP Wrappers."
  echo "[WARN] This may not affect sshd on modern systems; packet-level deny logging not available here."

  [ -f /etc/hosts.deny ]  && run_cmd cp /etc/hosts.deny  /etc/hosts.deny.bak."$(date +%s)"
  [ -f /etc/hosts.allow ] && run_cmd cp /etc/hosts.allow /etc/hosts.allow.bak."$(date +%s)"

  run_cmd sh -c 'echo "ALL: ALL" > /etc/hosts.deny'
  run_cmd sh -c "echo \"sshd: $TRUSTED_IPS_NORM\" > /etc/hosts.allow"
  return 0
}

# ---------------- MAIN DISPATCH ----------------
OS=$(uname -s 2>/dev/null || echo unknown)

case "$OS" in
  Linux*)
    # Check for firewalld first (active)
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
      apply_firewalld && exit 0
    elif command -v iptables >/dev/null 2>&1; then
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
    if command -v pfctl >/dev/null 2>&1; then apply_pf && exit 0; fi
    if command -v ipfw >/dev/null 2>&1; then apply_ipfw && exit 0; fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then apply_firewalld && exit 0; fi
    if command -v iptables >/dev/null 2>&1; then apply_iptables && exit 0; fi
    if command -v nft >/dev/null 2>&1; then apply_nft && exit 0; fi
    apply_tcp_wrappers && exit 0
    ;;
esac

echo "ERROR: unexpected failure."
exit 1
