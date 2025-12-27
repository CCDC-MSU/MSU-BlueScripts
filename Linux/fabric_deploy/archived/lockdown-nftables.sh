#!/bin/sh
# go_dark_nftables.sh - Locks down a Linux system using nftables

# Prompt for the trusted IP address
printf "Enter the ONLY IP address you want to allow SSH from: "
read -r TRUSTED_IP

# Validate the IP address format
if ! echo "$TRUSTED_IP" | grep -E -q '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
  echo "Invalid IP address format. Exiting."
  exit 1
fi

echo "Applying 'go dark' rules with nftables for trusted IP: $TRUSTED_IP"

# Flush the entire ruleset
nft flush ruleset

# Create a new table
nft add table inet filter

# Add chains for input, forward, and output
nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }

# Add rules to the input chain
# Allow loopback traffic
nft add rule inet filter input iif lo accept
# Allow traffic from established connections
nft add rule inet filter input ct state established,related accept
# Allow SSH from the trusted IP
nft add rule inet filter input ip saddr "$TRUSTED_IP" tcp dport 22 accept

echo "Nftables rules applied. Only SSH from $TRUSTED_IP is allowed."
echo "To make these rules permanent, save the ruleset:"
echo "  nft list ruleset > /etc/nftables.conf"
echo "Then enable the nftables service."
