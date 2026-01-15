#!/bin/sh
echo "Flushing firewall on $(hostname)..."
iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
nft flush ruleset 2>/dev/null
echo "Firewall flushed."
