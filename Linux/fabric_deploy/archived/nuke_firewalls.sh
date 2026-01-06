#!/bin/bash
# Nuke all firewall tools to simulate a clean slate for module testing

echo "Nuking firewalls on $(hostname)..."

# Function to run command if binary exists
check_run() {
    if command -v "$1" >/dev/null 2>&1; then
        "$@"
    fi
}

# 1. Stop Services first
echo "Stopping services..."
check_run systemctl stop firewalld ufw nftables iptables
check_run systemctl disable firewalld ufw nftables iptables

# 2. Uninstall Packages based on Distro
if [ -f /etc/redhat-release ]; then
    echo "RedHat/CentOS/Fedora detected"
    if command -v dnf >/dev/null; then
        dnf remove -y firewalld ufw nftables conntrack-tools
    else
        yum remove -y firewalld ufw nftables conntrack-tools
    fi
    
elif [ -f /etc/debian_version ]; then
    echo "Debian/Ubuntu detected"
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y ufw firewalld nftables conntrack conntrack-tools iptables-persistent
    apt-get autoremove -y

elif [ -f /etc/alpine-release ]; then
    echo "Alpine detected"
    apk del nftables firewalld ufw conntrack-tools
    # Keep iptables as it might be part of base or needed for networking, but remove extras
    
elif [ -f /etc/arch-release ]; then
    echo "Arch detected"
    pacman -Rns --noconfirm firewalld ufw nftables conntrack-tools || true
    
elif [ -f /etc/slackware-version ]; then
    echo "Slackware detected"
    # Slackware usually uses packages but raw init scripts.
    removepkg conntrack-tools firewalld ufw nftables || true
    # Clear iptables manually just in case
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    
elif [ -f /etc/gentoo-release ]; then
    echo "Gentoo detected"
    emerge --deselect --unmerge firewalld ufw conntrack-tools nftables || true
    
fi

# 3. Flush any remaining rules (nuclear option) to ensure "uninstalled" feel doesn't leave locked state
# BUT be careful not to lock out. Default policy ACCEPT first.
echo "Flushing residual rules..."
if command -v iptables >/dev/null; then
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F
    iptables -X
fi

if command -v nft >/dev/null; then
    nft flush ruleset
fi

echo "Firewall nuke complete."
