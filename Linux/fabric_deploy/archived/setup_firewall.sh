#!/bin/sh
# firewall_prep.sh
# Purpose: Detect, enable, and FLUSH (allow-all) any native firewall system.
# Use this BEFORE running hardening scripts to ensure the "plumbing" works.

# Ensure standard paths are available (fixes CentOS/OpenSUSE detection)
export PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin

# ---------------- HELPERS ----------------
log() {
    echo "[PREP] $1"
}

warn() {
    echo "[WARN] $1"
}

run() {
    echo "+ $*"
    "$@"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: Must run as root."
        exit 1
    fi
}

# ---------------- LINUX HANDLERS ----------------

prep_firewalld() {
    log "Detected firewalld. Preparing..."
    
    # 1. Ensure service is running
    if command -v systemctl >/dev/null 2>&1; then
        run systemctl unmask firewalld
        run systemctl start firewalld
        run systemctl enable firewalld
    elif [ -f /etc/init.d/firewalld ]; then
        run /etc/init.d/firewalld start
    fi

    # 2. Wait a moment for dbus to catch up
    sleep 2

    # 3. SET TO OPEN (Trusted Zone)
    # The 'trusted' zone allows all connections by default.
    if firewall-cmd --state >/dev/null 2>&1; then
        log "Setting firewalld default zone to 'trusted' (ALLOW ALL)..."
        run firewall-cmd --set-default-zone=trusted
        run firewall-cmd --reload
        log "Firewalld is ready and open."
        return 0
    else
        warn "Firewalld installed but not running. Check system logs."
        return 1
    fi
}

prep_ufw() {
    log "Detected UFW. Preparing..."
    
    # 1. Set defaults to ALLOW first (to prevent lockout on enable)
    run ufw default allow incoming
    run ufw default allow outgoing
    
    # 2. Enable
    # piping 'y' because ufw might ask for confirmation
    echo "y" | run ufw enable
    
    # 3. Ensure it's running
    if ufw status | grep -q "active"; then
        log "UFW is active and set to ALLOW ALL."
        return 0
    fi
    return 1
}

prep_nft() {
    log "Detected nftables (nft). Preparing..."
    
    # 1. Start service if systemd
    if command -v systemctl >/dev/null 2>&1; then
        run systemctl enable nftables
        run systemctl start nftables
    fi

    # 2. Flush everything (Default policy in nft is usually implicit accept if no chains exist)
    run nft flush ruleset
    log "nftables ruleset flushed (implicit ALLOW ALL)."
    return 0
}

prep_iptables() {
    log "Detected iptables. Preparing..."
    
    # 1. Set policies to ACCEPT
    run iptables -P INPUT ACCEPT
    run iptables -P FORWARD ACCEPT
    run iptables -P OUTPUT ACCEPT
    
    # 2. Flush all rules and delete custom chains
    run iptables -F
    run iptables -X
    run iptables -Z
    
    log "iptables flushed and policies set to ACCEPT."
    return 0
}

# ---------------- BSD HANDLERS ----------------

prep_pf() {
    log "Detected PF (Packet Filter). Preparing..."
    
    # 1. Try to load kernel module (FreeBSD specific, OpenBSD has it built-in)
    if [ "$(uname)" = "FreeBSD" ]; then
        kldload pf >/dev/null 2>&1
    fi

    # 2. Enable in rc.conf (FreeBSD/NetBSD) to survive reboot
    if [ -f /etc/rc.conf ]; then
        if ! grep -q 'pf_enable="YES"' /etc/rc.conf; then
            log "Enabling pf in /etc/rc.conf..."
            run sysrc pf_enable="YES" >/dev/null 2>&1 || echo 'pf_enable="YES"' >> /etc/rc.conf
        fi
    fi

    # 3. Load "Pass All" rule and Enable
    # We do this via stdin to avoid needing a temporary file
    log "Loading 'pass all' rule..."
    echo "pass all" | pfctl -f -
    
    log "Enabling PF..."
    run pfctl -e >/dev/null 2>&1 
    
    # Just in case it was already running and had state
    run pfctl -F all >/dev/null 2>&1
    
    log "PF is active and passing all traffic."
    return 0
}

prep_ipfw() {
    log "Detected IPFW. Preparing..."
    
    # 1. Load module
    if [ "$(uname)" = "FreeBSD" ]; then
        kldload ipfw >/dev/null 2>&1
    fi

    # 2. Enable in rc.conf
    if [ -f /etc/rc.conf ]; then
        if ! grep -q 'firewall_enable="YES"' /etc/rc.conf; then
            log "Enabling firewall (ipfw) in /etc/rc.conf..."
            run sysrc firewall_enable="YES" >/dev/null 2>&1 || echo 'firewall_enable="YES"' >> /etc/rc.conf
            # Set type to open to be safe on reboot
            run sysrc firewall_type="open" >/dev/null 2>&1 || echo 'firewall_type="open"' >> /etc/rc.conf
        fi
    fi

    # 3. Force Allow-All
    # IPFW default can be "deny all", so we add allow rule BEFORE flushing if possible,
    # but flush removes everything.
    # The safest atomic-ish way: Flush, then immediately add allow.
    
    log "Flushing IPFW and adding allow-all..."
    # -f forces flush without confirmation
    # We use a subshell to try and execute these as close as possible
    (
        ipfw -f flush
        ipfw add 65535 allow ip from any to any
    )
    
    log "IPFW active with allow-all."
    return 0
}

# ---------------- MAIN DISPATCH ----------------

check_root
OS=$(uname -s)

log "Running on $OS..."

case "$OS" in
    Linux*)
        # Priority: Firewalld -> UFW -> NFT -> IPTables
        if command -v firewall-cmd >/dev/null 2>&1; then
            prep_firewalld
        elif command -v ufw >/dev/null 2>&1; then
            prep_ufw
        elif command -v nft >/dev/null 2>&1; then
            prep_nft
        elif command -v iptables >/dev/null 2>&1; then
            prep_iptables
        else
            warn "No known Linux firewall tools found!"
            exit 1
        fi
        ;;
        
    FreeBSD*|OpenBSD*|NetBSD*|DragonFly*|Darwin*)
        # Priority: PF -> IPFW
        if command -v pfctl >/dev/null 2>&1; then
            prep_pf
        elif command -v ipfw >/dev/null 2>&1; then
            prep_ipfw
        else
            warn "No known BSD firewall tools found!"
            exit 1
        fi
        ;;
        
    *)
        warn "Unknown OS family."
        exit 1
        ;;
esac

exit 0