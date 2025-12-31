"""
Firewall hardening module for CCDC framework
Ported from lockdown.sh with Dead Man's Switch
"""

import logging
import time
from typing import List
from fabric import Connection, Config
from invoke.exceptions import CommandTimedOut, UnexpectedExit
from .base import HardeningModule, HardeningCommand, PythonAction, HardeningResult
from ..discovery import OSFamily

logger = logging.getLogger(__name__)

# Hardcoded from lockdown.sh
TRUSTED_IPS = [
    "203.0.113.10",
    "198.51.100.99",
    "10.0.0.2"
]

class FirewallHardeningModule(HardeningModule):
    """
    Firewall configuration module with Dead Man's Switch safety net.
    Supports: firewalld, iptables, nftables, pf, ipfw.
    """
    
    def __init__(self, connection, server_info, os_family):
        super().__init__(connection, server_info, os_family)
        self.dead_mans_switch_pid = None
        self.active_backend = None

    def get_name(self) -> str:
        return "firewall_hardening"
    
    def is_applicable(self) -> bool:
        return self.server_info.os.distro.lower() != "unknown"
    
    def _detect_backend(self, conn) -> str:
        """Detect the best available firewall backend"""
        # Logic mirrors lockdown.sh detection
        os_name = self.server_info.os.distro.lower()
        
        # Check firewalld first (must be running)
        if conn.run("command -v firewall-cmd && firewall-cmd --state", warn=True, hide=True).ok:
            return "firewalld"
            
        # BSD variants
        if "bsd" in os_name or "darwin" in os_name:
            if conn.run("command -v pfctl", warn=True, hide=True).ok:
                return "pf"
            if conn.run("command -v ipfw", warn=True, hide=True).ok:
                return "ipfw"
                
        # Linux alternatives
        if conn.run("command -v iptables", warn=True, hide=True).ok:
            return "iptables"
        if conn.run("command -v nft", warn=True, hide=True).ok:
            return "nft"
            
        return "unknown"

    def get_commands(self) -> List[HardeningCommand]:
        commands = []
        
        # Detection Step (PythonAction to set self.active_backend dynamically)
        commands.append(PythonAction(
            function=self._identify_backend,
            description="Identify active firewall backend",
            requires_sudo=True
        ))
        
        # Arm Dead Man's Switch
        commands.append(PythonAction(
            function=self._arm_dead_mans_switch,
            description="Arm Dead Man's Switch (60s revert timer)",
            requires_sudo=True
        ))
        
        # Apply Rules (PythonAction that generates and runs backend-specific commands)
        # We use a PythonAction here because the specific commands depend on the detection step
        commands.append(PythonAction(
            function=self._apply_firewall_rules,
            description="Apply firewall rules (Allow Trusted IPs ONLY)",
            requires_sudo=True
        ))
        
        # Test Connectivity
        commands.append(PythonAction(
            function=self._test_connectivity,
            description="Test SSH connectivity after firewall changes",
            requires_sudo=False
        ))
        
        return commands

    def _identify_backend(self, conn, server_info):
        # 1. Ensure tools are present
        self._ensure_firewall_installed(conn, server_info)
        
        # 2. Detect
        self.active_backend = self._detect_backend(conn)
        
        # 3. Prepare (Set to "Open/Trusted" initially)
        self._prepare_firewall(conn)

        return HardeningResult(
            success=True,
            command="identify_backend",
            description="Identified firewall backend",
            output=f"Backend: {self.active_backend}"
        )

    def _ensure_firewall_installed(self, conn, server_info):
        """Install and enable firewall service if missing (CentOS/OpenSUSE fix)"""
        # Check if already running/detected
        initial_backend = self._detect_backend(conn)
        if initial_backend != "unknown":
            logger.info(f"Firewall backend {initial_backend} already detected.")
            return

        pms = server_info.package_managers
        cmd = None
        service = None

        if "dnf" in pms:
            cmd = "dnf install -y firewalld"
            service = "firewalld"
        elif "yum" in pms:
            cmd = "yum install -y firewalld"
            service = "firewalld"
        elif "zypper" in pms:
            cmd = "zypper --non-interactive install firewalld"
            service = "firewalld"
        elif "apt" in pms:
            # Debian/Ubuntu usually have ufw
            cmd = "DEBIAN_FRONTEND=noninteractive apt-get install -y ufw"
            service = "ufw"
        elif "apk" in pms:
             # Alpine usually uses nftables or iptables; ensuring nftables is installed
             cmd = "apk add nftables"
             service = "nftables"

        if cmd:
            logger.info(f"Installing firewall tools: {cmd}")
            conn.sudo(cmd, hide=True)
            if service:
                # Some containers/distros might not have systemd, check first
                if conn.run("command -v systemctl", warn=True, hide=True).ok:
                    logger.info(f"Enabling {service} service...")
                    conn.sudo(f"systemctl unmask {service}", warn=True, hide=True)
                    conn.sudo(f"systemctl enable --now {service}", warn=True, hide=True)
                    time.sleep(3) # Give it moment to initialize
                # Fallback for Alpine/OpenRC
                elif conn.run("command -v rc-service", warn=True, hide=True).ok:
                     conn.sudo(f"rc-service {service} start", warn=True, hide=True)
                     conn.sudo(f"rc-update add {service}", warn=True, hide=True)

    def _prepare_firewall(self, conn):
        """Set firewall to OPEN/TRUSTED state before locking down (Plumbing fix)"""
        if not self.active_backend or self.active_backend == "unknown":
            return

        logger.info(f"Preparing {self.active_backend} (Setting to ALLOW ALL)...")
        try:
            if self.active_backend == "firewalld":
                conn.sudo("firewall-cmd --set-default-zone=trusted", hide=True)
                conn.sudo("firewall-cmd --reload", hide=True)
            elif self.active_backend == "ufw":
                conn.sudo("ufw default allow incoming", hide=True)
                conn.sudo("ufw default allow outgoing", hide=True)
                conn.sudo("echo 'y' | ufw enable", hide=True)
            elif self.active_backend == "iptables":
                conn.sudo("iptables -P INPUT ACCEPT", hide=True)
                conn.sudo("iptables -P OUTPUT ACCEPT", hide=True)
                conn.sudo("iptables -F", hide=True)
            elif self.active_backend == "nft":
                conn.sudo("nft flush ruleset", hide=True)
            elif self.active_backend == "pf":
                conn.sudo("pfctl -d", warn=True, hide=True)
            # ipfw usually default deny, we leave it alone until apply
        except Exception as e:
            logger.warning(f"Failed to prepare firewall: {e}")

    def _arm_dead_mans_switch(self, conn, server_info):
        """Start a background process that flushes firewalls after 60s unless killed"""
        if not self.active_backend or self.active_backend == "unknown":
            return HardeningResult(success=True, command="arm_dms", description="Skipping DMS (unknown backend)", output="Skipped")

        revert_cmd = ""
        if self.active_backend == "iptables":
            revert_cmd = "iptables -F && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT"
        elif self.active_backend == "firewalld":
            # Fix: set back to trusted so reload restores an open state
            revert_cmd = "firewall-cmd --set-default-zone=trusted && firewall-cmd --reload"
        elif self.active_backend == "nft":
            revert_cmd = "nft flush ruleset"
        elif self.active_backend == "pf":
            revert_cmd = "pfctl -d"
        elif self.active_backend == "ipfw":
            revert_cmd = "ipfw -q flush && ipfw add 65535 allow ip from any to any"
        else:
            return HardeningResult(success=False, command="arm_dms", description="Arm DMS", error="Unknown backend")

        # Command: sleep 60 && REVERT
        full_cmd = f"nohup sh -c \"sleep 60 && {revert_cmd} && echo 'DMS triggered'\" >/dev/null 2>&1 & echo $!"
        
        try:
            result = conn.sudo(full_cmd, hide=True)
            if result.ok and result.stdout.strip().isdigit():
                self.dead_mans_switch_pid = result.stdout.strip()
                logger.info(f"Armed Firewall DMS ({self.active_backend}) PID: {self.dead_mans_switch_pid}")
                return HardeningResult(success=True, command="arm_dms", description="Armed DMS", output=f"PID {self.dead_mans_switch_pid}")
        except Exception as e:
            return HardeningResult(success=False, command="arm_dms", description="Arm DMS", error=str(e))
            
        return HardeningResult(success=False, command="arm_dms", description="Arm DMS", error="Failed to get PID")

    def _apply_firewall_rules(self, conn, server_info):
        """Execute the actual firewall commands based on backend"""
        if not self.active_backend:
            return HardeningResult(success=False, command="apply_rules", description="Apply Rules", error="Backend not identified")

        try:
            if self.active_backend == "firewalld":
                return self._apply_firewalld(conn)
            elif self.active_backend == "iptables":
                return self._apply_iptables(conn)
            elif self.active_backend == "nft":
                return self._apply_nft(conn)
            elif self.active_backend == "pf":
                return self._apply_pf(conn)
            elif self.active_backend == "ipfw":
                return self._apply_ipfw(conn)
            else:
                return HardeningResult(success=True, command="apply_rules", description="Apply Rules", output="No supported firewall found (or TCP Wrappers only)")
        except Exception as e:
             return HardeningResult(success=False, command="apply_rules", description="Apply Rules", error=str(e))

    # --- Backend Specific Implementations ---

    def _apply_firewalld(self, conn):
        try:
            # 1. Reload to clear old runtime junk
            conn.sudo("firewall-cmd --reload", hide=True, timeout=30)
            
            # 2. Configure Trusted Zone
            # Add loopback interface to trusted zone (try/except in case of issues)
            conn.sudo("firewall-cmd --zone=trusted --add-interface=lo", warn=True, hide=True, timeout=30)
            
            # Add Trusted IPs to trusted zone
            for ip in TRUSTED_IPS:
                conn.sudo(f"firewall-cmd --zone=trusted --add-source={ip}", hide=True, timeout=30)
            
            # 3. Set Default Zone to Drop
            # This is the dangerous step that might cut connection
            conn.sudo("firewall-cmd --set-default-zone=drop", hide=True, timeout=10)
            
        except CommandTimedOut:
            logger.warning("Firewall command timed out (likely connection severed by rules). Assuming success.")
            return HardeningResult(success=True, command="apply_firewalld", description="Applied firewalld rules", output="Command timed out (Session severed)")
        except Exception as e:
            return HardeningResult(success=False, command="apply_firewalld", description="Applied firewalld rules", error=str(e))

        return HardeningResult(success=True, command="apply_firewalld", description="Applied firewalld rules", output="Zone rules applied")

    def _apply_iptables(self, conn):
        cmds = [
            "iptables -F", 
            "iptables -X", 
            "iptables -Z",
            "iptables -P INPUT ACCEPT", # Temp safety
            "iptables -P OUTPUT ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT"
        ]
        
        for ip in TRUSTED_IPS:
            cmds.append(f"iptables -A INPUT -s {ip} -j ACCEPT")
            cmds.append(f"iptables -A OUTPUT -d {ip} -j ACCEPT")
            
        cmds.append("iptables -P INPUT DROP")
        cmds.append("iptables -P FORWARD DROP")
        cmds.append("iptables -P OUTPUT DROP")
        
        full_cmd = " && ".join(cmds)
        try:
            conn.sudo(full_cmd, hide=True, timeout=10)
        except CommandTimedOut:
             logger.warning("IPTables command timed out (likely connection severed).")
             return HardeningResult(success=True, command="apply_iptables", description="Applied iptables rules", output="Command timed out (Session severed)")
        
        return HardeningResult(success=True, command="apply_iptables", description="Applied iptables rules", output="Rules applied")

    def _apply_nft(self, conn):
        script = [
            "nft flush ruleset",
            "nft add table inet filter",
            "nft add chain inet filter input { type filter hook input priority 0 ; policy drop ; }",
            "nft add chain inet filter forward { type filter hook forward priority 0 ; policy drop ; }",
            "nft add chain inet filter output { type filter hook output priority 0 ; policy drop ; }",
            "nft add rule inet filter input iif lo accept",
            "nft add rule inet filter output oif lo accept"
        ]
        for ip in TRUSTED_IPS:
            script.append(f"nft add rule inet filter input ip saddr {ip} accept")
            script.append(f"nft add rule inet filter output ip daddr {ip} accept")
            
        full_cmd = " && ".join([f"sh -c '{c}'" for c in script])
        try:
            conn.sudo(full_cmd, hide=True, timeout=10)
        except CommandTimedOut:
            logger.warning("NFTables command timed out (likely connection severed).")
            return HardeningResult(success=True, command="apply_nft", description="Applied nftables rules", output="Command timed out (Session severed)")
            
        return HardeningResult(success=True, command="apply_nft", description="Applied nftables rules", output="Rules applied")

    def _apply_pf(self, conn):
        pf_conf = "/tmp/pf.conf.go_dark"
        trusted_str = " ".join(TRUSTED_IPS)
        # Detect loopback interface name
        lo_if = "lo0"
        if conn.run("ifconfig lo0", warn=True, hide=True).failed:
            lo_if = "lo"
            
        conf_content = f"""
table <trusted_ssh> {{ {trusted_str} }}
set block-policy drop
set skip on {lo_if}
block in all
block out all
pass in from <trusted_ssh> to any no state
pass out from any to <trusted_ssh> no state
"""
        try:
            # Write config
            conn.sudo(f"printf '%s' '{conf_content}' > {pf_conf}", hide=True)
            # Apply
            conn.sudo(f"pfctl -f {pf_conf}", hide=True, timeout=10)
            conn.sudo("pfctl -e", warn=True, hide=True, timeout=10)
            conn.sudo("pfctl -F state", warn=True, hide=True, timeout=10) # Flush states
        except CommandTimedOut:
            logger.warning("PF command timed out (likely connection severed).")
            return HardeningResult(success=True, command="apply_pf", description="Applied PF rules", output="Command timed out (Session severed)")
        except Exception as e:
            return HardeningResult(success=False, command="apply_pf", description="Applied PF rules", error=str(e))

        
        return HardeningResult(success=True, command="apply_pf", description="Applied PF rules", output="PF rules loaded")

    def _apply_ipfw(self, conn):
        try:
            conn.sudo("ipfw -q flush", hide=True, timeout=10)
            conn.sudo("ipfw add 50 allow ip from any to any via lo0", hide=True, timeout=10)
            
            rule_id = 100
            for ip in TRUSTED_IPS:
                conn.sudo(f"ipfw add {rule_id} allow ip from {ip} to me in", hide=True, timeout=10)
                conn.sudo(f"ipfw add {rule_id+1} allow ip from me to {ip} out", hide=True, timeout=10)
                rule_id += 10
                
            # Deny rest
            conn.sudo("ipfw add 65000 deny ip from any to any", hide=True, timeout=10)
        except CommandTimedOut:
            logger.warning("IPFW command timed out (likely connection severed).")
            return HardeningResult(success=True, command="apply_ipfw", description="Applied IPFW rules", output="Command timed out (Session severed)")
        except Exception as e:
            return HardeningResult(success=False, command="apply_ipfw", description="Applied IPFW rules", error=str(e))

        
        return HardeningResult(success=True, command="apply_ipfw", description="Applied IPFW rules", output="IPFW rules applied")

    def _test_connectivity(self, conn, server_info):
        """Verify we are not locked out; disarm DMS on success"""
        # Standard Fabric connectivity test (implicit in run/sudo, but we do verification action explicitly)
        # Connection params:
        host = server_info.credentials.host
        user = server_info.credentials.user
        password = getattr(server_info.credentials, 'password', None)
        port = getattr(server_info.credentials, 'port', 22)
        key_file = getattr(server_info.credentials, 'key_file', None)
        
        # Prepare connectivity test
        connect_kwargs = {'allow_agent': False, 'look_for_keys': False, 'timeout': 10}
        if key_file:
            connect_kwargs['key_filename'] = key_file
        if password:
            connect_kwargs['password'] = password
        
        config = Config(overrides={'sudo': {'password': password}, 'load_ssh_configs': False})
        
        logger.info(f"Verifying connectivity to {host}...")
        try:
            # We must use a NEW connection to verify
            with Connection(host, user=user, port=port, config=config, connect_kwargs=connect_kwargs) as test_conn:
                test_conn.run("echo 'Connectivity Check'", hide=True, timeout=10)
            
            # If success, kill DMS
            if self.dead_mans_switch_pid:
                conn.sudo(f"kill {self.dead_mans_switch_pid} || true", hide=True, warn=True)
                logger.info(f"DMS Disarmed (PID {self.dead_mans_switch_pid})")
                return HardeningResult(success=True, command="verify_connectivity", description="Connectivity Verified", output="DMS Disarmed")
                
        except Exception as e:
            logger.error(f"Connectivity check failed: {e}")
            return HardeningResult(
                success=False, 
                command="verify_connectivity", 
                description="Connectivity Check", 
                error="Failed to connect. DMS should revert changes in ~60s.",
                output="LOCKED OUT?"
            )
        
        return HardeningResult(success=True, command="verify_connectivity", description="Connectivity Verified", output="Success")