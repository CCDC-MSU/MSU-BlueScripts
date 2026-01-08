"""
Firewall hardening module for CCDC framework
Ported from lockdown.sh with Dead Man's Switch
"""
# To-Do: if running firewalld we should also try to install conntrack-tools (or equivalent) first

import logging
import time
from typing import List
from fabric import Connection, Config
from invoke.exceptions import CommandTimedOut, UnexpectedExit
from .base import HardeningModule, HardeningCommand, PythonAction, HardeningResult
from ..discovery import OSFamily
import os

logger = logging.getLogger(__name__)

# Path to root key for connectivity testing
ROOT_KEY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../keys/test-root-key.private"))

# Hardcoded from lockdown.sh
TRUSTED_IPS = [
    "10.0.0.2",
    "100.18.6.211",
    "172.239.63.207"
]

# Ports allowed in "allow_internet" mode (for package updates)
# Format: {port: [protocols]}
INTERNET_PORTS = {
    53: ["udp", "tcp"],   # DNS
    80: ["tcp"],          # HTTP
    443: ["tcp"],         # HTTPS
    123: ["udp"],         # NTP
    25: ["tcp"],          # SMTP
}

# UID range for system users (0-999 are system accounts, 1000+ are human users)
SYSTEM_UID_MAX = 999

# Firewall mode constants
MODE_STRICT = "strict"
MODE_ALLOW_INTERNET = "allow_internet"

class FirewallHardeningModule(HardeningModule):
    """
    Firewall configuration module with Dead Man's Switch safety net.
    Supports: firewalld, iptables, nftables, pf, ipfw.
    """
    
    def __init__(self, connection, server_info, os_family, mode: str = MODE_STRICT):
        """
        Initialize firewall hardening module.

        Args:
            connection: Fabric connection
            server_info: ServerInfo object with system details
            os_family: OS family string
            mode: Firewall mode - "strict" (default) or "allow_internet"
                  - strict: Only traffic from trusted IPs allowed
                  - allow_internet: Allows outbound HTTP/HTTPS/DNS/NTP/SMTP for system users (UID 0-999)
        """
        super().__init__(connection, server_info, os_family)
        self.dead_mans_switch_pid = None
        self.active_backend = None
        self.mode = mode if mode in (MODE_STRICT, MODE_ALLOW_INTERNET) else MODE_STRICT
        self.uses_hybrid_nftables = False  # Track if we injected custom nftables rules
        logger.info(f"Firewall module initialized with mode: {self.mode}")

    def get_name(self) -> str:
        return "firewall_hardening"
    
    def is_applicable(self) -> bool:
        return self.server_info.os.distro.lower() != "unknown"
    
    def _detect_backend(self, conn) -> str:
        """Detect the best available firewall backend"""
        # Logic mirrors lockdown.sh detection
        os_name = self.server_info.os.distro.lower()
        
        if conn.run("command -v firewall-cmd && firewall-cmd --state", warn=True, hide=True).ok:
            return "firewalld"
            
        # Check UFW
        if conn.run("command -v ufw", warn=True, hide=True).ok:
             # ufw status might return 'inactive', but if binary exists we likely want to use it on Debian
             return "ufw"
             
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
        mode_desc = "Trusted IPs ONLY" if self.mode == MODE_STRICT else "Trusted IPs + Internet (root only)"
        commands.append(PythonAction(
            function=self._apply_firewall_rules,
            description=f"Apply firewall rules ({mode_desc})",
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
        """Install and enable firewall service if missing"""
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
            # to-do: test if this is enough to start firewall in all cases (i suspect not) use the detected server_info.init_system
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

    def _ensure_conntrack_installed(self, conn):
        """
        Attempt to install conntrack-tools to allow flushing state tables.
        Returns True if conntrack command is available, False otherwise.
        """
        if conn.run("command -v conntrack", warn=True, hide=True).ok:
            return True

        logger.info("Conntrack not found. Attempting to install...")
        pms = self.server_info.package_managers
        cmd = None

        if "dnf" in pms:
            cmd = "dnf install -y conntrack-tools"
        elif "yum" in pms:
            cmd = "yum install -y conntrack-tools"
        elif "apt" in pms:
            cmd = "DEBIAN_FRONTEND=noninteractive apt-get install -y conntrack"
        elif "zypper" in pms:
            cmd = "zypper --non-interactive install conntrack-tools"
        elif "apk" in pms:
            cmd = "apk add conntrack-tools"

        if cmd:
            try:
                conn.sudo(cmd, hide=True)
                if conn.run("command -v conntrack", warn=True, hide=True).ok:
                    return True
            except Exception as e:
                logger.warning(f"Failed to install conntrack: {e}")
        
        return False

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
            # Fix: set back to trusted so reload restores an open state (both persistent and runtime)
            revert_cmd = (
                "firewall-cmd --permanent --zone=trusted --remove-source=10.0.0.2 2>/dev/null; "
                "firewall-cmd --permanent --zone=trusted --remove-source=100.18.6.211 2>/dev/null; "
                "firewall-cmd --permanent --zone=trusted --remove-source=172.239.63.207 2>/dev/null; "
                "firewall-cmd --set-default-zone=trusted && firewall-cmd --reload"
            )
            # If using hybrid nftables mode, also cleanup the custom table
            if self.uses_hybrid_nftables:
                revert_cmd = f"nft delete table inet ccdc_internet 2>/dev/null; {revert_cmd}"
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
            elif self.active_backend == "ufw":
                return self._apply_ufw(conn)
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

    def _inject_nft_user_rules_for_firewalld(self, conn):
        """
        Inject native nftables rules alongside firewalld for user-filtered internet access.
        Creates a custom table with higher priority than firewalld to enable user filtering.

        This is necessary because firewalld's rich rules don't support user matching when
        using the nftables backend.
        """
        logger.info("Injecting native nftables rules for user filtering (firewalld+nftables)")

        # Clean up any existing rules from previous runs
        conn.sudo("nft delete table inet ccdc_internet 2>/dev/null || true", hide=True, warn=True)

        # Build ruleset as a list
        rules = [
            "add table inet ccdc_internet",
            # Priority -10 = runs before firewalld (priority 0)
            "add chain inet ccdc_internet output { type filter hook output priority -10 ; }",
            "add chain inet ccdc_internet input { type filter hook input priority -10 ; }",
        ]

        # Add rules for each allowed port (system users: UID 0-999)
        for port, protocols in INTERNET_PORTS.items():
            for proto in protocols:
                # Outbound: Allow system users (UID 0-999) to initiate
                rules.append(
                    f"add rule inet ccdc_internet output {proto} dport {port} "
                    f"meta skuid 0-{SYSTEM_UID_MAX} ct state new,established accept"
                )
                # Inbound: Allow established/related responses
                rules.append(
                    f"add rule inet ccdc_internet input {proto} sport {port} "
                    f"ct state established,related accept"
                )

        # Create ruleset content
        ruleset = "\n".join(rules)

        # Apply atomically via temp file
        try:
            # Write to temp file
            conn.run(f"cat > /tmp/ccdc_internet.nft << 'EOF'\n{ruleset}\nEOF", hide=True)

            # Apply the ruleset
            conn.sudo("nft -f /tmp/ccdc_internet.nft", hide=True, timeout=10)
            logger.info("Successfully injected nftables user filtering rules")

            # Set flag to track that we're using hybrid mode
            self.uses_hybrid_nftables = True

            # Attempt to persist: Add to nftables include directory if available
            # Check for common nftables config locations
            if conn.run("test -d /etc/nftables", warn=True, hide=True).ok:
                conn.sudo("cp /tmp/ccdc_internet.nft /etc/nftables/ccdc_internet.nft", hide=True, warn=True)
                # Try to add include to main config if not present
                for config_path in ["/etc/sysconfig/nftables.conf", "/etc/nftables.conf"]:
                    if conn.run(f"test -f {config_path}", warn=True, hide=True).ok:
                        conn.sudo(
                            f"grep -q 'ccdc_internet.nft' {config_path} || "
                            f"echo 'include \"/etc/nftables/ccdc_internet.nft\"' >> {config_path}",
                            warn=True, hide=True
                        )
                        logger.info(f"Added persistence to {config_path}")
                        break

        except Exception as e:
            logger.warning(f"Failed to inject nftables rules: {e}")
            raise

    def _apply_ufw(self, conn):
        try:
            # 0. Ensure conntrack
            has_conntrack = self._ensure_conntrack_installed(conn)

            # 1. Reset (flushes rules)
            conn.sudo("echo 'y' | ufw reset", hide=True, timeout=30)
            
            # 2. Defaults
            conn.sudo("ufw default deny incoming", hide=True)
            conn.sudo("ufw default deny outgoing", hide=True)

            # 3. Allow Loopback
            conn.sudo("ufw allow in on lo", hide=True)
            conn.sudo("ufw allow out on lo", hide=True)
            
            # 4. Trusted IPs
            for ip in TRUSTED_IPS:
                conn.sudo(f"ufw allow from {ip}", hide=True)
                conn.sudo(f"ufw allow out to {ip}", hide=True)
            
            # 5. Allow Internet Mode (system users only) - uses iptables directly
            # UFW doesn't support owner matching, so we inject iptables rules
            if self.mode == MODE_ALLOW_INTERNET:
                logger.info("Adding allow_internet rules (system users: UID 0-999) via iptables...")
                for port, protocols in INTERNET_PORTS.items():
                    for proto in protocols:
                        # Outbound: Allow system users (UID 0-999) to initiate connections
                        conn.sudo(
                            f"iptables -I ufw-before-output -p {proto} --dport {port} "
                            f"-m owner --uid-owner 0-{SYSTEM_UID_MAX} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
                            hide=True
                        )
                        # Inbound: Allow established/related responses
                        conn.sudo(
                            f"iptables -I ufw-before-input -p {proto} --sport {port} "
                            f"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                            hide=True
                        )
            
            # 6. Enable
            conn.sudo("echo 'y' | ufw enable", hide=True, timeout=30)
            
            # 7. Flush states
            if has_conntrack:
                try:
                    conn.sudo("conntrack -F", hide=True, timeout=5)
                except:
                    pass
                    
        except CommandTimedOut:
            logger.warning("UFW command timed out (likely session severed).")
            return HardeningResult(success=True, command="apply_ufw", description="Applied UFW rules", output="Command timed out (Session severed)")
        except Exception as e:
            return HardeningResult(success=False, command="apply_ufw", description="Applied UFW rules", error=str(e))
        
        mode_info = f" (mode: {self.mode})"    
        return HardeningResult(success=True, command="apply_ufw", description="Applied UFW rules", output=f"UFW rules applied{mode_info}")

    def _apply_firewalld(self, conn):
        # 1. Ensure Conntrack is present (for flushing state later)
        has_conntrack = self._ensure_conntrack_installed(conn)
        
        # Check if firewalld uses nftables backend (modern distros)
        # Direct rules (ipv4 filter) only work with iptables backend
        # Method 1: Try the CLI option (newer versions of firewalld)
        backend_result = conn.run("firewall-cmd --get-default-backend 2>/dev/null", warn=True, hide=True)
        uses_nftables = backend_result.ok and "nftables" in backend_result.stdout.lower()
        
        # Method 2: Check config file if CLI didn't return a backend
        if not uses_nftables and not backend_result.stdout.strip():
            config_result = conn.run("grep -i 'FirewallBackend.*nftables' /etc/firewalld/firewalld.conf 2>/dev/null", warn=True, hide=True)
            uses_nftables = config_result.ok and "nftables" in config_result.stdout.lower()
        
        logger.info(f"Firewalld backend detection: uses_nftables={uses_nftables}")
        
        try:
            # 2. Reload to clear old runtime junk
            conn.sudo("firewall-cmd --reload", hide=True, timeout=30)
            
            # 3. Configure Trusted Zone (BOTH permanent and runtime to survive reboots)
            # Add loopback interface to trusted zone
            conn.sudo("firewall-cmd --permanent --zone=trusted --add-interface=lo", warn=True, hide=True, timeout=30)
            conn.sudo("firewall-cmd --zone=trusted --add-interface=lo", warn=True, hide=True, timeout=30)
            
            # Add Trusted IPs to trusted zone (permanent + runtime)
            for ip in TRUSTED_IPS:
                conn.sudo(f"firewall-cmd --permanent --zone=trusted --add-source={ip}", hide=True, timeout=30)
                conn.sudo(f"firewall-cmd --zone=trusted --add-source={ip}", hide=True, timeout=30)

            # Ensure SSH is explicitly allowed in trusted zone (permanent + runtime)
            conn.sudo("firewall-cmd --permanent --zone=trusted --add-service=ssh", warn=True, hide=True, timeout=30)
            conn.sudo("firewall-cmd --zone=trusted --add-service=ssh", warn=True, hide=True, timeout=30)
            
            # 4. Set Default Zone to Drop
            conn.sudo("firewall-cmd --set-default-zone=drop", hide=True, timeout=10)
            
            # 5. Allow Internet Mode (system users only)
            if self.mode == MODE_ALLOW_INTERNET:
                if uses_nftables:
                    # Use native nftables for user filtering (firewalld rich rules don't support it)
                    logger.info("Using hybrid nftables injection for user filtering (firewalld+nftables)...")
                    self._inject_nft_user_rules_for_firewalld(conn)
                else:
                    # Use direct rules (iptables backend) with owner matching
                    logger.info("Adding allow_internet rules (system users: UID 0-999) via firewalld direct rules...")
                    for port, protocols in INTERNET_PORTS.items():
                        for proto in protocols:
                            # Outbound: Allow system users (UID 0-999) to initiate connections
                            conn.sudo(
                                f"firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 "
                                f"-p {proto} --dport {port} -m owner --uid-owner 0-{SYSTEM_UID_MAX} "
                                f"-m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
                                hide=True, timeout=30
                            )
                            # Inbound: Allow established/related responses
                            conn.sudo(
                                f"firewall-cmd --direct --add-rule ipv4 filter INPUT 1 "
                                f"-p {proto} --sport {port} "
                                f"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                                hide=True, timeout=30
                            )
            
            # 6. FLUSH EXISTING CONNECTIONS (Critical Fix)
            # firewalld preserves state by default. We must flush it to kill 'evil' connections.
            # This might sever our own connection, so we expect timeouts.
            logger.info("Applying Rules: Flushing existing connection states...")
            
            try:
                if has_conntrack:
                    # Preferred method: Flush conntrack table
                    logger.info("Executing: conntrack -F")
                    conn.sudo("conntrack -F", hide=True, timeout=5)
                else:
                    # Fallback method: Complete reload (Disruptive but effective)
                    logger.info("Conntrack missing. Fallback to: firewall-cmd --complete-reload")
                    conn.sudo("firewall-cmd --complete-reload", hide=True, timeout=10)
            
            except (CommandTimedOut, UnexpectedExit):
                # This is actually a GOOD sign - it means the flush likely worked and killed the ssh state.
                logger.info("Connection severed during state flush (Expected behavior).")

        except CommandTimedOut:
            logger.warning("Firewall command timed out (likely connection severed by rules). Assuming success.")
            return HardeningResult(success=True, command="apply_firewalld", description="Applied firewalld rules", output="Command timed out (Session severed)")
        except Exception as e:
            return HardeningResult(success=False, command="apply_firewalld", description="Applied firewalld rules", error=str(e))

        mode_info = f" (mode: {self.mode})"
        return HardeningResult(success=True, command="apply_firewalld", description="Applied firewalld rules", output=f"Zone rules applied & States Flushed{mode_info}")

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
        
        # Allow Internet Mode (system users only)
        if self.mode == MODE_ALLOW_INTERNET:
            logger.info("Adding allow_internet rules (system users: UID 0-999) to iptables...")
            for port, protocols in INTERNET_PORTS.items():
                for proto in protocols:
                    # Outbound: Allow system users (UID 0-999) to initiate connections
                    cmds.append(
                        f"iptables -A OUTPUT -p {proto} --dport {port} "
                        f"-m owner --uid-owner 0-{SYSTEM_UID_MAX} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
                    )
                    # Inbound: Allow established/related responses
                    cmds.append(
                        f"iptables -A INPUT -p {proto} --sport {port} "
                        f"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
                    )
            
        cmds.append("iptables -P INPUT DROP")
        cmds.append("iptables -P FORWARD DROP")
        cmds.append("iptables -P OUTPUT DROP")
        
        full_cmd = " && ".join(cmds)
        try:
            conn.sudo(full_cmd, hide=True, timeout=10)
            
            # Persistence Logic for iptables
            # Debian/Ubuntu: /etc/iptables/rules.v4
            # RHEL/CentOS: /etc/sysconfig/iptables
            if conn.run("test -d /etc/iptables", warn=True, hide=True).ok:
                conn.sudo("iptables-save > /etc/iptables/rules.v4", hide=True)
                logger.info("Saved iptables rules to /etc/iptables/rules.v4")
            elif conn.run("test -d /etc/sysconfig", warn=True, hide=True).ok:
                conn.sudo("iptables-save > /etc/sysconfig/iptables", hide=True)
                logger.info("Saved iptables rules to /etc/sysconfig/iptables")
                
        except CommandTimedOut:
             logger.warning("IPTables command timed out (likely connection severed).")
             return HardeningResult(success=True, command="apply_iptables", description="Applied iptables rules", output="Command timed out (Session severed)")
        
        mode_info = f" (mode: {self.mode})"
        return HardeningResult(success=True, command="apply_iptables", description="Applied iptables rules", output=f"Rules applied and saved{mode_info}")

    def _apply_nft(self, conn):
        # Build nftables config file content
        nft_conf = "/tmp/nftables.conf.go_dark"
        
        config_lines = [
            "flush ruleset",
            "add table inet filter",
            "add chain inet filter input { type filter hook input priority 0 ; policy drop ; }",
            "add chain inet filter forward { type filter hook forward priority 0 ; policy drop ; }",
            "add chain inet filter output { type filter hook output priority 0 ; policy drop ; }",
            "add rule inet filter input iif lo accept",
            "add rule inet filter output oif lo accept"
        ]
        
        for ip in TRUSTED_IPS:
            config_lines.append(f"add rule inet filter input ip saddr {ip} accept")
            config_lines.append(f"add rule inet filter output ip daddr {ip} accept")
        
        # Allow Internet Mode (system users only) - uses meta skuid for user matching
        if self.mode == MODE_ALLOW_INTERNET:
            logger.info("Adding allow_internet rules (system users: UID 0-999) to nftables config...")
            for port, protocols in INTERNET_PORTS.items():
                for proto in protocols:
                    # Outbound: Allow system users (UID 0-999) to initiate connections
                    config_lines.append(
                        f"add rule inet filter output {proto} dport {port} "
                        f"meta skuid 0-{SYSTEM_UID_MAX} ct state new,established accept"
                    )
                    # Inbound: Allow established/related responses
                    config_lines.append(
                        f"add rule inet filter input {proto} sport {port} "
                        f"ct state established,related accept"
                    )
            
        full_config = "\\n".join(config_lines)
        
        try:
            # Determine persistent config path based on loaded package manager/OS family
            # Alpine uses /etc/nftables.nft, Debian/RedHat use /etc/nftables.conf
            persistent_conf = "/etc/nftables.conf"
            if "alpine" in self.server_info.os.distro.lower():
                persistent_conf = "/etc/nftables.nft"
            
            # Write config to temp file first
            conn.sudo(f"printf '{full_config}' > {nft_conf}", hide=True)
            
            # Write to persistent location
            conn.sudo(f"printf '{full_config}' > {persistent_conf}", hide=True)
            logger.info(f"Saved nftables rules to {persistent_conf}")
            
            # Apply config
            conn.sudo(f"nft -f {nft_conf}", hide=True, timeout=10)
            
        except CommandTimedOut:
            logger.warning("NFTables command timed out (likely connection severed).")
            return HardeningResult(success=True, command="apply_nft", description="Applied nftables rules", output="Command timed out (Session severed)")
        except Exception as e:
            return HardeningResult(success=False, command="apply_nft", description="Applied nftables rules", error=str(e))
        
        mode_info = f" (mode: {self.mode})"    
        return HardeningResult(success=True, command="apply_nft", description="Applied nftables rules", output=f"Rules applied via config file{mode_info}")

    def _apply_pf(self, conn):
        pf_conf = "/tmp/pf.conf.go_dark"
        trusted_str = " ".join(TRUSTED_IPS)
        # Detect loopback interface name
        lo_if = "lo0"
        if conn.run("ifconfig lo0", warn=True, hide=True).failed:
            lo_if = "lo"
        
        # Build base config
        conf_lines = [
            f"table <trusted_ssh> {{ {trusted_str} }}",
            "set block-policy drop",
            f"set skip on {lo_if}",
            "block in all",
            "block out all",
            "pass in from <trusted_ssh> to any no state",
            "pass out from any to <trusted_ssh> no state"
        ]
        
        # Allow Internet Mode
        # NOTE: pf doesn't have native user-level filtering like iptables' owner match
        # Internet access will be allowed for all users when in this mode
        if self.mode == MODE_ALLOW_INTERNET:
            logger.info("Adding allow_internet rules to pf config (user filtering not available on BSD)...")
            # DNS (UDP/TCP)
            conf_lines.append("pass out proto { udp tcp } to any port 53 keep state")
            # HTTP/HTTPS
            conf_lines.append("pass out proto tcp to any port { 80 443 } keep state")
            # NTP
            conf_lines.append("pass out proto udp to any port 123 keep state")
            # SMTP
            conf_lines.append("pass out proto tcp to any port 25 keep state")
            
        conf_content = "\n".join(conf_lines)
        
        try:
            # Write config
            conn.sudo(f"printf '%s' '{conf_content}' > {pf_conf}", hide=True)
            # Write to persistent config (Standard BSD location)
            conn.sudo(f"printf '%s' '{conf_content}' > /etc/pf.conf", hide=True)
            logger.info("Saved PF rules to /etc/pf.conf")
            
            # Apply
            conn.sudo(f"pfctl -f {pf_conf}", hide=True, timeout=10)
            conn.sudo("pfctl -e", warn=True, hide=True, timeout=10)
            conn.sudo("pfctl -F state", warn=True, hide=True, timeout=10) # Flush states
        except CommandTimedOut:
            logger.warning("PF command timed out (likely connection severed).")
            return HardeningResult(success=True, command="apply_pf", description="Applied PF rules", output="Command timed out (Session severed)")
        except Exception as e:
            return HardeningResult(success=False, command="apply_pf", description="Applied PF rules", error=str(e))

        mode_info = f" (mode: {self.mode})"
        return HardeningResult(success=True, command="apply_pf", description="Applied PF rules", output=f"PF rules loaded and saved{mode_info}")

    def _apply_ipfw(self, conn):
        try:
            conn.sudo("ipfw -q flush", hide=True, timeout=10)
            conn.sudo("ipfw add 10 check-state", hide=True, timeout=10)  # Enable stateful tracking
            conn.sudo("ipfw add 50 allow ip from any to any via lo0", hide=True, timeout=10)
            
            rule_id = 100
            for ip in TRUSTED_IPS:
                conn.sudo(f"ipfw add {rule_id} allow ip from {ip} to me in", hide=True, timeout=10)
                conn.sudo(f"ipfw add {rule_id+1} allow ip from me to {ip} out", hide=True, timeout=10)
                rule_id += 10
            
            # Allow Internet Mode (system users only) - uses uid matching
            if self.mode == MODE_ALLOW_INTERNET:
                logger.info("Adding allow_internet rules (system users: UID 0-999) to ipfw...")
                base_rule = 200
                for port, protocols in INTERNET_PORTS.items():
                    for proto in protocols:
                        # Outbound: Allow system users (UID 0-999) to initiate connections with state tracking
                        conn.sudo(
                            f"ipfw add {base_rule} allow {proto} from me to any {port} out uid 0:{SYSTEM_UID_MAX} keep-state",
                            hide=True, timeout=10
                        )
                        base_rule += 10
                
            # Deny rest
            conn.sudo("ipfw add 65000 deny ip from any to any", hide=True, timeout=10)
        except CommandTimedOut:
            logger.warning("IPFW command timed out (likely connection severed).")
            return HardeningResult(success=True, command="apply_ipfw", description="Applied IPFW rules", output="Command timed out (Session severed)")
        except Exception as e:
            return HardeningResult(success=False, command="apply_ipfw", description="Applied IPFW rules", error=str(e))

        mode_info = f" (mode: {self.mode})"
        return HardeningResult(success=True, command="apply_ipfw", description="Applied IPFW rules", output=f"IPFW rules applied{mode_info}")

    def _test_connectivity(self, conn, server_info):
        """Verify we are not locked out; disarm DMS on success. Retries with key-only auth for root."""
        host = server_info.credentials.host
        user = server_info.credentials.user
        password = getattr(server_info.credentials, 'password', None)
        port = getattr(server_info.credentials, 'port', 22)
        key_file = getattr(server_info.credentials, 'key_file', None)
        
        # Prepare connectivity test with KEY-ONLY auth for root (password auth may be disabled)
        connect_kwargs = {'allow_agent': False, 'look_for_keys': False, 'timeout': 15}
        
        # For root user, prioritize the designated root key
        if user == 'root' and os.path.exists(ROOT_KEY_PATH):
            logger.info(f"Using root recovery key for connectivity test: {ROOT_KEY_PATH}")
            key_list = [ROOT_KEY_PATH]
            if key_file:
                if isinstance(key_file, list):
                    key_list.extend(key_file)
                else:
                    key_list.append(key_file)
            connect_kwargs['key_filename'] = key_list
            # Don't use password for root - key auth only after hardening
        else:
            if key_file:
                connect_kwargs['key_filename'] = key_file
            if password:
                connect_kwargs['password'] = password
        
        config = Config(overrides={'sudo': {'password': password}, 'load_ssh_configs': False})
        
        # Retry with increasing delays (network stack needs to settle after rule changes)
        max_retries = 3
        delays = [3, 5, 8]  # Seconds to wait before each attempt
        last_error = None
        
        for attempt in range(max_retries):
            delay = delays[attempt] if attempt < len(delays) else 5
            logger.info(f"Verifying connectivity to {host} (attempt {attempt + 1}/{max_retries}, waiting {delay}s)...")
            time.sleep(delay)
            
            try:
                with Connection(host, user=user, port=port, config=config, connect_kwargs=connect_kwargs) as test_conn:
                    test_conn.run("echo 'Connectivity Check OK'", hide=True, timeout=10)
                
                # If success, kill DMS
                if self.dead_mans_switch_pid:
                    conn.sudo(f"kill {self.dead_mans_switch_pid} || true", hide=True, warn=True)
                    logger.info(f"DMS Disarmed (PID {self.dead_mans_switch_pid})")
                    return HardeningResult(success=True, command="verify_connectivity", description="Connectivity Verified", output=f"DMS Disarmed (attempt {attempt + 1})")
                
                return HardeningResult(success=True, command="verify_connectivity", description="Connectivity Verified", output=f"Success (attempt {attempt + 1})")
                    
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Connectivity check attempt {attempt + 1} failed: {e}")
        
        # All retries exhausted
        logger.error(f"Connectivity check failed after {max_retries} attempts: {last_error}")
        return HardeningResult(
            success=False, 
            command="verify_connectivity", 
            description="Connectivity Check", 
            error="Failed to connect. DMS should revert changes in ~60s.",
            output=f"Failed after {max_retries} attempts: {last_error}"
        )