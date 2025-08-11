"""
Firewall hardening module for CCDC framework
"""

from typing import List
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily


class FirewallHardeningModule(HardeningModule):
    """Firewall configuration module"""
    
    def get_name(self) -> str:
        return "firewall_hardening"
    
    def is_applicable(self) -> bool:
        """Check if we can configure a firewall on this system"""
        return self.server_info.os.distro.lower() != "unknown"
    
    def get_commands(self) -> List[HardeningCommand]:
        """Get firewall commands based on available firewall"""
        firewall_status = getattr(self.server_info, 'firewall_status', 'unknown')
        
        if "ufw" in firewall_status:
            return self._get_ufw_commands()
        elif "firewalld" in firewall_status:
            return self._get_firewalld_commands()
        elif "iptables" in firewall_status:
            return self._get_iptables_commands()
        else:
            # Try to install and configure UFW on Debian/Ubuntu
            try:
                if OSFamily(self.os_family) == OSFamily.DEBIAN:
                    return self._get_ufw_install_commands()
            except ValueError:
                pass
            return []
    
    def _get_ufw_commands(self) -> List[HardeningCommand]:
        """UFW firewall commands"""
        return [
            HardeningCommand(
                command="ufw --force reset",
                description="Reset UFW to defaults",
                requires_sudo=True
            ),
            HardeningCommand(
                command="ufw default deny incoming",
                description="Set default incoming policy to deny",
                requires_sudo=True
            ),
            HardeningCommand(
                command="ufw default allow outgoing",
                description="Set default outgoing policy to allow",
                requires_sudo=True
            ),
            HardeningCommand(
                command="ufw allow 22/tcp comment 'SSH'",
                description="Allow SSH access",
                requires_sudo=True
            ),
            HardeningCommand(
                command="echo 'y' | ufw enable",
                description="Enable UFW firewall",
                check_command="ufw status | grep -q 'Status: active' && echo active",
                requires_sudo=True
            ),
        ]
    
    def _get_firewalld_commands(self) -> List[HardeningCommand]:
        """Firewalld commands"""
        return [
            HardeningCommand(
                command="firewall-cmd --set-default-zone=drop",
                description="Set default zone to drop",
                requires_sudo=True
            ),
            HardeningCommand(
                command="firewall-cmd --permanent --add-service=ssh",
                description="Allow SSH service",
                requires_sudo=True
            ),
            HardeningCommand(
                command="firewall-cmd --permanent --remove-service=dhcpv6-client",
                description="Remove DHCPv6 client service",
                requires_sudo=True
            ),
            HardeningCommand(
                command="firewall-cmd --reload",
                description="Reload firewall configuration",
                requires_sudo=True
            ),
        ]
    
    def _get_iptables_commands(self) -> List[HardeningCommand]:
        """Basic iptables commands"""
        return [
            HardeningCommand(
                command="iptables -P INPUT DROP",
                description="Set default INPUT policy to DROP",
                requires_sudo=True
            ),
            HardeningCommand(
                command="iptables -P FORWARD DROP",
                description="Set default FORWARD policy to DROP",
                requires_sudo=True
            ),
            HardeningCommand(
                command="iptables -P OUTPUT ACCEPT",
                description="Set default OUTPUT policy to ACCEPT",
                requires_sudo=True
            ),
            HardeningCommand(
                command="iptables -A INPUT -i lo -j ACCEPT",
                description="Allow loopback traffic",
                requires_sudo=True
            ),
            HardeningCommand(
                command="iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                description="Allow established connections",
                requires_sudo=True
            ),
            HardeningCommand(
                command="iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
                description="Allow SSH",
                requires_sudo=True
            ),
        ]
    
    def _get_ufw_install_commands(self) -> List[HardeningCommand]:
        """Commands to install and configure UFW"""
        commands = [
            HardeningCommand(
                command="apt-get update && apt-get install -y ufw",
                description="Install UFW firewall",
                check_command="which ufw && echo installed",
                requires_sudo=True,
                os_families=[OSFamily.DEBIAN]
            )
        ]
        commands.extend(self._get_ufw_commands())
        return commands