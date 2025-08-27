"""
Agent account management module for CCDC framework
Creates and manages the scan-agent account for security operations
Supports Linux, BSD, and Unix systems
"""
# TODO: make a restricted user, create a new user called restricteddawg assign rbash as their shell

from typing import List
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily

# Global variable for the scan-agent password
SCAN_AGENT_PASSWORD = "Agentbigdawg13377331"


class AgentAccountModule(HardeningModule):
    """Create and manage the scan-agent account with sudo permissions"""
    
    def get_name(self) -> str:
        return "agent_account"
    
    def get_commands(self) -> List[HardeningCommand]:
        try:
            os_family = OSFamily(self.os_family)
        except ValueError:
            os_family = OSFamily.UNKNOWN
        
        if os_family in [OSFamily.FREEBSD, OSFamily.OPENBSD, OSFamily.NETBSD, OSFamily.BSDGENERIC]:
            return self._get_bsd_commands()
        elif os_family == OSFamily.DARWIN:
            return self._get_macos_commands()
        else:
            return self._get_linux_commands()
    
    def _get_linux_commands(self) -> List[HardeningCommand]:
        """Commands for Linux systems"""
        commands = []
        
        # Create the scan-agent user
        commands.append(HardeningCommand(
            command="useradd -m -s /bin/bash scan-agent",
            description="Create scan-agent user account",
            check_command="id scan-agent >/dev/null 2>&1 && echo exists",
            requires_sudo=True
        ))
        
        # Set password for scan-agent (try multiple methods)
        commands.append(HardeningCommand(
            command=f"usermod --password $(openssl passwd -6 '{SCAN_AGENT_PASSWORD}') scan-agent || echo 'scan-agent:{SCAN_AGENT_PASSWORD}' | chpasswd",
            description="Set password for scan-agent",
            requires_sudo=True
        ))
        
        # Add scan-agent to sudo group (try both sudo and wheel)
        commands.append(HardeningCommand(
            command="usermod -aG sudo scan-agent 2>/dev/null || usermod -aG wheel scan-agent",
            description="Add scan-agent to sudo/wheel group",
            check_command="groups scan-agent | grep -E '(sudo|wheel)' >/dev/null && echo in_sudo",
            requires_sudo=True
        ))
        
        # Create sudoers entry for scan-agent (try multiple methods)
        commands.append(HardeningCommand(
            command="mkdir -p /etc/sudoers.d && (echo 'scan-agent ALL=(ALL:ALL) ALL' | tee /etc/sudoers.d/scan-agent > /dev/null || echo 'scan-agent ALL=(ALL:ALL) ALL' >> /etc/sudoers)",
            description="Grant sudo privileges to scan-agent",
            check_command="test -f /etc/sudoers.d/scan-agent && echo exists || grep -q 'scan-agent.*ALL' /etc/sudoers && echo exists_in_main",
            requires_sudo=True
        ))
        
        # Set proper permissions on sudoers file (if it exists)
        commands.append(HardeningCommand(
            command="test -f /etc/sudoers.d/scan-agent && chmod 440 /etc/sudoers.d/scan-agent || true",
            description="Set correct permissions on scan-agent sudoers file",
            requires_sudo=True
        ))
        
        # Verify sudoers syntax
        commands.append(HardeningCommand(
            command="visudo -c -f /etc/sudoers.d/scan-agent 2>/dev/null || echo 'visudo check skipped'",
            description="Verify scan-agent sudoers syntax",
            requires_sudo=True
        ))
        
        # Create home directory structure
        commands.append(HardeningCommand(
            command="mkdir -p /home/scan-agent/.ssh && chown scan-agent:scan-agent /home/scan-agent/.ssh && chmod 700 /home/scan-agent/.ssh",
            description="Create SSH directory for scan-agent",
            check_command="test -d /home/scan-agent/.ssh && echo exists",
            requires_sudo=True
        ))
        
        # Set up basic shell configuration
        commands.append(HardeningCommand(
            command="test -f /etc/skel/.bashrc && cp /etc/skel/.bashrc /home/scan-agent/.bashrc && chown scan-agent:scan-agent /home/scan-agent/.bashrc || echo 'bashrc setup skipped'",
            description="Set up bashrc for scan-agent",
            requires_sudo=True
        ))
        
        # Add scan-agent to useful groups for security operations (best effort)
        commands.append(HardeningCommand(
            command='bash -c "for group in adm systemd-journal; do getent group \\$group >/dev/null && usermod -aG \\$group scan-agent; done || true"',
            description="Add scan-agent to system monitoring groups",
            requires_sudo=True
        ))
        
        return commands
    
    def _get_bsd_commands(self) -> List[HardeningCommand]:
        """Commands for BSD systems (FreeBSD, OpenBSD, NetBSD)"""
        commands = []
        
        # Create the scan-agent user (BSD style)
        commands.append(HardeningCommand(
            command="pw useradd scan-agent -m -s /bin/sh -c 'CCDC Scan Agent' 2>/dev/null || adduser -batch scan-agent '' '' '' 'CCDC Scan Agent' '' '' || useradd -m -s /bin/sh scan-agent",
            description="Create scan-agent user account (BSD)",
            check_command="id scan-agent >/dev/null 2>&1 && echo exists",
            requires_sudo=True
        ))
        
        # Set password for scan-agent (BSD style)
        commands.append(HardeningCommand(
            command=f"echo '{SCAN_AGENT_PASSWORD}' | pw usermod scan-agent -h 0 2>/dev/null || echo 'scan-agent:{SCAN_AGENT_PASSWORD}' | chpasswd",
            description="Set password for scan-agent (BSD)",
            requires_sudo=True
        ))
        
        # Add scan-agent to wheel group (BSD sudo group)
        commands.append(HardeningCommand(
            command="pw groupmod wheel -m scan-agent 2>/dev/null || usermod -G wheel scan-agent",
            description="Add scan-agent to wheel group (BSD)",
            check_command="groups scan-agent | grep -q wheel && echo in_wheel",
            requires_sudo=True
        ))
        
        # Enable wheel group in sudoers (uncomment wheel line)
        commands.append(HardeningCommand(
            command="sed -i.bak 's/^# %wheel ALL=(ALL) ALL/%wheel ALL=(ALL) ALL/' /usr/local/etc/sudoers 2>/dev/null || sed -i.bak 's/^# %wheel ALL=(ALL) ALL/%wheel ALL=(ALL) ALL/' /etc/sudoers",
            description="Enable wheel group in sudoers (BSD)",
            requires_sudo=True
        ))
        
        # Alternative: Direct sudoers entry
        commands.append(HardeningCommand(
            command="echo 'scan-agent ALL=(ALL) ALL' >> /usr/local/etc/sudoers 2>/dev/null || echo 'scan-agent ALL=(ALL) ALL' >> /etc/sudoers",
            description="Grant direct sudo privileges to scan-agent (BSD)",
            requires_sudo=True
        ))
        
        # Create home directory structure
        commands.append(HardeningCommand(
            command="mkdir -p /home/scan-agent/.ssh && chown scan-agent:scan-agent /home/scan-agent/.ssh && chmod 700 /home/scan-agent/.ssh",
            description="Create SSH directory for scan-agent (BSD)",
            check_command="test -d /home/scan-agent/.ssh && echo exists",
            requires_sudo=True
        ))
        
        # Set up shell configuration for BSD
        commands.append(HardeningCommand(
            command="test -f /usr/share/skel/dot.profile && cp /usr/share/skel/dot.profile /home/scan-agent/.profile && chown scan-agent:scan-agent /home/scan-agent/.profile || echo 'profile setup skipped'",
            description="Set up shell profile for scan-agent (BSD)",
            requires_sudo=True
        ))
        
        # Add to operator group for system access (BSD)
        commands.append(HardeningCommand(
            command="pw groupmod operator -m scan-agent 2>/dev/null || true",
            description="Add scan-agent to operator group (BSD)",
            requires_sudo=True
        ))
        
        return commands
    
    def _get_macos_commands(self) -> List[HardeningCommand]:
        """Commands for macOS systems"""
        commands = []
        
        # Create the scan-agent user (macOS style)
        commands.append(HardeningCommand(
            command="dscl . -create /Users/scan-agent && dscl . -create /Users/scan-agent UserShell /bin/bash && dscl . -create /Users/scan-agent RealName 'CCDC Scan Agent' && dscl . -create /Users/scan-agent UniqueID 1001 && dscl . -create /Users/scan-agent PrimaryGroupID 20 && dscl . -create /Users/scan-agent NFSHomeDirectory /Users/scan-agent",
            description="Create scan-agent user account (macOS)",
            check_command="dscl . -read /Users/scan-agent >/dev/null 2>&1 && echo exists",
            requires_sudo=True
        ))
        
        # Set password for scan-agent (macOS)
        commands.append(HardeningCommand(
            command=f"dscl . -passwd /Users/scan-agent '{SCAN_AGENT_PASSWORD}'",
            description="Set password for scan-agent (macOS)",
            requires_sudo=True
        ))
        
        # Add scan-agent to admin group (macOS sudo equivalent)
        commands.append(HardeningCommand(
            command="dseditgroup -o edit -a scan-agent -t user admin",
            description="Add scan-agent to admin group (macOS)",
            check_command="dseditgroup -o checkmember -m scan-agent admin >/dev/null 2>&1 && echo in_admin",
            requires_sudo=True
        ))
        
        # Create home directory
        commands.append(HardeningCommand(
            command="mkdir -p /Users/scan-agent && chown scan-agent:staff /Users/scan-agent",
            description="Create home directory for scan-agent (macOS)",
            check_command="test -d /Users/scan-agent && echo exists",
            requires_sudo=True
        ))
        
        # Create SSH directory structure
        commands.append(HardeningCommand(
            command="mkdir -p /Users/scan-agent/.ssh && chown scan-agent:staff /Users/scan-agent/.ssh && chmod 700 /Users/scan-agent/.ssh",
            description="Create SSH directory for scan-agent (macOS)",
            check_command="test -d /Users/scan-agent/.ssh && echo exists",
            requires_sudo=True
        ))
        
        # Set up basic shell configuration
        commands.append(HardeningCommand(
            command="cp /etc/skel/.bashrc /Users/scan-agent/.bashrc 2>/dev/null && chown scan-agent:staff /Users/scan-agent/.bashrc || echo 'bashrc setup skipped'",
            description="Set up bashrc for scan-agent (macOS)",
            requires_sudo=True
        ))
        
        return commands
    
    def is_applicable(self) -> bool:
        """This module is applicable to Linux, BSD, and macOS systems"""
        return self.server_info.os.distro.lower() != "unknown"