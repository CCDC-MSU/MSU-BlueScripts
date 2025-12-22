"""
System discovery utilities for CCDC hardening framework
Contains classes and functions for discovering system information
"""

import re
import logging
from fabric import Connection
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
from invoke.exceptions import UnexpectedExit
from .models import ServerCredentials, ServerInfo, OSInfo, UserInfo, NetworkInfo

logger = logging.getLogger(__name__)


class OSFamily(Enum):
    """Operating system families"""
    DEBIAN = "debian"
    REDHAT = "redhat" 
    SUSE = "suse"
    ARCH = "arch"
    ALPINE = "alpine"
    FREEBSD = "freebsd"
    OPENBSD = "openbsd"
    NETBSD = "netbsd"
    DARWIN = "darwin"
    UNKNOWN = "unknown"
    BSDGENERIC = "bsd_generic"

@dataclass
class CommandResult:
    """Result of a command execution"""
    success: bool
    output: str
    error: Optional[str] = None
    command: Optional[str] = None


class SystemDiscovery:
    """Discovers comprehensive system information from a remote server"""
    
    def __init__(self, connection: Connection, credentials: ServerCredentials):
        self.conn = connection
        self.credentials = credentials
        self.server_info = ServerInfo(hostname=credentials.host, credentials=credentials)
        self._os_family = OSFamily.UNKNOWN.value
        
    def discover_system(self) -> ServerInfo:
        """Main discovery method - runs all discovery tasks"""
        logger.info(f"Starting system discovery for {self.credentials.host}")
        
        discovery_tasks = [
            ("basic system info", self._discover_basic_info),
            ("operating system", self._discover_os_info),
            ("users", self._discover_users),
            ("services", self._discover_services),
            ("network configuration", self._discover_network),
            ("security tools", self._discover_security_tools),
            ("system resources", self._discover_system_resources),
            ("package managers", self._discover_package_managers),
        ]
        
        errors = []
        for task_name, task_func in discovery_tasks:
            try:
                task_func()
                logger.debug("Finished task: %-20s. %s", task_name, self._format_task_result(task_name))
            except Exception as e:
                error_msg = f"Failed to discover {task_name}: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        self.server_info.discovery_errors = errors
        self.server_info.discovery_successful = len(errors) == 0
        
        logger.info(f"Discovery completed for {self.credentials.host}. Success: {self.server_info.discovery_successful}")
        return self.server_info

    def _format_task_result(self, task_name: str) -> str:
        """Return a short, summary of what a discovery task found (for debug logs)."""
        try:
            if task_name == "basic system info":
                return (
                    f"hostname={self.server_info.hostname!r}, "
                    f"uptime_set={bool(self.server_info.uptime)}, "
                    f"default_shell={self.server_info.default_shell!r}"
                )

            if task_name == "operating system":
                os_info = getattr(self.server_info, "os", None)
                if os_info:
                    return (
                        f"distro={getattr(os_info, 'distro', None)!r}, "
                        f"version={getattr(os_info, 'version', None)!r}, "
                        f"kernel={getattr(os_info, 'kernel', None)!r}, "
                        f"arch={getattr(os_info, 'architecture', None)!r}, "
                        f"family={self._os_family!r}"
                    )
                return f"os_info=None, family={self._os_family!r}"

            if task_name == "users":
                users = getattr(self.server_info, "users", []) or []
                sample = [getattr(u, "username", None) for u in users[:10] if getattr(u, "username", None)]
                return f"count={len(users)}, sample={sample}"

            if task_name == "services":
                services = getattr(self.server_info, "services", []) or []
                return f"running_count={len(services)}, sample={services[:10]}"

            if task_name == "network configuration":
                net = getattr(self.server_info, "network", None)
                if not net:
                    return "network=None"
                interfaces = getattr(net, "interfaces", None) or ""
                listening = getattr(net, "listening_ports", None) or ""
                iface_lines = len(interfaces.splitlines()) if interfaces else 0
                listen_lines = len(listening.splitlines()) if listening else 0
                return (
                    f"interfaces_lines={iface_lines}, "
                    f"listening_lines={listen_lines}, "
                    f"default_route={getattr(net, 'default_route', None)!r}"
                )

            if task_name == "security tools":
                tools = getattr(self.server_info, "security_tools", {}) or {}
                enabled = sorted([k for k, v in tools.items() if v])
                return f"installed={enabled}"

            if task_name == "system resources":
                return (
                    f"cpu_cores={getattr(self.server_info, 'cpu_cores', None)!r}, "
                    f"memory_info_set={bool(getattr(self.server_info, 'memory_info', None))}, "
                    f"disk_info_set={bool(getattr(self.server_info, 'disk_info', None))}"
                )

            if task_name == "package managers":
                pms = getattr(self.server_info, "package_managers", []) or []
                return f"available={pms}"

            return "ok"
        except Exception as e:
            return f"summary_error={e!r}"

    def _run_command(self, command: str, warn: bool = True, timeout: int = 30) -> CommandResult:
        """
        Run a command and return the result
        
        Args:
            command: Command to run
            warn: Only warn on failure (don't raise exception)
            timeout: Command timeout in seconds
            
        Returns:
            CommandResult object
        """
        try:
            result = self.conn.run(command, hide=True, warn=warn, timeout=timeout)
            return CommandResult(
                success=result.ok,
                output=result.stdout.strip(),
                error=result.stderr.strip() if result.stderr else None,
                command=command
            )
        except UnexpectedExit as e:
            return CommandResult(
                success=False,
                output="",
                error=str(e),
                command=command
            )
        except Exception as e:
            return CommandResult(
                success=False,
                output="",
                error=f"Unexpected error: {str(e)}",
                command=command
            )
    
    def _try_command_chain(self, commands: List[str], 
                          processor: Optional[Callable] = None) -> Optional[str]:
        """
        Try a chain of commands until one succeeds
        
        Args:
            commands: List of commands to try
            processor: Optional function to process the output
            
        Returns:
            Processed output or None if all fail
        """
        for cmd in commands:
            result = self._run_command(cmd)
            if result.success and result.output:
                if processor:
                    return processor(result.output)
                return result.output
        return None
    
    def _discover_basic_info(self):
        """Discover basic system information"""
        # Hostname
        result = self._run_command('hostname')
        if result.success:
            self.server_info.hostname = result.output
        
        # Uptime
        result = self._run_command('uptime')
        if result.success:
            self.server_info.uptime = result.output
            
        # Default shell detection
        self._discover_shell()
    
    def _discover_shell(self):
        """Discover the default shell for system operations"""
        # Try multiple methods to determine the best shell to use
        shell_detection_commands = [
            # Check current shell
            ('echo $SHELL', lambda x: x),
            # Check if bash is available
            ('which bash', lambda x: '/bin/bash' if x else None),
            # Check if sh is available (fallback)
            ('which sh', lambda x: '/bin/sh' if x else None),
            # Last resort - assume sh
            ('echo /bin/sh', lambda x: '/bin/sh')
        ]
        
        for cmd, processor in shell_detection_commands:
            result = self._run_command(cmd)
            if result.success and result.output:
                shell_path = processor(result.output)
                if shell_path and ('bash' in shell_path or 'sh' in shell_path):
                    self.server_info.default_shell = shell_path
                    break
    
    def _discover_os_info(self):
        """Discover operating system information"""
        os_info = OSInfo()
        
        # Try /etc/os-release first (most modern systems)
        result = self._run_command('cat /etc/os-release 2>/dev/null')
        if result.success and result.output:
            os_release = {}
            for line in result.output.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    os_release[key] = value.strip('"')
            
            os_info.distro = os_release.get('NAME', 'unknown')
            os_info.version = os_release.get('VERSION', os_release.get('VERSION_ID', 'unknown'))
            
            # Store OS family information for later use
            os_id = os_release.get('ID', '').lower()
            if os_id in ['ubuntu', 'debian', 'linuxmint', 'pop', 'elementary']:
                self._os_family = OSFamily.DEBIAN.value
            elif os_id in ['fedora', 'centos', 'rhel', 'rocky', 'alma', 'oracle', 'amzn']:
                self._os_family = OSFamily.REDHAT.value
            elif os_id in ['opensuse', 'sles']:
                self._os_family = OSFamily.SUSE.value
            elif os_id in ['arch', 'manjaro', 'endeavouros']:
                self._os_family = OSFamily.ARCH.value
            elif os_id == 'alpine':
                self._os_family = OSFamily.ALPINE.value
            else:
                self._os_family = OSFamily.UNKNOWN.value
        else:
            # Fallback methods
            self._detect_os_fallback(os_info)
            
        # Kernel information
        result = self._run_command('uname -r')
        if result.success:
            os_info.kernel = result.output
            
        # Architecture
        result = self._run_command('uname -m')
        if result.success:
            os_info.architecture = result.output
            
        self.server_info.os = os_info
    
    def _detect_os_fallback(self, os_info: OSInfo):
        """Fallback OS detection methods"""
        # Check for specific release files
        distro_files = {
            '/etc/redhat-release': (OSFamily.REDHAT, 'RedHat'),
            '/etc/debian_version': (OSFamily.DEBIAN, 'Debian'),
            '/etc/alpine-release': (OSFamily.ALPINE, 'Alpine'),
            '/etc/arch-release': (OSFamily.ARCH, 'Arch'),
            '/etc/SuSE-release': (OSFamily.SUSE, 'SUSE'),
        }
        
        for file_path, (family, name) in distro_files.items():
            result = self._run_command(f'test -f {file_path} && echo "exists"')
            if result.success and result.output == "exists":
                self._os_family = family.value
                os_info.distro = name
                
                # Try to get version
                version_result = self._run_command(f'cat {file_path} 2>/dev/null | head -1')
                if version_result.success:
                    os_info.version = version_result.output
                break
        else:
            # Final fallback
            result = self._run_command('uname -s')
            if result.success:
                uname = result.output.lower()
                if 'linux' in uname:
                    os_info.distro = "Linux"
                    self._os_family = OSFamily.UNKNOWN.value
                elif 'darwin' in uname:
                    os_info.distro = "macOS"
                    self._os_family = OSFamily.DARWIN.value
                elif 'bsd' in uname:
                    os_info.distro = "BSD"
                    self._os_family = OSFamily.FREEBSD.value
    
    def _discover_users(self):
        """Discover system users"""
        result = self._run_command('cat /etc/passwd')
        if not result.success:
            return
            
        users = []
        for line in result.output.split('\n'):
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 6:
                    try:
                        user = UserInfo(
                            username=parts[0],
                            uid=int(parts[2]),
                            gid=int(parts[3]),
                            home=parts[5],
                            shell=parts[6] if len(parts) > 6 else '/bin/sh'
                        )
                        users.append(user)
                    except ValueError:
                        # Skip malformed entries
                        continue
        
        # Check password hashes in /etc/shadow to determine if password change is required
        shadow_result = self._run_command('cat /etc/shadow')
        if shadow_result.success:
            shadow_users = {}
            for line in shadow_result.output.split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        # If password hash is not * or !, the user has a password that should be changed
                        requires_change = password_hash not in ['*', '!', '!!']
                        shadow_users[username] = requires_change
            
            # Update users with password change information
            for user in users:
                if user.username in shadow_users:
                    user.requires_password_change = shadow_users[user.username]
        else:
            # If we can't read /etc/shadow, try BSD's /etc/master.passwd
            master_passwd_result = self._run_command('cat /etc/master.passwd')
            if master_passwd_result.success:
                for line in master_passwd_result.output.split('\n'):
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            username = parts[0]
                            password_hash = parts[1]
                            # Find matching user and update password change flag
                            for user in users:
                                if user.username == username:
                                    user.requires_password_change = password_hash not in ['*', '!'] and password_hash.strip() != ''
                                    break
        
        self.server_info.users = users
    
    def _discover_services(self):
        """Discover running services"""
        services = []
        
        # Try systemctl first (systemd systems)
        result = self._run_command('systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null')
        if result.success and result.output:
            for line in result.output.split('\n'):
                if line.strip():
                    # Extract service name (first field)
                    service_name = line.split()[0] if line.split() else ''
                    if service_name and service_name.endswith('.service'):
                        services.append(service_name)
        else:
            # Fallback to ps for non-systemd systems
            result = self._run_command('ps aux --no-headers')
            if result.success and result.output:
                # Simple extraction of process names
                for line in result.output.split('\n')[:20]:  # Limit to avoid too much data
                    if line.strip():
                        parts = line.split()
                        if len(parts) > 10:
                            services.append(parts[10])  # Process name
        
        self.server_info.services = services[:50]  # Limit to reasonable number
    
    def _discover_network(self):
        """Discover network configuration"""
        network = NetworkInfo()
        
        # Network interfaces
        interfaces = self._try_command_chain([
            'ip link show 2>/dev/null',
            'ifconfig -a 2>/dev/null'
        ])
        if interfaces:
            network.interfaces = interfaces[:1000]  # Limit output size
        
        # Listening ports
        listening = self._try_command_chain([
            'ss -tuln 2>/dev/null',
            'netstat -tuln 2>/dev/null'
        ])
        if listening:
            network.listening_ports = listening[:2000]  # Limit output size
        
        # Default route
        route = self._try_command_chain([
            'ip route show default 2>/dev/null',
            'route -n | grep ^0.0.0.0'
        ])
        if route:
            network.default_route = route
            
        self.server_info.network = network
    
    def _discover_security_tools(self):
        """Discover installed security tools"""
        security_tools = {}
        
        # Common security tools to check
        tools_to_check = [
            'ufw', 'iptables', 'firewalld', 'fail2ban', 'chkrootkit', 'rkhunter',
            'clamav', 'aide', 'tripwire', 'lynis', 'nmap', 'wireshark'
        ]
        
        for tool in tools_to_check:
            # Check if tool is installed
            result = self._run_command(f'which {tool} 2>/dev/null || command -v {tool} 2>/dev/null')
            security_tools[tool] = result.success and len(result.output) > 0
        
        self.server_info.security_tools = security_tools
    
    def _discover_system_resources(self):
        """Discover system resource information"""
        # Memory information
        result = self._run_command('free -h')
        if result.success:
            self.server_info.memory_info = result.output
        
        # Disk information
        result = self._run_command('df -h')
        if result.success:
            self.server_info.disk_info = result.output
        
        # CPU cores
        cpu_count = self._try_command_chain([
            'nproc',
            'sysctl -n hw.ncpu',
            'grep -c ^processor /proc/cpuinfo'
        ])
        if cpu_count and cpu_count.isdigit():
            self.server_info.cpu_cores = int(cpu_count)
    
    def _discover_package_managers(self):
        """Discover available package managers"""
        package_managers = []
        
        # Common package managers
        pm_commands = {
            'apt':      'apt-get --version',
            'yum':      'yum --version',
            'dnf':      'dnf --version',
            'zypper':   'zypper --version', 
            'pacman':   'pacman --version',
            'emerge':   'emerge --version',
            'apk':      'apk --version',
            'pkg':      'pkg --version',
            'brew':     'brew --version',
            'snap':     'snap --version',
            'flatpak':  'flatpak --version',
            'slackpkg': 'slackpkg version'
        }
        
        for pm_name, pm_command in pm_commands.items():
            result = self._run_command(f'{pm_command} 2>/dev/null')
            if result.success:
                package_managers.append(pm_name)
        
        self.server_info.package_managers = package_managers

    @property 
    def os_family(self) -> str:
        """Get the detected OS family"""
        return self._os_family