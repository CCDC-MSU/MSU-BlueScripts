"""
Data models for CCDC hardening framework
Contains all data classes and structures for server information
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class ServerCredentials:
    """Credentials for connecting to a server"""
    host: str
    user: str = 'root'
    password: Optional[str] = None
    key_file: Optional[str] = None
    port: int = 22


@dataclass 
class UserInfo:
    """Information about a system user"""
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    requires_password_change: bool = False  # True if user has a password hash (not * or !)
    
    @property
    def is_regular_user(self) -> bool:
        """Check if this is a regular user (not system user)"""
        return self.uid >= 1000 and self.uid != 65534


@dataclass
class OSInfo:
    """Operating system information"""
    distro: str = 'unknown'
    version: str = 'unknown'
    kernel: str = 'unknown'
    architecture: str = 'unknown'
    
    @property
    def is_debian_based(self) -> bool:
        """Check if OS is Debian-based (Ubuntu, Debian)"""
        return self.distro.lower() in ['ubuntu', 'debian']
    
    @property
    def is_redhat_based(self) -> bool:
        """Check if OS is RedHat-based (CentOS, RHEL, Fedora)"""
        return self.distro.lower() in ['centos', 'rhel', 'fedora']


@dataclass
class NetworkInfo:
    """Network configuration information"""
    interfaces: str = ''
    listening_ports: str = ''
    default_route: str = ''
    
    @property
    def open_ports(self) -> List[str]:
        """Extract list of open ports from listening_ports string"""
        ports = []
        if self.listening_ports:
            # Simple regex to find port numbers in netstat/ss output
            port_matches = re.findall(r':(\d+)\s', self.listening_ports)
            ports = list(set(port_matches))  # Remove duplicates
        return sorted(ports, key=int)


@dataclass
class ServerInfo:
    """Complete server information from discovery"""
    hostname: str
    credentials: ServerCredentials
    discovery_time: datetime = field(default_factory=datetime.now)
    
    # OS Information
    os: OSInfo = field(default_factory=OSInfo)
    package_managers: List[str] = field(default_factory=list)
    
    # User Information  
    users: List[UserInfo] = field(default_factory=list)
    
    # Services
    services: List[str] = field(default_factory=list)
    
    # Network
    network: NetworkInfo = field(default_factory=NetworkInfo)
    
    # Security Tools
    security_tools: Dict[str, bool] = field(default_factory=dict)
    
    # System Resources
    memory_info: str = ''
    disk_info: str = ''
    cpu_cores: int = 0
    uptime: str = ''
    
    # Shell Information
    default_shell: str = '/bin/sh'  # Default shell for system operations
    
    # Discovery Status
    discovery_successful: bool = False
    discovery_errors: List[str] = field(default_factory=list)
    
    @property
    def regular_users(self) -> List[UserInfo]:
        """Get list of regular (non-system) users"""
        return [user for user in self.users if user.is_regular_user]
    
    @property
    def user_count(self) -> int:
        """Total number of users"""
        return len(self.users)
    
    @property
    def regular_user_count(self) -> int:
        """Number of regular users"""
        return len(self.regular_users)
    
    @property
    def usernames(self) -> List[str]:
        """List of all usernames"""
        return [user.username for user in self.users]
    
    @property
    def regular_usernames(self) -> List[str]:
        """List of regular usernames"""
        return [user.username for user in self.regular_users]
    
    @property
    def users_requiring_password_change(self) -> List[UserInfo]:
        """Get list of users that require password changes"""
        return [user for user in self.users if user.requires_password_change]
    
    @property
    def users_requiring_password_change_count(self) -> int:
        """Number of users requiring password changes"""
        return len(self.users_requiring_password_change)
    
    def get_user(self, username: str) -> Optional[UserInfo]:
        """Get user info by username"""
        for user in self.users:
            if user.username == username:
                return user
        return None
    
    def has_user(self, username: str) -> bool:
        """Check if user exists"""
        return self.get_user(username) is not None
    
    def has_security_tool(self, tool: str) -> bool:
        """Check if security tool is installed"""
        return self.security_tools.get(tool, False)
    
    def summary(self) -> str:
        """Generate a summary string of the server info"""
        return f"""
Server: {self.hostname}
OS: {self.os.distro} {self.os.version} ({self.os.architecture})
Users: {self.regular_user_count} regular, {self.user_count} total
Services: {len(self.services)} running
Package Managers: {', '.join(self.package_managers)}
Discovery: {'Successful' if self.discovery_successful else 'Failed'}
        """.strip()