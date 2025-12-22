from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import re


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
            port_matches = re.findall(r':(\d+)\s', self.listening_ports)
            ports = list(set(port_matches))
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

    # User/Group Management Commands
    available_commands: List[str] = field(default_factory=list)

    # System Resources
    memory_info: str = ''
    disk_info: str = ''
    cpu_cores: int = 0
    uptime: str = ''

    # Shell Information
    default_shell: str = '/bin/sh'

    # Discovery Status
    discovery_successful: bool = False
    discovery_errors: List[str] = field(default_factory=list)

    @property
    def regular_users(self) -> List[UserInfo]:
        return [user for user in self.users if user.is_regular_user]

    @property
    def user_count(self) -> int:
        return len(self.users)

    @property
    def regular_user_count(self) -> int:
        return len(self.regular_users)

    @property
    def usernames(self) -> List[str]:
        return [user.username for user in self.users]

    @property
    def regular_usernames(self) -> List[str]:
        return [user.username for user in self.regular_users]

    @property
    def users_requiring_password_change(self) -> List[UserInfo]:
        return [user for user in self.users if user.requires_password_change]

    @property
    def users_requiring_password_change_count(self) -> int:
        return len(self.users_requiring_password_change)

    def get_user(self, username: str) -> Optional[UserInfo]:
        for user in self.users:
            if user.username == username:
                return user
        return None

    def has_user(self, username: str) -> bool:
        return self.get_user(username) is not None

    def has_security_tool(self, tool: str) -> bool:
        return self.security_tools.get(tool, False)

    # ----------- NEW: Human-friendly printing -----------

    def __str__(self) -> str:
        def yn(v: bool) -> str:
            return "yes" if v else "no"

        def join_or_dash(items: List[str]) -> str:
            return ", ".join(items) if items else "—"

        def truncate_list(items: List[str], limit: int = 12) -> str:
            if not items:
                return "—"
            if len(items) <= limit:
                return ", ".join(items)
            shown = ", ".join(items[:limit])
            return f"{shown} … (+{len(items) - limit} more)"

        def format_kv(label: str, value: str, width: int = 18) -> str:
            return f"{label:<{width}} {value}"

        def format_block(title: str, lines: List[str]) -> str:
            body = "\n".join(f"  {line}" for line in lines) if lines else "  —"
            return f"{title}\n{body}"

        # Connection info (avoid leaking password)
        auth_bits = []
        if self.credentials.key_file:
            auth_bits.append(f"key={self.credentials.key_file}")
        auth_bits.append(f"password_set={yn(self.credentials.password is not None)}")

        conn = f"{self.credentials.user}@{self.credentials.host}:{self.credentials.port}"

        # OS line
        os_line = f"{self.os.distro} {self.os.version} ({self.os.architecture})"
        if self.os.kernel and self.os.kernel != "unknown":
            os_line += f" | kernel {self.os.kernel}"

        # Users
        regular_names = sorted(self.regular_usernames)
        system_names = sorted([u.username for u in self.users if not u.is_regular_user])
        pw_change_names = sorted([u.username for u in self.users_requiring_password_change])

        # Services/security tools
        services = sorted(self.services)
        installed_tools = sorted([name for name, installed in self.security_tools.items() if installed])
        missing_tools = sorted([name for name, installed in self.security_tools.items() if not installed])
        available_cmds = sorted(self.available_commands or [])

        # Network
        open_ports = self.network.open_ports
        ports_str = ", ".join(open_ports) if open_ports else "—"

        # Discovery status + errors
        status = "Successful" if self.discovery_successful else "Failed"
        errors = self.discovery_errors[:]
        if not errors and not self.discovery_successful:
            errors = ["(no errors recorded)"]

        # Format time nicely
        dt = self.discovery_time.strftime("%Y-%m-%d %H:%M:%S")

        header = f"🖥️  ServerInfo: {self.hostname}"
        sub = f"{conn}  |  discovered {dt}  |  discovery={status}"

        sections: List[str] = []

        sections.append(
            format_block("OS", [
                format_kv("OS", os_line),
                format_kv("Pkg managers", join_or_dash(self.package_managers)),
                format_kv("Default shell", self.default_shell or "—"),
            ])
        )

        sections.append(
            format_block("Users", [
                format_kv("Total users", str(self.user_count)),
                format_kv("Regular users", f"{self.regular_user_count} ({truncate_list(regular_names)})"),
                format_kv("System users", f"{len(system_names)} ({truncate_list(system_names)})"),
                format_kv("PW change req", f"{self.users_requiring_password_change_count} ({truncate_list(pw_change_names)})"),
            ])
        )

        sections.append(
            format_block("User mgmt cmds", [
                format_kv("Available", truncate_list(available_cmds)),
            ])
        )

        sections.append(
            format_block("Services", [
                format_kv("Running", f"{len(services)}"),
                format_kv("List", truncate_list(services)),
            ])
        )

        sections.append(
            format_block("Network", [
                format_kv("Open ports", ports_str),
                format_kv("Default route", self.network.default_route.strip() or "—"),
                format_kv("Interfaces", "present" if self.network.interfaces.strip() else "—"),
                format_kv("Listening raw", "present" if self.network.listening_ports.strip() else "—"),
            ])
        )

        sections.append(
            format_block("Security tools", [
                format_kv("Installed", truncate_list(installed_tools)),
                format_kv("Missing", truncate_list(missing_tools)),
            ])
        )

        sections.append(
            format_block("Resources", [
                format_kv("CPU cores", str(self.cpu_cores) if self.cpu_cores else "—"),
                format_kv("Uptime", self.uptime.strip() or "—"),
                format_kv("Memory", self.memory_info.strip() or "—"),
                format_kv("Disk", self.disk_info.strip() or "—"),
            ])
        )

        sections.append(
            format_block("Credentials", [
                format_kv("Auth", truncate_list(auth_bits, limit=99)),
            ])
        )

        if not self.discovery_successful or self.discovery_errors:
            sections.append(
                format_block("Discovery notes", [
                    format_kv("Errors", truncate_list(errors, limit=8)),
                ])
            )

        return "\n".join([header, sub, "—" * 72, *sections])

    # Optional: keep repr concise/debuggy
    def __repr__(self) -> str:
        return (
            f"ServerInfo(hostname={self.hostname!r}, "
            f"os={self.os.distro!r} {self.os.version!r}, "
            f"users={len(self.users)}, services={len(self.services)}, "
            f"discovery_successful={self.discovery_successful})"
        )
