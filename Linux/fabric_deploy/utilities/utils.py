"""
Utility functions for CCDC hardening framework
Contains helper functions for configuration, file parsing, and common operations
"""

import json
import logging
import secrets
import string
from pathlib import Path
from typing import List
import yaml
from .models import ServerCredentials
import re
import socket
from paramiko.ssh_exception import SSHException

logger = logging.getLogger(__name__)


def is_connection_reset(e):
    """Check if exception is a connection reset (host hostile or blocking)"""
    # Check for direct types
    if isinstance(e, (EOFError, socket.error, ConnectionResetError)):
        return True
        
    msg = str(e).lower()
    # Check for ConnectionResetError or similar OS errors via message
    if "connection reset by peer" in msg or "Errno 104" in msg or "errno 10054" in msg:
        return True
    
    # Check for wrapped SSHException
    if isinstance(e, SSHException):
        if "connection reset" in msg or "eof" in msg:
            return True
            
    return False


def load_config(config_file: str = None) -> dict:
    """Load configuration from config.yaml file"""
    if config_file:
        config_path = Path(config_file)
    else:
        config_path = Path(__file__).parent.parent / 'config.yaml'
    if config_path.exists():
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {}


def parse_hosts_file(hosts_file: str) -> List[ServerCredentials]:
    """Parse hosts file with credentials per host
    
    Supported formats:
        host:user:password                       - password auth
        host:user:keyfile                        - SSH key auth (if path-like)
        host:user:password:port                  - custom port
        host:user:password:friendly_name         - friendly name (starts with alpha)
        host:user:password:port:friendly_name    - port and friendly name
    """
    servers = []
    config = load_config()
    logger.info(f"Parsing hosts file: {hosts_file}")
    
    def _is_port(value: str) -> bool:
        """Check if value looks like a port number"""
        return value.isdigit()
    
    def _is_friendly_name(value: str) -> bool:
        """Check if value looks like a friendly name (starts with alpha)"""
        return value and value[0].isalpha()
    
    try:
        with open(hosts_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Parse different formats
                    parts = line.split(':')
                    
                    host = None
                    user = None
                    password = None
                    key_file = None
                    port = 22
                    friendly_name = None
                    
                    if len(parts) == 1:
                        # Just host, rely on SSH config or fabric defaults
                        host = parts[0]
                        user = config.get('connection', {}).get('user', 'root')
                        password = config.get('connection', {}).get('password')
                        
                    elif len(parts) == 3:
                        # host:user:password_or_keyfile
                        host, user, auth = parts
                        if auth.startswith('/') or auth.startswith('~') or auth.endswith('.pem') or auth.endswith('.key'):
                            key_file = auth
                        else:
                            password = auth
                            
                    elif len(parts) == 4:
                        # Could be:
                        # - host:user:password:port (4th is numeric)
                        # - host:user:password:friendly_name (4th starts with alpha)
                        host, user, auth, fourth = parts
                        
                        if auth.startswith('/') or auth.startswith('~') or auth.endswith('.pem') or auth.endswith('.key'):
                            key_file = auth
                        else:
                            password = auth
                        
                        if _is_port(fourth):
                            port = int(fourth)
                        elif _is_friendly_name(fourth):
                            friendly_name = fourth
                        else:
                            logger.warning(f"Ambiguous 4th field on line {line_num}: {fourth}")
                            
                    elif len(parts) == 5:
                        # host:user:password:port:friendly_name
                        host, user, auth, port_str, friendly_name = parts
                        
                        if auth.startswith('/') or auth.startswith('~') or auth.endswith('.pem') or auth.endswith('.key'):
                            key_file = auth
                        else:
                            password = auth
                        
                        if _is_port(port_str):
                            port = int(port_str)
                        else:
                            logger.warning(f"Invalid port on line {line_num}: {port_str}")
                            continue
                            
                    else:
                        logger.warning(f"Invalid host format on line {line_num}: {line}")
                        continue
                    
                    servers.append(ServerCredentials(
                        host=host,
                        user=user,
                        password=password,
                        key_file=key_file,
                        port=port,
                        friendly_name=friendly_name
                    ))
                    
                    display = friendly_name if friendly_name else host
                    logger.debug(f"Added server: {display} (host: {host}, user: {user})")
                    
                except Exception as e:
                    logger.error(f"Error parsing line {line_num} in {hosts_file}: {e}")
                    continue
                    
    except FileNotFoundError:
        logger.error(f"Hosts file not found: {hosts_file}")
        return []
    except Exception as e:
        logger.error(f"Error reading hosts file {hosts_file}: {e}")
        return []
    
    logger.info(f"Parsed {len(servers)} servers from hosts file")
    return servers


def save_discovery_summary(server_info, output_file: str):
    """Save discovery results to JSON file"""
    sudoers_info = getattr(server_info, "sudoers_info", None)
    sudoers_dump = getattr(server_info, "sudoers_dump", "") or ""
    sudoers_data = {
        'dump': sudoers_dump,
        'dump_present': bool(sudoers_dump),
        'dump_line_count': len(sudoers_dump.splitlines()) if sudoers_dump else 0,
        'nopasswd_lines': getattr(sudoers_info, 'nopasswd_lines', []) if sudoers_info else [],
        'sudoer_users': getattr(sudoers_info, 'sudoer_users', []) if sudoers_info else [],
        'sudoer_groups': getattr(sudoers_info, 'sudoer_groups', []) if sudoers_info else [],
        'sudoer_group_all': getattr(sudoers_info, 'sudoer_group_all', []) if sudoers_info else [],
    }

    summary_data = {
        'hostname': server_info.hostname,
        'discovery_time': server_info.discovery_time.isoformat(),
        'discovery_successful': server_info.discovery_successful,
        'os': {
            'distro': server_info.os.distro,
            'version': server_info.os.version,
            'kernel': server_info.os.kernel,
            'architecture': server_info.os.architecture
        },
        'users': {
            'total': server_info.user_count,
            'regular': server_info.regular_user_count,
            'usernames': server_info.usernames
        },
        'groups': server_info.groups,
        'sudoers': sudoers_data,
        'services_count': len(server_info.services),
        'package_managers': server_info.package_managers,
        'security_tools': server_info.security_tools,
        'available_commands': server_info.available_commands,
        'discovery_errors': server_info.discovery_errors
    }
    
    with open(output_file, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
    logger.info(f"Discovery results saved to {output_file}")


def setup_logging(level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def generate_password() -> str:
    """Generate a password with 6 upper, 6 lower, and 4 symbols in random order."""
    symbols = "!@#$%^&*()-_=+[]{}:,.?"
    chars = (
        [secrets.choice(string.ascii_uppercase) for _ in range(6)]
        + [secrets.choice(string.ascii_lowercase) for _ in range(6)]
        + [secrets.choice(symbols) for _ in range(4)]
    )

    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)

def analyze_sudoers(all_users, all_groups, sudoers_dump):
    logger.info("Analyzing sudoers entries")
    nopasswd_lines = []
    sudoer_users = set()
    sudoer_groups = set()
    sudoer_group_all = set()

    # Normalize users/groups for quick lookup
    all_users = set(all_users)
    all_groups = set(all_groups)

    # Join line continuations and split into lines
    if not sudoers_dump:
        logger.warning("Empty sudoers dump provided")
    sudoers_dump = sudoers_dump.replace("\\\n", "")
    sudoers_dump = sudoers_dump.replace(', ', ',')  # normalize by replacing ', ' with just ','

    lines = sudoers_dump.splitlines()
    logger.debug(f"Sudoers dump line count: {len(lines)}")
    for line in lines:
        if len(line)>1:
            logger.debug(line)

    for raw_line in lines:
        if len(raw_line) < 2:
            continue
        line = raw_line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Track NOPASSWD lines
        if "NOPASSWD" in line:
            nopasswd_lines.append(line)

        # Split LHS and RHS
        if "=" not in line:
            continue

        lhs, rhs = map(str.strip, line.split("=", 1))

        # ----- Parse LHS (users + hosts) -----
        # Example: "alice, bob, %dbadmins db01, db02"
        lhs_tokens = lhs.split()
        if not lhs_tokens or len(lhs_tokens)>2:     # if theres more than one space present before the = sign it might be a non relevant line
            continue

        users_part = lhs_tokens[0]

        for entry in users_part.split(","):
            entry = entry.strip()
            if entry.startswith("%"):
                group = entry[1:]
                if group in all_groups:
                    sudoer_groups.add(group)
            else:
                if entry in all_users:
                    sudoer_users.add(entry)

        # ----- Parse RunAs section -----
        # Example: "(ALL : ALL)" or "(postgres, mysql)"
        runas_match = re.search(r"\(([^)]+)\)", rhs)
        # logger.debug(f"runas users match: {runas_match}")

        runas_users = set()

        if runas_match:
            runas_field = runas_match.group(1)
            runas_user_part = runas_field.split(":")[0]
            for ru in runas_user_part.split(","):
                runas_users.add(ru.strip())
        else:
            runas_users.add('root')     # defaults to root a runas section is not present fkts

        # ----- Parse command section -----
        command_part = rhs.split(")", 1)[-1].strip()

        is_all_commands = command_part == "ALL"

        # ----- Detect groups with ALL as root -----
        if ("ALL" in runas_users or "root" in runas_users) and is_all_commands:
            for entry in users_part.split(","):
                entry = entry.strip()
                if entry.startswith("%"):
                    group = entry[1:]
                    if group in all_groups:
                        sudoer_group_all.add(group)

    logger.info(
        "Sudoers analysis complete: users=%d groups=%d nopasswd_lines=%d group_all=%d",
        len(sudoer_users),
        len(sudoer_groups),
        len(nopasswd_lines),
        len(sudoer_group_all),
    )
    return {
        "nopasswd_lines": nopasswd_lines,
        "sudoer_users": sorted(sudoer_users),
        "sudoer_groups": sorted(sudoer_groups),
        "sudoer_group_all": sorted(sudoer_group_all),
    }
