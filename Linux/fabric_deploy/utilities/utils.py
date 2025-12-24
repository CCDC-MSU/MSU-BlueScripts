"""
Utility functions for CCDC hardening framework
Contains helper functions for configuration, file parsing, and common operations
"""

import json
import logging
from pathlib import Path
from typing import List
import yaml
from .models import ServerCredentials
import re

logger = logging.getLogger(__name__)


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
    """Parse hosts file with credentials per host"""
    servers = []
    config = load_config()
    logger.info(f"Parsing hosts file: {hosts_file}")
    
    try:
        with open(hosts_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Parse different formats:
                    # Format 1: host:user:password
                    # Format 2: host:user:password:port
                    # Format 3: host:user:key_file
                    # Format 4: host (uses defaults from config)
                    
                    parts = line.split(':')
                    
                    if len(parts) == 1:
                        # Just host, use config defaults
                        host = parts[0]
                        user = config.get('connection', {}).get('user', 'root')
                        password = config.get('connection', {}).get('password')
                        servers.append(ServerCredentials(host=host, user=user, password=password))
                        
                    elif len(parts) == 3:
                        # host:user:password_or_keyfile
                        host, user, auth = parts
                        if auth.startswith('/') or auth.endswith('.pem') or auth.endswith('.key'):
                            # Looks like a key file path
                            servers.append(ServerCredentials(host=host, user=user, key_file=auth))
                        else:
                            # Treat as password
                            servers.append(ServerCredentials(host=host, user=user, password=auth))
                            
                    elif len(parts) == 4:
                        # host:user:password:port
                        host, user, password, port = parts
                        servers.append(ServerCredentials(host=host, user=user, password=password, port=int(port)))
                        
                    else:
                        logger.warning(f"Invalid host format on line {line_num}: {line}")
                        continue
                        
                    logger.debug(f"Added server: {host} (user: {user})")
                    
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
        logger.debug(f"runas users match: {runas_match}")

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
