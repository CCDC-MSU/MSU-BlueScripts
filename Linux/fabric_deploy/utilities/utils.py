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
        'services_count': len(server_info.services),
        'package_managers': server_info.package_managers,
        'security_tools': server_info.security_tools,
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