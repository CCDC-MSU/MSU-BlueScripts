from fabric import task, Connection, Config
from invoke import UnexpectedExit
import logging
import getpass
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from utilities.models import ServerCredentials, ServerInfo
from utilities.discovery import SystemDiscovery
from utilities.utils import load_config, parse_hosts_file, save_discovery_summary, is_connection_reset

from .common import (
    _configure_parallel_logging,
    _get_console_logger,
    _host_label,
    _host_log_handler
)

logger = logging.getLogger(__name__)

# Load configuration with error handling
try:
    CONFIG = load_config()
except Exception as e:
    logger.warning(f"Could not load config: {e}")
    CONFIG = {}


@task
def discover(c, host, user=None, key_file=None, password=None):
    """Discover system information on target host"""
    # Use config defaults if not provided
    if user is None:
        user = CONFIG.get('connection', {}).get('user', 'root')
    if password is None and key_file is None:
        password = CONFIG.get('connection', {}).get('password')
    
    # Handle authentication
    connect_kwargs = {'allow_agent':False,'look_for_keys':False }
    config_overrides = {
        'sudo': {'password': None},
        'load_ssh_configs': False  # Disable SSH config loading to avoid parse errors
    }
    
    if key_file:
        connect_kwargs['key_filename'] = key_file
        logger.info(f"Using SSH key authentication: {key_file}")
    elif password:
        connect_kwargs['password'] = password
        config_overrides['sudo']['password'] = password
        logger.info("Using password authentication")
    else:
        # Prompt for password if neither key nor password provided
        password = getpass.getpass(f"Enter password for {user}@{host}: ")
        connect_kwargs['password'] = password
        config_overrides['sudo']['password'] = password
        logger.info("Using prompted password authentication")
    
    config = Config(overrides=config_overrides)
    
    try:
        with Connection(host, user=user, config=config, connect_kwargs=connect_kwargs) as conn:
            credentials = ServerCredentials(host=host, user=user, password=password, key_file=key_file)
            discovery = SystemDiscovery(conn, credentials)
            server_info = discovery.discover_system()
            
            # Save discovery results
            output_file = f"discovery_{host.replace('.', '_')}.json"
            save_discovery_summary(server_info, output_file)
            
            return server_info
    except Exception as e:
        if is_connection_reset(e):
            logger.error(f"Connection failed to {host}: Connection reset by peer (Firewall/Hostile Action)")
        else:
            logger.error(f"Connection failed to {host}: {e}")
        return None


@task
def discover_all(c, hosts_file='hosts.txt'):
    """Automated discovery pipeline - discovers all hosts"""
    _configure_parallel_logging()
    console_logger = _get_console_logger()

    console_logger.info("=" * 60)
    console_logger.info("CCDC DISCOVERY PIPELINE STARTING (PARALLEL)")
    console_logger.info("=" * 60)

    start_time = datetime.now()

    # Check if hosts file exists
    if not os.path.exists(hosts_file):
        console_logger.error(f"Hosts file not found: {hosts_file}")
        return

    # Parse hosts file
    try:
        servers = parse_hosts_file(hosts_file)
    except Exception as e:
        console_logger.error(f"Error parsing hosts file: {e}")
        return

    if not servers:
        console_logger.error("No servers found in hosts file or file not found")
        return

    console_logger.info(f"Found {len(servers)} servers to process")
    console_logger.info("Logs: logs/discover-all/<host>/<timestamp>.log")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _discover_host(server_creds):
        host_id = _host_label(server_creds)
        with _host_log_handler("discover-all", host_id, timestamp) as log_path:
            try:
                logger.info(f"Starting discovery on {server_creds.host}")
                # Set up connection
                connect_kwargs = {
                    'allow_agent': False,
                    'look_for_keys': False
                }
                config_overrides = {
                    'sudo': {'password': None},
                    'load_ssh_configs': False  # Disable SSH config loading
                }

                if server_creds.key_file:
                    connect_kwargs['key_filename'] = server_creds.key_file
                    logger.info(f"Using SSH key: {server_creds.key_file}")
                elif server_creds.password:
                    connect_kwargs['password'] = server_creds.password
                    config_overrides['sudo']['password'] = server_creds.password
                    logger.info("Using password authentication")

                # Add port if specified
                if server_creds.port != 22:
                    connect_kwargs['port'] = server_creds.port

                config = Config(overrides=config_overrides)

                # Run discovery
                with Connection(server_creds.host, user=server_creds.user,
                              config=config, connect_kwargs=connect_kwargs) as conn:
                    discovery = SystemDiscovery(conn, server_creds)
                    server_info = discovery.discover_system()

                    # Store discovery instance for OS family access
                    server_info._discovery = discovery

                    if server_info.discovery_successful:
                        logger.info(f"Discovery successful for {server_creds.host}")
                        logger.info(f"OS: {server_info.os.distro} {server_info.os.version}")
                        logger.info(f"Users: {server_info.regular_usernames}")
                        logger.info(f"Services: {len(server_info.services)} running")
                        logger.info(f"Security tools: {[k for k, v in server_info.security_tools.items() if v]}")
                        sudoers_info = getattr(server_info, "sudoers_info", None)
                        if sudoers_info:
                            logger.info(
                                "Sudoers: users=%d groups=%d nopasswd=%d group_all=%d",
                                len(sudoers_info.sudoer_users),
                                len(sudoers_info.sudoer_groups),
                                len(sudoers_info.nopasswd_lines),
                                len(sudoers_info.sudoer_group_all),
                            )
                    else:
                        logger.error(f"Discovery failed for {server_creds.host}")
                        for error in server_info.discovery_errors:
                            logger.error(f"Error: {error}")

                return {
                    'host': server_creds.host,
                    'success': server_info.discovery_successful,
                    'server_info': server_info,
                    'log_file': str(log_path)
                }

            except Exception as e:
                if is_connection_reset(e):
                     logger.error(f"Discovery failed for {server_creds.host}: Connection reset by peer")
                else:
                     logger.error(f"Discovery failed for {server_creds.host}: {e}")
                server_info = ServerInfo(hostname=server_creds.host, credentials=server_creds)
                server_info.discovery_successful = False
                server_info.discovery_errors.append(str(e))
                return {
                    'host': server_creds.host,
                    'success': False,
                    'server_info': server_info,
                    'log_file': str(log_path)
                }

    discovered_servers = []
    results = []
    max_workers = min(16, len(servers)) if servers else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for server_creds in servers:
            console_logger.info(f"Starting discovery on {server_creds.host}")
            futures.append(executor.submit(_discover_host, server_creds))

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            discovered_servers.append(result['server_info'])

    successful_discoveries = sum(1 for r in results if r['success'])
    failed_discoveries = len(results) - successful_discoveries

    end_time = datetime.now()
    duration = end_time - start_time

    console_logger.info("=" * 60)
    console_logger.info("CCDC DISCOVERY PIPELINE COMPLETED")
    console_logger.info("=" * 60)
    console_logger.info(f"Total time: {duration}")
    if len(servers) > 0:
        console_logger.info(
            f"Discovery success rate: {successful_discoveries}/{len(servers)} ({(successful_discoveries/len(servers)*100):.1f}%)"
        )
    if failed_discoveries > 0:
        failed_hosts = [r['host'] for r in results if not r['success']]
        console_logger.error(f"Discovery failed for: {', '.join(failed_hosts)}")

    if len(servers) > 0 and successful_discoveries > 0:
        console_logger.info("Discovery complete. Use 'fab harden' to apply hardening configurations.")

    return discovered_servers
