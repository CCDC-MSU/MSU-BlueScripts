from fabric import task, Connection, Config
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from utilities.utils import parse_hosts_file, is_connection_reset
from .common import (
    _configure_parallel_logging,
    _get_console_logger,
    _host_label,
    _host_log_handler
)

logger = logging.getLogger(__name__)


@task
def reset_ssh(c, hosts_file='hosts.txt', restart=True):
    """
    Reset SSH configuration to the latest backup (Development Helper)
    
    Args:
        hosts_file: Path to hosts file
        restart: Whether to restart SSH service after reset (default: True)
    """
    _configure_parallel_logging()
    console_logger = _get_console_logger()
    
    console_logger.info("=" * 60)
    console_logger.info("RESETTING SSH CONFIGURATION FROM BACKUPS")
    console_logger.info("=" * 60)
    
    servers = parse_hosts_file(hosts_file)
    if not servers:
        console_logger.error("No servers found")
        return

    def _reset_host(server_creds):
        host_id = _host_label(server_creds)
        with _host_log_handler("reset-ssh", host_id, datetime.now().strftime("%Y%m%d_%H%M%S")) as log_path:
            try:
                # Connection setup
                connect_kwargs = {'allow_agent': False, 'look_for_keys': False}
                config_overrides = {'sudo': {'password': None}}
                if server_creds.key_file:
                    connect_kwargs['key_filename'] = server_creds.key_file
                elif server_creds.password:
                    connect_kwargs['password'] = server_creds.password
                    config_overrides['sudo']['password'] = server_creds.password
                
                if server_creds.port != 22:
                    connect_kwargs['port'] = server_creds.port
                
                fabric_config = Config(overrides=config_overrides)
                
                with Connection(server_creds.host, user=server_creds.user,
                               config=fabric_config, connect_kwargs=connect_kwargs) as conn:
                    
                    # 1. Find latest backup
                    logger.info("Looking for latest sshd_config backup...")
                    # listing files, sorting by time (newest first), picking first
                    # Updated to match the robust backup naming convention (sshd_config.fabric.backup)
                    res = conn.sudo("ls -t /etc/ssh/sshd_config.fabric.backup* 2>/dev/null | head -1", warn=True)
                    
                    if not res.ok or not res.stdout.strip():
                        logger.warning("No backup files found. Skipping reset.")
                        return {'host': server_creds.host, 'status': 'no-backup'}
                    
                    backup_file = res.stdout.strip()
                    logger.info(f"Found backup: {backup_file}")
                    
                    # 2. Restore backup
                    conn.sudo(f"cp {backup_file} /etc/ssh/sshd_config")
                    logger.info("Restored backup to /etc/ssh/sshd_config")
                    
                    # 3. Restart Service
                    if restart:
                        logger.info("Restarting SSH service...")
                        # Try common restart commands including Gentoo (OpenRC) and Slackware
                        restart_cmd = (
                            "service sshd restart || service ssh restart || "
                            "systemctl restart sshd || systemctl restart ssh || "
                            "/etc/init.d/ssh restart || /etc/init.d/sshd restart || "
                            "/etc/rc.d/rc.sshd restart"
                        )
                        res = conn.sudo(restart_cmd, warn=True)
                        if res.ok:
                            logger.info("SSH service restarted successfully")
                        else:
                            host_identifier  = server_creds.friendly_name if server_creds.friendly_name else server_creds.host
                            logger.error(f"Failed to restart SSH on host {host_identifier}: {res.stderr}")
                            return {'host': server_creds.host, 'status': 'restart-failed'}
                            
                    return {'host': server_creds.host, 'status': 'ok'}

            except Exception as e:
                if is_connection_reset(e):
                    logger.error(f"Reset failed for {server_creds.host}: Connection reset by peer")
                else:
                    logger.error(f"Reset failed: {e}")
                return {'host': server_creds.host, 'status': 'failed'}

    results = []
    with ThreadPoolExecutor(max_workers=min(16, len(servers))) as executor:
        futures = {executor.submit(_reset_host, s): s for s in servers}
        for future in as_completed(futures):
            results.append(future.result())

    success = sum(1 for r in results if r['status'] == 'ok')
    console_logger.info(f"Reset complete. Success: {success}/{len(servers)}")
