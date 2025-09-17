"""
SSH hardening module for CCDC framework
Enhanced with proper backup/rollback and connection testing
"""
#TODO: Explicitly allowing only users in users.json to log in via SSH using the AllowUsers directive.

import time
from typing import List
from fabric import Connection, Config
from .base import HardeningModule, HardeningCommand, PythonAction, HardeningResult
from ..discovery import OSFamily


class SSHHardeningModule(HardeningModule):
    """SSH hardening commands with backup, rollback, and connection testing"""
    
    def get_name(self) -> str:
        return "ssh_hardening"
    
    def get_commands(self) -> List[HardeningCommand]:
        commands = []
        
        # Create backup with timestamp and store backup path
        backup_timestamp = "$(date +%Y%m%d_%H%M%S)"
        backup_path = f"/etc/ssh/sshd_config.backup.{backup_timestamp}"
        
        # backup SSH config
        commands.append(HardeningCommand(
            command=f"cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.{backup_timestamp} && echo 'Backup created: /etc/ssh/sshd_config.backup.{backup_timestamp}'",
            description="Create timestamped SSH configuration backup",
            check_command="ls /etc/ssh/sshd_config.backup.* >/dev/null 2>&1 && echo backup_exists",
            requires_sudo=True
        ))
        
        # Store original config validation
        commands.append(HardeningCommand(
            command="sshd -t -f /etc/ssh/sshd_config && echo 'Original config valid'",
            description="Validate original SSH configuration",
            requires_sudo=True
        ))
        
        # SSH hardening parameters
        ssh_params = [
            ("PermitRootLogin no", "Disable root login"),
            ("PermitEmptyPasswords no", "Disable empty passwords"), 
            ("ChallengeResponseAuthentication no", "Disable challenge response auth"),
            ("X11Forwarding no", "Disable X11 forwarding"),
            ("MaxAuthTries 5", "Limit authentication attempts"),
            ("ClientAliveInterval 300", "Set client alive interval"),
            ("ClientAliveCountMax 2", "Set client alive count to 2"),
            ("Protocol 2", "Force SSH protocol 2"),
        ]
        
        for param, desc in ssh_params:
            key = param.split()[0]
            # Use detected shell instead of hardcoded bash
            shell = self.server_info.default_shell
            commands.append(HardeningCommand(
                command=f"{shell} -c \"echo '{param}' >> /etc/ssh/sshd_config && sed -i.bak 's/^#*{key}.*/{param}/g' /etc/ssh/sshd_config\"",
                description=desc,
                check_command=f"grep -q '^{param}' /etc/ssh/sshd_config && echo found",
                requires_sudo=True
            ))
        
        # Validate new configuration before applying
        commands.append(HardeningCommand(
            command="sshd -t -f /etc/ssh/sshd_config && echo 'New config valid'",
            description="Validate new SSH configuration",
            requires_sudo=True
        ))
        
        # Reload SSH service safely (reload instead of restart to avoid connection loss)
        reload_cmd = self._get_ssh_reload_command()
        commands.append(HardeningCommand(
            command=reload_cmd,
            description="Reload SSH service configuration",
            requires_sudo=True
        ))
        
        # Test SSH connectivity with Python function
        commands.append(PythonAction(
            function=self._test_ssh_connectivity,
            description="Test SSH connectivity after changes",
            requires_sudo=False
        ))
        
        return commands
    
    def _test_ssh_connectivity(self, conn, server_info):
        """Test SSH connectivity after configuration changes with automatic rollback on failure"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Get connection details from server_info
            host = server_info.credentials.host
            user = server_info.credentials.user
            port = getattr(server_info.credentials, 'port', 22)
            password = getattr(server_info.credentials, 'password', None)
            key_file = getattr(server_info.credentials, 'key_file', None)
            
            logger.info(f"Testing SSH connectivity to {host}:{port} as {user}")
            
            # Set up connection configuration
            connect_kwargs = {'allow_agent': False, 'look_for_keys': False}
            config_overrides = {
                'sudo': {'password': password},
                'load_ssh_configs': False
            }
            
            if key_file:
                connect_kwargs['key_filename'] = key_file
            elif password:
                connect_kwargs['password'] = password
                
            if port != 22:
                connect_kwargs['port'] = port
                
            config = Config(overrides=config_overrides)
            
            # Test new connection with a timeout
            test_success = False
            error_msg = None
            
            try:
                with Connection(host, user=user, config=config, connect_kwargs=connect_kwargs) as test_conn:
                    # Simple connectivity test
                    result = test_conn.run('echo "SSH test successful"', hide=True, warn=True, timeout=10)
                    test_success = result.ok
                    if not test_success:
                        error_msg = f"SSH test command failed: {result.stderr}"
                        
            except Exception as e:
                test_success = False
                error_msg = f"SSH connection failed: {str(e)}"
                
            if test_success:
                return HardeningResult(
                    success=True,
                    command="python_function:_test_ssh_connectivity",
                    description="Test SSH connectivity after changes",
                    output="SSH connectivity test successful - new configuration is working"
                )
            else:
                # Connection failed - attempt automatic rollback
                logger.warning(f"SSH connectivity test failed: {error_msg}")
                logger.info("Attempting automatic rollback of SSH configuration...")
                
                # Find the most recent backup
                backup_result = conn.run("ls -t /etc/ssh/sshd_config.backup.* 2>/dev/null | head -1", 
                                       hide=True, warn=True)
                
                if backup_result.ok and backup_result.stdout.strip():
                    backup_file = backup_result.stdout.strip()
                    logger.info(f"Found backup file: {backup_file}")
                    
                    # Restore the backup
                    restore_result = conn.sudo(f"cp {backup_file} /etc/ssh/sshd_config", 
                                             hide=True, warn=True)
                    
                    if restore_result.ok:
                        # Restart SSH service
                        reload_cmd = self._get_ssh_reload_command()
                        restart_result = conn.sudo(reload_cmd, hide=True, warn=True)
                        
                        if restart_result.ok:
                            logger.info("SSH configuration rolled back successfully")
                            return HardeningResult(
                                success=False,
                                command="python_function:_test_ssh_connectivity",
                                description="Test SSH connectivity after changes",
                                output="SSH test failed, configuration rolled back automatically",
                                error=f"Original error: {error_msg}. Rollback completed successfully."
                            )
                        else:
                            logger.error("Failed to restart SSH service after rollback")
                    else:
                        logger.error("Failed to restore SSH configuration backup")
                else:
                    logger.error("No SSH configuration backup found for rollback")
                
                return HardeningResult(
                    success=False,
                    command="python_function:_test_ssh_connectivity",
                    description="Test SSH connectivity after changes",
                    output="SSH connectivity test failed",
                    error=f"SSH test failed: {error_msg}. Manual intervention may be required."
                )
                
        except Exception as e:
            logger.error(f"SSH connectivity test encountered an error: {e}")
            return HardeningResult(
                success=False,
                command="python_function:_test_ssh_connectivity",
                description="Test SSH connectivity after changes",
                output="SSH connectivity test encountered an error",
                error=str(e)
            )
    
    def _get_ssh_reload_command(self) -> str:
        """Get the appropriate SSH reload command for the OS (safer than restart)"""
        try:
            os_family = OSFamily(self.os_family)
            
            # Detect init system from server info
            init_system = getattr(self.server_info, 'init_system', 'unknown')
            
            if init_system == "systemd":
                if os_family == OSFamily.DEBIAN:
                    # Use reload instead of restart to avoid connection loss
                    return "systemctl reload ssh || sudo systemctl restart ssh"
                else:
                    return "systemctl reload sshd || sudo systemctl restart sshd"
            elif init_system == "openrc":
                return "rc-service sshd reload || sudo rc-service sshd restart"
            else:
                # For SysV init systems
                return "service sshd reload || sudo service sshd restart"
        except ValueError:
            # Fallback for unknown OS family
            return "service sshd reload || sudo service sshd restart"
