"""
Logging Setup Module
Configures rsyslog, auditd, and other logging mechanisms using external configuration files.
"""

import os
import logging
import time
from typing import List
from pathlib import Path
from .base import HardeningModule, HardeningCommand, HardeningResult, PythonAction
from ..discovery import OSFamily

logger = logging.getLogger(__name__)

class LoggingSetupModule(HardeningModule):
    """Configure comprehensive logging for CCDC scenarios"""
    
    def get_name(self) -> str:
        return "logging_setup"
    
    def _read_config_file(self, filename: str) -> str:
        """Read configuration file from configs directory"""
        # Assuming configs directory is at the same level as utilities/..
        # Structure: Linux/fabric_deploy/utilities/modules/logging_setup.py
        # Configs: Linux/fabric_deploy/configs/
        
        # Get the path to the current file
        current_file = Path(__file__)
        # Go up 3 levels to fabric_deploy
        base_dir = current_file.parent.parent.parent
        config_path = base_dir / "configs" / filename
        
        if not config_path.exists():
            logger.error(f"Configuration file not found: {config_path}")
            return ""
            
        with open(config_path, 'r') as f:
            return f.read()

    def _get_service_restart_cmd(self, service: str) -> str:
        """Get robust restart command for a service"""
        return (
            f"(systemctl restart {service} 2>/dev/null || "
            f"service {service} restart 2>/dev/null || "
            f"/etc/init.d/{service} restart 2>/dev/null || "
            f"rc-service {service} restart 2>/dev/null || "
            f"/etc/rc.d/rc.{service} restart 2>/dev/null || "
            f"/etc/rc.d/{service} restart 2>/dev/null || "
            f"echo 'Failed to restart {service}')"
        )

    def _get_service_enable_cmd(self, service: str) -> str:
        """Get robust enable command for a service"""
        return (
            f"(systemctl enable {service} 2>/dev/null || "
            f"rc-update add {service} default 2>/dev/null || "
            f"chkconfig {service} on 2>/dev/null || "
            f"sysrc {service}_enable=YES 2>/dev/null || "
            f"echo 'Failed to enable {service}')"
        )
            
    def get_commands(self) -> List[HardeningCommand]:
        try:
            os_family = OSFamily(self.os_family)
        except ValueError:
            os_family = OSFamily.UNKNOWN
        
        if os_family in [OSFamily.FREEBSD, OSFamily.OPENBSD, OSFamily.NETBSD, OSFamily.BSDGENERIC]:
            return self._get_bsd_commands()
        else:
            return self._get_linux_commands()
    
    def _get_linux_commands(self) -> List[HardeningCommand]:
        """Commands for Linux systems"""
        commands = []
        
        # Ensure rsyslog is installed (PythonAction)
        commands.append(PythonAction(
            function=self._ensure_rsyslog_installed,
            description="Ensure rsyslog is installed and enabled",
            requires_sudo=True
        ))
        
        # Configure rsyslog
        commands.extend(self._configure_rsyslog())
        
        # Configure systemd journald (if systemd is present)
        commands.extend(self._configure_journald())
        
        # Ensure auditd is installed (PythonAction)
        commands.append(PythonAction(
            function=self._ensure_auditd_installed,
            description="Ensure auditd is installed and enabled",
            requires_sudo=True
        ))

        # Configure auditd for security auditing
        commands.extend(self._configure_auditd())
        
        # Configure logrotate
        commands.extend(self._configure_logrotate())
        
        # Configure additional security logging
        commands.extend(self._configure_security_logging())
        
        return commands
    
    def _get_bsd_commands(self) -> List[HardeningCommand]:
        """Commands for BSD systems"""
        commands = []
        
        # Configure BSD syslogd
        commands.extend(self._configure_bsd_syslog())
        
        # Configure newsyslog (BSD log rotation)
        commands.extend(self._configure_newsyslog())
        
        # Configure BSD security logging
        commands.extend(self._configure_bsd_security_logging())
        
        return commands
    
    def _ensure_rsyslog_installed(self, conn, server_info):
        """Install rsyslog if missing"""
        if conn.run("command -v rsyslogd", warn=True, hide=True).ok:
            return HardeningResult(success=True, command="check_rsyslog", description="Check rsyslog", output="Already installed")

        logger.info("Installing rsyslog...")
        pms = server_info.package_managers
        cmd = None
        
        # Priority order for package managers (though usually only one is pertinent)
        if "dnf" in pms:
            cmd = "dnf install -y rsyslog"
        elif "yum" in pms:
            cmd = "yum install -y rsyslog"
        elif "apt" in pms:
            cmd = "DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog"
        elif "zypper" in pms:
            cmd = "zypper --non-interactive install rsyslog"
        elif "pacman" in pms:
            # Arch needs rsyslog-gnutls or similar usually, but 'rsyslog' is in AUR or sometimes distinct repos.
            # However, 'rsyslog' is standard package name in official repos (extra).
            # If it failed with target not found, maybe repo sync needed.
            cmd = "pacman -Sy --noconfirm rsyslog" 
        elif "emerge" in pms:
            cmd = "PAGER=cat emerge --ask=n app-admin/rsyslog"
        elif "apk" in pms:
            # Alpine sometimes needs update first if index is stale
            cmd = "apk update && apk add rsyslog"
        elif "pkg" in pms:
            cmd = "pkg install -y rsyslog"
        elif "slackpkg" in pms or "sbopkg" in pms:
             # Slackware: rsyslog is in SBo. sbopkg can install it.
             # If sbopkg is present, use it.
             if "sbopkg" in pms:
                 cmd = "sbopkg -B -e -i rsyslog"
             else:
                 # Manually install if only slackpkg (which manages base system)? 
                 # rsyslog is NOT in base Slackware (sysklogd is). 
                 # We can try to rely on native syslogd if rsyslog install fails, but here we are ensuring rsyslog.
                 # Let's try and see if user has a queue file or similar, but for now just fail gracefully or try sbopkg.
                 cmd = "echo 'rsyslog not in base slackware; install via sbopkg if available' && false"
            
        if cmd:
            try:
                conn.sudo(cmd, hide=True)
                
                # Enable service
                enable_cmd = self._get_service_enable_cmd("rsyslog")
                if conn.run("command -v rsyslogd", warn=True, hide=True).ok:
                     conn.sudo(f"{enable_cmd} && {self._get_service_restart_cmd('rsyslog')}", warn=True, hide=True)
                     
                return HardeningResult(success=True, command="install_rsyslog", description="Install rsyslog", output="Installed and enabled")
            except Exception as e:
                return HardeningResult(success=False, command="install_rsyslog", description="Install rsyslog", error=str(e))
                
        return HardeningResult(success=False, command="install_rsyslog", description="Install rsyslog", error=f"No supported package manager found in {pms}")

    def _ensure_auditd_installed(self, conn, server_info):
        """Install auditd if missing"""
        if conn.run("command -v auditctl", warn=True, hide=True).ok:
            return HardeningResult(success=True, command="check_auditd", description="Check auditd", output="Already installed")

        logger.info("Installing auditd...")
        pms = server_info.package_managers
        cmd = None
        
        if "dnf" in pms or "yum" in pms:
            cmd = "yum install -y audit" 
            # RHEL/CentOS package is usually just 'audit', not 'auditd'
        elif "apt" in pms:
            cmd = "DEBIAN_FRONTEND=noninteractive apt-get install -y auditd"
        elif "zypper" in pms:
            cmd = "zypper --non-interactive install audit"
        elif "pacman" in pms:
            cmd = "pacman -Sy --noconfirm audit"
        elif "emerge" in pms:
            cmd = "PAGER=cat emerge --ask=n sys-process/audit"
        elif "apk" in pms:
            cmd = "apk update && apk add audit"
        elif "pkg" in pms:
            pass
        elif "slackpkg" in pms or "sbopkg" in pms:
            # Audit is in SBo for Slackware
            if "sbopkg" in pms:
                cmd = "sbopkg -B -e -i audit"
            else:
                cmd = "echo 'audit not in base slackware; install via sbopkg if available' && false"
            
        if cmd:
            try:
                conn.sudo(cmd, hide=True)
                
                # Enable service
                enable_cmd = self._get_service_enable_cmd("auditd")
                conn.sudo(f"{enable_cmd} && {self._get_service_restart_cmd('auditd')}", warn=True, hide=True)

                return HardeningResult(success=True, command="install_auditd", description="Install auditd", output="Installed and enabled")
            except Exception as e:
                return HardeningResult(success=False, command="install_auditd", description="Install auditd", error=str(e))
                
        return HardeningResult(success=False, command="install_auditd", description="Install auditd", error=f"No supported package manager found in {pms}")

    def _configure_rsyslog(self) -> List[HardeningCommand]:
        """Configure rsyslog for Linux systems"""
        commands = []
        
        # Backup original rsyslog configuration
        commands.append(HardeningCommand(
            command="cp /etc/rsyslog.conf /etc/rsyslog.conf.backup.$(date +%Y%m%d_%H%M%S)",
            description="Backup rsyslog configuration",
            check_command="test -f /etc/rsyslog.conf && echo exists",
            requires_sudo=True
        ))
        
        # Read config from file
        rsyslog_config = self._read_config_file("rsyslog.conf")
        
        if rsyslog_config:
            commands.append(HardeningCommand(
                command=f'cat > /etc/rsyslog.d/ccdc-security.conf << "EOF"\n{rsyslog_config}\nEOF',
                description="Create CCDC security logging configuration",
                check_command="test -f /etc/rsyslog.d/ccdc-security.conf && echo exists",
                requires_sudo=True
            ))
        
        # Set proper permissions on rsyslog config files
        commands.append(HardeningCommand(
            command="chmod 644 /etc/rsyslog.d/ccdc-security.conf",
            description="Set permissions on rsyslog configuration",
            requires_sudo=True
        ))
        
        # Create log directories if they don't exist
        commands.append(HardeningCommand(
            command="mkdir -p /var/log && touch /var/log/auth.log /var/log/kern.log /var/log/daemon.log /var/log/ssh.log /var/log/sudo.log",
            description="Create security log files",
            requires_sudo=True
        ))
        
        # Set proper permissions on log files
        commands.append(HardeningCommand(
            command="chmod 640 /var/log/auth.log /var/log/secure /var/log/ssh.log /var/log/sudo.log 2>/dev/null || true",
            description="Set restrictive permissions on security logs",
            requires_sudo=True
        ))
        
        # Restart rsyslog to apply configuration
        commands.append(HardeningCommand(
            command=self._get_service_restart_cmd("rsyslog"),
            description="Restart rsyslog service",
            requires_sudo=True
        ))
        
        return commands
    
    def _configure_journald(self) -> List[HardeningCommand]:
        """Configure systemd journald"""
        commands = []
        
        # Create journald configuration directory
        commands.append(HardeningCommand(
            command="mkdir -p /etc/systemd/journald.conf.d",
            description="Create journald configuration directory",
            check_command="test -d /etc/systemd/journald.conf.d && echo exists",
            requires_sudo=True
        ))
        
        # Read config from file
        journald_config = self._read_config_file("journald.conf")
        
        if journald_config:
            commands.append(HardeningCommand(
                command=f'cat > /etc/systemd/journald.conf.d/ccdc.conf << "EOF"\n{journald_config}\nEOF',
                description="Configure systemd journald",
                check_command="test -f /etc/systemd/journald.conf.d/ccdc.conf && echo exists",
                requires_sudo=True
            ))
        
        # Restart journald to apply configuration (IF it is running/present)
        # We only try to restart journald if systemd is the init system or if it's active
        commands.append(HardeningCommand(
            command=f"systemctl is-active systemd-journald >/dev/null 2>&1 && {self._get_service_restart_cmd('systemd-journald')} || echo 'systemd-journald not active'",
            description="Restart systemd-journald service (if active)",
            requires_sudo=True
        ))
        
        return commands
    
    def _configure_auditd(self) -> List[HardeningCommand]:
        """Configure auditd for security auditing"""
        commands = []
        
        # Read config
        audit_rules = self._read_config_file("audit.rules")
        
        if audit_rules:
            commands.append(HardeningCommand(
                command=f'test -d /etc/audit && cat > /etc/audit/rules.d/ccdc.rules << "EOF"\n{audit_rules}\nEOF || echo "auditd not installed"',
                description="Configure audit rules for security monitoring",
                check_command="test -f /etc/audit/rules.d/ccdc.rules && echo exists || echo not_applicable",
                requires_sudo=True
            ))
        
        # Load audit rules
        commands.append(HardeningCommand(
            command="which auditctl >/dev/null && auditctl -R /etc/audit/rules.d/ccdc.rules || echo 'auditctl not available'",
            description="Load audit rules",
            requires_sudo=True
        ))
        
        # Restart auditd
        # Fix: don't rely on 'systemctl is-active' which fails on non-systemd distros
        commands.append(HardeningCommand(
            command=f"(pidof auditd >/dev/null || pgrep -x auditd >/dev/null) && {self._get_service_restart_cmd('auditd')} || echo 'auditd not running, skipping restart'",
            description="Restart auditd service",
            requires_sudo=True
        ))
        
        return commands
    
    def _configure_logrotate(self) -> List[HardeningCommand]:
        """Configure log rotation"""
        commands = []
        
        # Read config
        logrotate_config = self._read_config_file("logrotate.conf")
        
        if logrotate_config:
            commands.append(HardeningCommand(
                command=f'cat > /etc/logrotate.d/ccdc-security << "EOF"\n{logrotate_config}\nEOF',
                description="Configure log rotation for security logs",
                check_command="test -f /etc/logrotate.d/ccdc-security && echo exists",
                requires_sudo=True
            ))
        
        return commands
    
    def _configure_security_logging(self) -> List[HardeningCommand]:
        """Configure additional security logging"""
        commands = []
        
        # Enable process accounting if available
        commands.append(HardeningCommand(
            command="which accton >/dev/null && accton /var/log/pacct || echo 'process accounting not available'",
            description="Enable process accounting",
            requires_sudo=True
        ))
        
        # Configure bash history logging
        commands.append(HardeningCommand(
            command='echo "export HISTTIMEFORMAT=\'%F %T \'" >> /etc/bash.bashrc',
            description="Enable bash history timestamps",
            check_command="grep -q HISTTIMEFORMAT /etc/bash.bashrc && echo exists",
            requires_sudo=True
        ))
        
        commands.append(HardeningCommand(
            command='echo "export HISTSIZE=10000" >> /etc/bash.bashrc',
            description="Increase bash history size",
            check_command="grep -q 'HISTSIZE=10000' /etc/bash.bashrc && echo exists",
            requires_sudo=True
        ))
        
        return commands
    
    def _configure_bsd_syslog(self) -> List[HardeningCommand]:
        """Configure BSD syslogd"""
        commands = []
        
        # Backup original syslog configuration
        commands.append(HardeningCommand(
            command="cp /etc/syslog.conf /etc/syslog.conf.backup.$(date +%Y%m%d_%H%M%S)",
            description="Backup BSD syslog configuration",
            check_command="test -f /etc/syslog.conf && echo exists",
            requires_sudo=True
        ))
        
        # Read config
        bsd_syslog_config = self._read_config_file("bsd_syslog.conf")
        
        if bsd_syslog_config:
            commands.append(HardeningCommand(
                command=f'cat > /etc/syslog.conf << "EOF"\n{bsd_syslog_config}\nEOF',
                description="Configure BSD syslog",
                check_command="test -f /etc/syslog.conf && echo exists",
                requires_sudo=True
            ))
        
        # Create log files
        commands.append(HardeningCommand(
            command="touch /var/log/auth.log /var/log/authpriv /var/log/daemon.log /var/log/kern.log /var/log/ssh.log",
            description="Create BSD log files",
            requires_sudo=True
        ))
        
        # Set permissions on log files
        commands.append(HardeningCommand(
            command="chmod 640 /var/log/auth.log /var/log/authpriv /var/log/security /var/log/ssh.log",
            description="Set restrictive permissions on security logs",
            requires_sudo=True
        ))
        
        # Restart syslogd
        commands.append(HardeningCommand(
            command=self._get_service_restart_cmd("syslogd"),
            description="Restart BSD syslogd service",
            requires_sudo=True
        ))
        
        return commands
    
    def _configure_newsyslog(self) -> List[HardeningCommand]:
        """Configure BSD newsyslog (log rotation)"""
        commands = []
        
        # Read config
        newsyslog_entries = self._read_config_file("bsd_newsyslog.conf")
        
        if newsyslog_entries:
            commands.append(HardeningCommand(
                command=f'echo "{newsyslog_entries}" >> /etc/newsyslog.conf',
                description="Configure BSD log rotation",
                check_command="grep -q 'CCDC Security Log Rotation' /etc/newsyslog.conf && echo exists",
                requires_sudo=True
            ))
        
        return commands
    
    def _configure_bsd_security_logging(self) -> List[HardeningCommand]:
        """Configure additional BSD security logging"""
        commands = []
        
        # Enable process accounting on BSD
        commands.append(HardeningCommand(
            command="accton /var/account/acct 2>/dev/null || echo 'process accounting not configured'",
            description="Enable BSD process accounting",
            requires_sudo=True
        ))
        
        # Configure shell history for BSD
        commands.append(HardeningCommand(
            command='echo "set history = 10000" >> /etc/csh.cshrc',
            description="Increase csh history size",
            check_command="grep -q 'set history = 10000' /etc/csh.cshrc && echo exists",
            requires_sudo=True
        ))
        
        return commands
    
    def is_applicable(self) -> bool:
        """This module is applicable to Linux and BSD systems"""
        try:
            os_family = OSFamily(self.os_family)
            # Applicable to everything except maybe Windows (which isn't in OSFamily yet)
            return True
        except ValueError:
            return True
    
    def apply_all(self, dry_run: bool = False):
        """Apply all hardening commands - write commands to file to reduce stdout noise"""
        import logging
        from pathlib import Path
        from datetime import datetime
        
        logger = logging.getLogger(__name__)
        
        if not self.is_applicable():
            logger.info(f"Module {self.get_name()} is not applicable to this system")
            return []
        
        commands = self.get_commands()
        
        # Write all commands to a timestamped file for reference
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = Path(f"/tmp/ccdc_logging_commands_{self.server_info.hostname}_{timestamp}.txt")
        try:
            with open(log_file, 'w') as f:
                f.write(f"CCDC Logging Setup Commands for {self.server_info.hostname}\n")
                f.write("=" * 60 + "\n\n")
                for i, cmd in enumerate(commands, 1):
                    f.write(f"Command {i}: {cmd.description}\n")
                    if isinstance(cmd, PythonAction):
                         f.write(f"Type: PythonAction ({cmd.function.__name__})\n")
                    else:
                         f.write(f"Command: {cmd.command}\n")
                         f.write(f"Check command: {cmd.check_command or 'None'}\n")
                    f.write(f"Requires sudo: {cmd.requires_sudo}\n")
                    f.write("-" * 40 + "\n\n")
            logger.info(f"Commands written to: {log_file}")
        except Exception as e:
            logger.warning(f"Failed to write log file: {e}")
        
        logger.info(f"Executing {len(commands)} logging configuration commands...")
        
        for i, cmd in enumerate(commands, 1):
            if dry_run:
                logger.info(f"[{i}/{len(commands)}] DRY RUN: {cmd.description}")
                self.results.append(HardeningResult(
                    success=True,
                    command=cmd.command if not isinstance(cmd, PythonAction) else cmd.function.__name__,
                    description=cmd.description,
                    output="DRY RUN - not executed",
                    already_applied=False
                ))
            else:
                logger.info(f"[{i}/{len(commands)}] {cmd.description}")
                result = self.apply_command(cmd)
                self.results.append(result)
                
                if result.success:
                    if result.already_applied:
                        logger.info(f"  ✓ Already applied")
                    else:
                        logger.info(f"  ✓ Success")
                else:
                    logger.error(f"  ✗ Failed: {result.error}")
        
        logger.info(f"Logging setup completed. Details in: {log_file}")
        return self.results