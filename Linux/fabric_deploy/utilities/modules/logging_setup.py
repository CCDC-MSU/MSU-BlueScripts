"""
Linux

   * `/etc/rsyslog.conf.backup.$(date +%Y%m%d_%H%M%S)`: A backup of the original rsyslog configuration file.
   * `/etc/rsyslog.d/ccdc-security.conf`: configuration file for rsyslog that contains the logging rules.
   * `/var/log/messages`: General, non-critical system messages.
   * `/var/log/secure`: Privileged authentication and security-related messages.
   * `/var/log/maillog`: Logs from the mail server.
   * `/var/log/cron`: Logs related to scheduled tasks (cron jobs).
   * `/var/log/auth.log`: Detailed authentication and authorization events.
   * `/var/log/kern.log`: Messages from the Linux kernel.
   * `/var/log/daemon.log`: Logs from background services (daemons).
   * `/var/log/syslog`: A general-purpose log file for system events.
   * `/var/log/ssh.log`: All connection attempts and activities related to the SSH daemon.
   * `/var/log/sudo.log`: A log of all commands executed with sudo.
   * `/etc/systemd/journald.conf.d/ccdc.conf`: Configuration for the systemd journal, making logs persistent across reboots and enabling compression.
   * `/etc/audit/rules.d/ccdc.rules`: A set of rules for the auditd service to monitor file changes, privilege escalation, and other security-sensitive events.
   * `/etc/logrotate.d/ccdc-security`: Configuration for logrotate to manage and rotate the new security log files.
   * `/var/log/pacct`: Process accounting logs, which record every command executed on the system.
   * `/etc/bash.bashrc`: System-wide configuration for the bash shell, modified to add timestamps to command history.

  BSD

   * `/etc/syslog.conf.backup.$(date +%Y%m%d_%H%M%S)`: A backup of the original BSD syslog.conf file.
   * `/etc/syslog.conf`: The main configuration file for the syslogd daemon on BSD.
   * `/var/log/messages`: General system messages.
   * `/var/log/security`: Security-related events.
   * `/var/log/auth.log`: Authentication and authorization logs.
   * `/var/log/authpriv`: Privileged authentication logs.
   * `/var/log/maillog`: Mail server logs.
   * `/var/log/cron`: Logs from cron jobs.
   * `/var/log/daemon.log`: Logs from background services.
   * `/var/log/kern.log`: Kernel messages.
   * `/var/log/ssh.log`: Logs from the SSH daemon.
   * `/etc/newsyslog.conf`: Configuration for newsyslog (the BSD log rotator), modified to include the new security logs.
   * `/var/account/acct`: Process accounting logs.
   * `/etc/csh.cshrc`: System-wide configuration for the csh shell, modified to increase command history size.

"""

from typing import List
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily


class LoggingSetupModule(HardeningModule):
    """Configure comprehensive logging for CCDC scenarios"""
    
    def get_name(self) -> str:
        return "logging_setup"
    
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
        
        # Configure rsyslog (most common Linux syslog daemon)
        commands.extend(self._configure_rsyslog())
        
        # Configure systemd journald (if systemd is present)
        commands.extend(self._configure_journald())
        
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
        
        # Create enhanced rsyslog configuration
        rsyslog_config = '''
# CCDC Enhanced Logging Configuration
$ModLoad imuxsock # provides support for local system logging
$ModLoad imklog   # provides kernel logging support

# Enhanced logging rules
*.info;mail.none;authpriv.none;cron.none    /var/log/messages
authpriv.*                                  /var/log/secure
mail.*                                      /var/log/maillog
cron.*                                      /var/log/cron
*.emerg                                     :omusrmsg:*
uucp,news.crit                              /var/log/spooler
local7.*                                    /var/log/boot.log

# Security-focused logging
auth,authpriv.*                             /var/log/auth.log
kern.*                                      /var/log/kern.log
daemon.*                                    /var/log/daemon.log
syslog.*                                    /var/log/syslog

# Log failed login attempts
auth.info                                   /var/log/auth.log
authpriv.warning                            /var/log/secure

# Log all SSH connections
if $programname == 'sshd' then /var/log/ssh.log
& stop

# Log sudo usage
if $programname == 'sudo' then /var/log/sudo.log
& stop

# Forward critical messages to console
*.crit                                      /dev/console

# Include additional config files
$IncludeConfig /etc/rsyslog.d/*.conf
'''
        
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
            command="systemctl restart rsyslog 2>/dev/null || service rsyslog restart",
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
        
        # Configure journald for persistent logging
        journald_config = '''[Journal]
# Store logs persistently
Storage=persistent

# Compress logs to save space
Compress=yes

# Forward to syslog for compatibility
ForwardToSyslog=yes

# Set maximum log size (3GB)
SystemMaxUse=3G

# Keep logs for 30 days
MaxRetentionSec=2592000

# Rate limiting
RateLimitInterval=30s
RateLimitBurst=10000
'''
        
        commands.append(HardeningCommand(
            command=f'cat > /etc/systemd/journald.conf.d/ccdc.conf << "EOF"\n{journald_config}\nEOF',
            description="Configure systemd journald",
            check_command="test -f /etc/systemd/journald.conf.d/ccdc.conf && echo exists",
            requires_sudo=True
        ))
        
        # Restart journald to apply configuration
        commands.append(HardeningCommand(
            command="systemctl restart systemd-journald",
            description="Restart systemd-journald service",
            requires_sudo=True
        ))
        
        return commands
    
    def _configure_auditd(self) -> List[HardeningCommand]:
        """Configure auditd for security auditing"""
        commands = []
        
        # Check if auditd is available and configure it
        commands.append(HardeningCommand(
            command="which auditd >/dev/null && systemctl enable auditd || echo 'auditd not available'",
            description="Enable auditd service if available",
            requires_sudo=True
        ))
        
        # Create enhanced audit rules
        audit_rules = '''# CCDC Audit Rules for Security Monitoring

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Set failure mode to continue logging
-f 1

# Monitor file access
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k ssh_config_changes

# Monitor system configuration changes
-w /etc/hosts -p wa -k network_config
-w /etc/hostname -p wa -k hostname_changes
-w /etc/fstab -p wa -k fstab_changes
-w /etc/crontab -p wa -k crontab_changes

# Monitor login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k failed_logins

# Monitor privilege escalation
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

# Monitor network configuration
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket_created
-a always,exit -F arch=b32 -S socket -F a0=2 -k network_socket_created

# Monitor file deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k file_deletion
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k file_deletion

# Monitor process execution
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# Make rules immutable (restart required to change)
-e 2
'''
        
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
        commands.append(HardeningCommand(
            command="systemctl is-active auditd >/dev/null && systemctl restart auditd || echo 'auditd not running'",
            description="Restart auditd service",
            requires_sudo=True
        ))
        
        return commands
    
    def _configure_logrotate(self) -> List[HardeningCommand]:
        """Configure log rotation"""
        commands = []
        
        # Create logrotate configuration for security logs
        logrotate_config = '''/var/log/auth.log
/var/log/secure
/var/log/ssh.log
/var/log/sudo.log
{
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        /bin/kill -HUP `cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}

/var/log/kern.log
/var/log/daemon.log
{
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        /bin/kill -HUP `cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
'''
        
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
        
        # Enhanced BSD syslog configuration
        bsd_syslog_config = '''# CCDC Enhanced BSD Syslog Configuration
*.err;kern.warning;auth.notice;mail.crit		/dev/console
*.notice;authpriv.none;kern.debug;lpr.info;mail.crit;news.err	/var/log/messages
security.*					/var/log/security
auth.info;authpriv.info				/var/log/auth.log
authpriv.debug					/var/log/authpriv
mail.info					/var/log/maillog
lpr.info					/var/log/lpd-errs
ftp.info					/var/log/xferlog
cron.*						/var/log/cron
daemon.*					/var/log/daemon.log
kern.*						/var/log/kern.log
*.=debug					/var/log/debug.log
*.emerg						*

# SSH logging
daemon.info					/var/log/ssh.log

# Console messages
*.err						/dev/console
kern.warning					/dev/console

# Everyone gets emergency messages
*.emerg						*
'''
        
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
            command="service syslogd restart || /etc/rc.d/syslogd restart",
            description="Restart BSD syslogd service",
            requires_sudo=True
        ))
        
        return commands
    
    def _configure_newsyslog(self) -> List[HardeningCommand]:
        """Configure BSD newsyslog (log rotation)"""
        commands = []
        
        # Add entries to newsyslog.conf for our custom logs
        newsyslog_entries = '''# CCDC Security Log Rotation
/var/log/auth.log		644  30   *    24    Z
/var/log/authpriv		640  30   *    24    Z
/var/log/daemon.log		644  7    *    24    Z
/var/log/kern.log		644  7    *    24    Z
/var/log/ssh.log		644  30   *    24    Z
'''
        
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
            return os_family != OSFamily.DARWIN and self.server_info.os.distro.lower() != "unknown"
        except ValueError:
            return self.server_info.os.distro.lower() != "unknown"
    
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
        with open(log_file, 'w') as f:
            f.write(f"CCDC Logging Setup Commands for {self.server_info.hostname}\n")
            f.write("=" * 60 + "\n\n")
            for i, cmd in enumerate(commands, 1):
                f.write(f"Command {i}: {cmd.description}\n")
                f.write(f"Command: {cmd.command}\n")
                f.write(f"Requires sudo: {cmd.requires_sudo}\n")
                f.write(f"Check command: {cmd.check_command or 'None'}\n")
                f.write("-" * 40 + "\n\n")
        
        logger.info(f"Commands written to: {log_file}")
        logger.info(f"Executing {len(commands)} logging configuration commands...")
        
        for i, cmd in enumerate(commands, 1):
            if dry_run:
                logger.info(f"[{i}/{len(commands)}] DRY RUN: {cmd.description}")
                self.results.append({
                    'success': True,
                    'command': cmd.command,
                    'description': cmd.description,
                    'output': "DRY RUN - not executed"
                })
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