"""
Logging Setup Module
Configures rsyslog, auditd, and other logging mechanisms using external configuration files.

Uses Ansible for cross-distro package installation, then configures via SSH commands.
"""

import logging
import os
import subprocess
from pathlib import Path

from ..discovery import OSFamily
from ..service_manager import ServiceManager
from .base import CommandAction, HardeningModule, HardeningResult, PythonAction

logger = logging.getLogger(__name__)

# Path to ansible directory (relative to this file)
ANSIBLE_DIR = Path(__file__).parent.parent.parent / "ansible"


class LoggingHardeningModule(HardeningModule):
    """Configure comprehensive logging for CCDC scenarios"""

    def get_name(self) -> str:
        return "logging_hardening"

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

        with open(config_path) as f:
            return f.read()

    def _get_service_manager(self) -> ServiceManager:
        """Get a ServiceManager instance configured for this system."""
        # Determine init system from server_info if available
        init_system = getattr(self.server_info, "init_system", ServiceManager.UNKNOWN)
        available_commands = getattr(self.server_info, "available_commands", [])
        return ServiceManager(
            init_system=init_system, available_commands=available_commands
        )

    def _get_service_restart_cmd(self, service: str) -> str:
        """Get robust restart command for a service (uses fallback chain for safety)."""
        # Use fallback chain to ensure maximum compatibility
        return self._get_service_manager()._fallback_restart(service)

    def _get_service_enable_cmd(self, service: str) -> str:
        """Get robust enable command for a service."""
        svc_mgr = self._get_service_manager()
        # Use direct method if init system known, otherwise fallback
        if svc_mgr.init_system != ServiceManager.UNKNOWN:
            return svc_mgr.enable(service)
        return (
            f"(systemctl enable {service} 2>/dev/null || "
            f"rc-update add {service} default 2>/dev/null || "
            f"chkconfig {service} on 2>/dev/null || "
            f"sysrc {service}_enable=YES 2>/dev/null || "
            f"echo 'Failed to enable {service}')"
        )

    def _get_service_is_running_cmd(self, service: str) -> str:
        """Check if a service is running across init systems."""
        return self._get_service_manager().is_running(service)

    def _get_service_start_or_restart_cmd(self, service: str) -> str:
        """Start a service if stopped, restart if already running."""
        svc_mgr = self._get_service_manager()
        return svc_mgr.start_or_restart(service)

    def _get_ansible_hostname_for_ip(self, ip: str) -> str:
        """Look up the Ansible inventory hostname for a given IP address"""
        import yaml

        inventory_file = ANSIBLE_DIR / "inventory" / "hosts.yaml"

        if not inventory_file.exists():
            return ip

        try:
            with open(inventory_file) as f:
                inventory = yaml.safe_load(f)

            # Search through all groups to find host with matching ansible_host
            def search_hosts(node):
                if isinstance(node, dict):
                    # Check if this is a host entry with ansible_host
                    if "ansible_host" in node and node["ansible_host"] == ip:
                        return True
                    # Recurse into children and hosts
                    for key, value in node.items():
                        if key == "hosts" and isinstance(value, dict):
                            for hostname, host_vars in value.items():
                                if (
                                    isinstance(host_vars, dict)
                                    and host_vars.get("ansible_host") == ip
                                ):
                                    return hostname
                        result = search_hosts(value)
                        if result and result is not True:
                            return result
                return None

            result = search_hosts(inventory)
            if result and result is not True:
                return result
        except Exception as e:
            logger.debug(f"Could not look up hostname for {ip}: {e}")

        return ip

    def _install_packages_via_ansible(self, conn, server_info) -> HardeningResult:
        """
        Use Ansible to install logging packages (rsyslog, auditd, logrotate).
        This handles cross-distro package name differences automatically.
        """
        host = server_info.host if hasattr(server_info, "host") else conn.host
        friendly_name = getattr(server_info, "friendly_name", None)

        # Look up the Ansible inventory hostname by IP if we don't have a friendly name
        if not friendly_name:
            friendly_name = self._get_ansible_hostname_for_ip(host)

        # Ansible inventory uses friendly_name as host key
        limit_target = friendly_name if friendly_name != host else host
        display_name = friendly_name or host

        logger.info(
            f"Installing logging packages via Ansible on {display_name} (limit: {limit_target})..."
        )

        # First sync configs to ensure inventory is up to date
        sync_result = subprocess.run(
            ["python3", "generate_configs.py"],
            cwd=str(ANSIBLE_DIR),
            capture_output=True,
            text=True,
        )

        if sync_result.returncode != 0:
            logger.warning(f"Config sync warning: {sync_result.stderr}")

        env = os.environ.copy()
        env["ANSIBLE_CONFIG"] = str(ANSIBLE_DIR / "ansible.cfg")
        env["ANSIBLE_HOST_KEY_CHECKING"] = "False"

        # Use the known root SSH key for ansible
        ssh_key_path = str(
            Path(__file__).parent.parent.parent / "keys" / "test-root-key.private"
        )

        result = subprocess.run(
            [
                "ansible-playbook",
                "playbooks/install_logging_packages.yaml",
                "--limit",
                limit_target,
                "--private-key",
                ssh_key_path,
                "-v",
            ],
            cwd=str(ANSIBLE_DIR),
            env=env,
            capture_output=True,
            text=True,
            timeout=900,  # 15 minute timeout
        )

        if result.returncode == 0:
            logger.info(f"Ansible package installation completed for {display_name}")
            return HardeningResult(
                success=True,
                command="ansible install_logging_packages",
                description="Install logging packages via Ansible",
                output="Packages installed successfully",
            )
        else:
            # Log the error but don't fail - packages might already be installed
            # or the host might not be in Ansible inventory
            logger.warning(f"Ansible installation returned non-zero for {display_name}")
            logger.debug(f"Ansible stdout: {result.stdout}")
            logger.debug(f"Ansible stderr: {result.stderr}")

            # Check if packages are available despite Ansible failure
            rsyslog_ok = conn.run("command -v rsyslogd", warn=True, hide=True).ok
            auditd_ok = conn.run("command -v auditctl", warn=True, hide=True).ok

            if rsyslog_ok or auditd_ok:
                return HardeningResult(
                    success=True,
                    command="ansible install_logging_packages",
                    description="Install logging packages via Ansible",
                    output=f"Packages present (rsyslog: {rsyslog_ok}, auditd: {auditd_ok})",
                )

            return HardeningResult(
                success=False,
                command="ansible install_logging_packages",
                description="Install logging packages via Ansible",
                error=f"Ansible failed and packages not found. stderr: {result.stderr[:500]}",
            )

    def get_commands(self) -> list[CommandAction]:
        try:
            os_family = OSFamily(self.os_family)
        except ValueError:
            os_family = OSFamily.UNKNOWN

        if os_family in [
            OSFamily.FREEBSD,
            OSFamily.OPENBSD,
            OSFamily.NETBSD,
            OSFamily.BSDGENERIC,
        ]:
            return self._get_bsd_commands()
        else:
            return self._get_linux_commands()

    def _get_linux_commands(self) -> list[CommandAction]:
        """Commands for Linux systems"""
        commands = []

        # Step 1: Install all logging packages via Ansible (handles cross-distro differences)
        commands.append(
            PythonAction(
                function=self._install_packages_via_ansible,
                description="Install logging packages via Ansible (rsyslog, auditd, logrotate)",
                requires_sudo=False,  # Ansible handles sudo internally
            )
        )

        # Step 2: Configure rsyslog (Fabric handles configuration)
        commands.extend(self._configure_rsyslog())

        # Step 3: Configure systemd journald (if systemd is present)
        commands.extend(self._configure_journald())

        # Step 4: Configure auditd for security auditing (Fabric handles configuration)
        commands.extend(self._configure_auditd())

        # Configure logrotate
        commands.extend(self._configure_logrotate())

        # Configure additional security logging
        commands.extend(self._configure_security_logging())

        return commands

    def _get_bsd_commands(self) -> list[CommandAction]:
        """Commands for BSD systems"""
        commands = []

        # Configure BSD syslogd
        commands.extend(self._configure_bsd_syslog())

        # Ensure BSD Audit is enabled (PythonAction)
        commands.append(
            PythonAction(
                function=self._ensure_bsd_audit_enabled,
                description="Ensure BSD Audit is enabled",
                requires_sudo=True,
            )
        )

        # Configure BSD Audit
        commands.extend(self._configure_bsd_audit())

        # Configure newsyslog (BSD log rotation)
        commands.extend(self._configure_newsyslog())

        # Configure BSD security logging
        commands.extend(self._configure_bsd_security_logging())

        return commands

    def _ensure_rsyslog_installed(self, conn, server_info):
        """Install rsyslog if missing"""
        if conn.run("command -v rsyslogd", warn=True, hide=True).ok:
            return HardeningResult(
                success=True,
                command="check_rsyslog",
                description="Check rsyslog",
                output="Already installed",
            )

        logger.info("Installing rsyslog...")
        pms = server_info.package_managers
        cmd = None

        if "dnf" in pms:
            cmd = "dnf install -y rsyslog"
        elif "yum" in pms:
            cmd = "yum install -y rsyslog"
        elif "apt" in pms:
            cmd = "DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog"
        elif "zypper" in pms:
            cmd = "zypper --non-interactive install rsyslog"
        elif "pacman" in pms:
            cmd = "pacman -Sy --noconfirm rsyslog"
        elif "emerge" in pms:
            cmd = "PAGER=cat emerge --ask=n app-admin/rsyslog"
        elif "apk" in pms:
            cmd = "apk update && apk add rsyslog"
        elif "pkg" in pms:
            cmd = "pkg install -y rsyslog"
        elif "slackpkg" in pms or "sbopkg" in pms:
            if "sbopkg" in pms:
                cmd = "sbopkg -B -e -i rsyslog"
            else:
                cmd = "echo 'rsyslog not in base slackware; install via sbopkg if available' && false"

        if cmd:
            try:
                conn.run(cmd, hide=True)
                enable_cmd = self._get_service_enable_cmd("rsyslog")
                if conn.run("command -v rsyslogd", warn=True, hide=True).ok:
                    conn.run(
                        f"{enable_cmd} && {self._get_service_restart_cmd('rsyslog')}",
                        warn=True,
                        hide=True,
                    )
                return HardeningResult(
                    success=True,
                    command="install_rsyslog",
                    description="Install rsyslog",
                    output="Installed and enabled",
                )
            except Exception as e:
                return HardeningResult(
                    success=False,
                    command="install_rsyslog",
                    description="Install rsyslog",
                    error=str(e),
                )

        return HardeningResult(
            success=False,
            command="install_rsyslog",
            description="Install rsyslog",
            error=f"No supported package manager found in {pms}",
        )

    def _ensure_auditd_installed(self, conn, server_info):
        """Install auditd if missing (Linux only)"""
        if conn.run("command -v auditctl", warn=True, hide=True).ok:
            return HardeningResult(
                success=True,
                command="check_auditd",
                description="Check auditd",
                output="Already installed",
            )

        logger.info("Installing auditd...")
        pms = server_info.package_managers
        cmd = None

        if "dnf" in pms or "yum" in pms:
            cmd = "yum install -y audit"
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
            if "sbopkg" in pms:
                cmd = "sbopkg -B -e -i audit"
            else:
                cmd = "echo 'audit not in base slackware; install via sbopkg if available' && false"

        if cmd:
            try:
                conn.run(cmd, hide=True)
                enable_cmd = self._get_service_enable_cmd("auditd")
                conn.run(
                    f"{enable_cmd} && {self._get_service_restart_cmd('auditd')}",
                    warn=True,
                    hide=True,
                )
                return HardeningResult(
                    success=True,
                    command="install_auditd",
                    description="Install auditd",
                    output="Installed and enabled",
                )
            except Exception as e:
                return HardeningResult(
                    success=False,
                    command="install_auditd",
                    description="Install auditd",
                    error=str(e),
                )

        return HardeningResult(
            success=False,
            command="install_auditd",
            description="Install auditd",
            error=f"No supported package manager found in {pms}",
        )

    def _ensure_bsd_audit_enabled(self, conn, server_info):
        """Enable Audit on FreeBSD/HardenedBSD"""
        # FreeBSD audit is usually base, check for auditd binary
        if not conn.run("command -v auditd", warn=True, hide=True).ok:
            return HardeningResult(
                success=False,
                command="check_bsd_audit",
                description="Check BSD Audit",
                error="auditd binary not found (is this FreeBSD?)",
            )

        try:
            # Enable in rc.conf
            conn.run("sysrc auditd_enable=YES", hide=True)

            # Start if not running
            conn.run(
                "service auditd start 2>/dev/null || service auditd onestart 2>/dev/null || true",
                hide=True,
            )

            return HardeningResult(
                success=True,
                command="enable_bsd_audit",
                description="Enable BSD Audit",
                output="Enabled in rc.conf and started",
            )
        except Exception as e:
            return HardeningResult(
                success=False,
                command="enable_bsd_audit",
                description="Enable BSD Audit",
                error=str(e),
            )

    def _configure_rsyslog(self) -> list[CommandAction]:
        """Configure rsyslog for Linux systems"""
        commands = []

        commands.append(
            CommandAction(
                command="test -f /etc/rsyslog.conf && cp /etc/rsyslog.conf /etc/rsyslog.conf.backup.$(date +%Y%m%d_%H%M%S) || echo 'No default rsyslog.conf to backup'",
                description="Backup rsyslog configuration",
                check_command="test ! -f /etc/rsyslog.conf -o -f /etc/rsyslog.conf.backup.* 2>/dev/null && echo exists",
                requires_sudo=True,
            )
        )

        rsyslog_config = self._read_config_file("rsyslog.conf")

        if rsyslog_config:
            commands.append(
                CommandAction(
                    command=f'test -d /etc/rsyslog.d && cat > /etc/rsyslog.d/ccdc-security.conf << "EOF"\n{rsyslog_config}\nEOF || echo "rsyslog not installed"',
                    description="Create CCDC security logging configuration",
                    check_command="test ! -d /etc/rsyslog.d -o -f /etc/rsyslog.d/ccdc-security.conf && echo exists",
                    requires_sudo=True,
                )
            )

        commands.append(
            CommandAction(
                command="test -f /etc/rsyslog.d/ccdc-security.conf && chmod 644 /etc/rsyslog.d/ccdc-security.conf || true",
                description="Set permissions on rsyslog configuration",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command="mkdir -p /var/log && touch /var/log/auth.log /var/log/kern.log /var/log/daemon.log /var/log/ssh.log /var/log/sudo.log",
                description="Create security log files",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command="chmod 640 /var/log/auth.log /var/log/secure /var/log/ssh.log /var/log/sudo.log 2>/dev/null || true",
                description="Set restrictive permissions on security logs",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command=f"command -v rsyslogd >/dev/null && ({self._get_service_enable_cmd('rsyslog')}) || echo 'rsyslog not installed, skipping'",
                description="Enable rsyslog service at boot",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command=f"command -v rsyslogd >/dev/null && ({self._get_service_restart_cmd('rsyslog')}) || echo 'rsyslog not installed, skipping'",
                description="Restart rsyslog service",
                requires_sudo=True,
            )
        )

        return commands

    def _configure_journald(self) -> list[CommandAction]:
        """Configure systemd journald"""
        commands = []

        commands.append(
            CommandAction(
                command="mkdir -p /etc/systemd/journald.conf.d",
                description="Create journald configuration directory",
                check_command="test -d /etc/systemd/journald.conf.d && echo exists",
                requires_sudo=True,
            )
        )

        journald_config = self._read_config_file("journald.conf")

        if journald_config:
            commands.append(
                CommandAction(
                    command=f'cat > /etc/systemd/journald.conf.d/ccdc.conf << "EOF"\n{journald_config}\nEOF',
                    description="Configure systemd journald",
                    check_command="test -f /etc/systemd/journald.conf.d/ccdc.conf && echo exists",
                    requires_sudo=True,
                )
            )

        commands.append(
            CommandAction(
                command=f"systemctl is-active systemd-journald >/dev/null 2>&1 && {self._get_service_restart_cmd('systemd-journald')} || echo 'systemd-journald not active'",
                description="Restart systemd-journald service (if active)",
                requires_sudo=True,
            )
        )

        return commands

    def _configure_auditd(self) -> list[CommandAction]:
        """Configure auditd for security auditing (Linux)"""
        commands = []

        audit_rules = self._read_config_file("audit.rules")
        
        # Read the path preparation script
        path_prep_script_path = Path(__file__).parent.parent.parent / "scripts" / "all" / "prepare_auditd_paths.sh"
        if path_prep_script_path.exists():
            with open(path_prep_script_path) as f:
               path_prep_script = f.read()

            commands.append(
                CommandAction(
                    command=f'cat > /tmp/prepare_auditd_paths.sh << "EOF"\n{path_prep_script}\nEOF',
                    description="Upload auditd path preparation script",
                    requires_sudo=True,
                )
            )

            commands.append(
                CommandAction(
                    command="chmod +x /tmp/prepare_auditd_paths.sh && /tmp/prepare_auditd_paths.sh",
                    description="Execute auditd path preparation script",
                    requires_sudo=True,
                )
            )

            commands.append(
                CommandAction(
                    command="rm -f /tmp/prepare_auditd_paths.sh",
                    description="Cleanup auditd path preparation script",
                    requires_sudo=True,
                )
            )
        else:
            logger.warning(f"Could not find prepare_auditd_paths.sh at {path_prep_script_path}")

        if audit_rules:
            commands.append(
                CommandAction(
                    command=f'mkdir -p /etc/audit/rules.d && cat > /etc/audit/rules.d/ccdc.rules << "EOF"\n{audit_rules}\nEOF',
                    description="Configure audit rules for security monitoring",
                    check_command="test -f /etc/audit/rules.d/ccdc.rules && echo exists",
                    requires_sudo=True,
                )
            )

        commands.append(
            CommandAction(
                command="command -v auditctl >/dev/null && auditctl -R /etc/audit/rules.d/ccdc.rules || echo 'auditctl not available'",
                description="Load audit rules",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command=f"test -d /etc/audit && {self._get_service_enable_cmd('auditd')} || echo 'auditd not installed'",
                description="Enable auditd service at boot",
                requires_sudo=True,
            )
        )

        # Start auditd if not running, restart if already running
        # Note: On RHEL/Fedora, auditd requires 'service auditd restart' - systemctl is refused
        commands.append(
            CommandAction(
                command=(
                    "test -d /etc/audit && ("
                    "service auditd restart 2>/dev/null || "
                    "systemctl restart auditd 2>/dev/null || "
                    "rc-service auditd restart 2>/dev/null || "
                    "/etc/init.d/auditd restart 2>/dev/null || "
                    "echo 'auditd restart failed or not installed'"
                    ") || echo 'auditd not installed'"
                ),
                description="Start or restart auditd service",
                requires_sudo=True,
            )
        )

        return commands

    def _configure_bsd_audit(self) -> list[CommandAction]:
        """Configure BSD Audit (audit_control)"""
        commands = []

        # Read config (You need to create a bsd_audit_control file in configs dir)
        audit_control = self._read_config_file("bsd_audit_control")

        if audit_control:
            commands.append(
                CommandAction(
                    command="cp /etc/security/audit_control /etc/security/audit_control.backup",
                    description="Backup audit_control",
                    requires_sudo=True,
                )
            )

            commands.append(
                CommandAction(
                    command=f'cat > /etc/security/audit_control << "EOF"\n{audit_control}\nEOF',
                    description="Configure BSD audit_control",
                    check_command="grep -q 'CCDC' /etc/security/audit_control && echo exists",
                    requires_sudo=True,
                )
            )

            # Reload audit triggers
            commands.append(
                CommandAction(
                    command="service auditd refresh || service auditd reload",
                    description="Refresh BSD auditd",
                    requires_sudo=True,
                )
            )

        return commands

    def _configure_logrotate(self) -> list[CommandAction]:
        """Configure log rotation"""
        commands = []

        logrotate_config = self._read_config_file("logrotate.conf")

        if logrotate_config:
            commands.append(
                CommandAction(
                    command=f'cat > /etc/logrotate.d/ccdc-security << "EOF"\n{logrotate_config}\nEOF',
                    description="Configure log rotation for security logs",
                    check_command="test -f /etc/logrotate.d/ccdc-security && echo exists",
                    requires_sudo=True,
                )
            )

        return commands

    def _configure_security_logging(self) -> list[CommandAction]:
        """Configure additional security logging"""
        commands = []

        # Enable process accounting IF auditd is NOT present/running
        # logic: if auditctl exists OR auditd is running, skip accton.
        # This prevents duplicate/conflicting accounting methods.
        accton_cmd = (
            "if ! command -v auditctl >/dev/null && ! pgrep -x auditd >/dev/null; then "
            "  if command -v accton >/dev/null; then "
            "    mkdir -p /var/log && touch /var/log/pacct && accton /var/log/pacct; "
            "  else echo 'process accounting not available'; fi; "
            "else echo 'auditd present, skipping accton'; fi"
        )

        commands.append(
            CommandAction(
                command=accton_cmd,
                description="Enable process accounting (if auditd is missing)",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command="echo \"export HISTTIMEFORMAT='%F %T '\" >> /etc/bash.bashrc",
                description="Enable bash history timestamps",
                check_command="grep -q HISTTIMEFORMAT /etc/bash.bashrc && echo exists",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command='echo "export HISTSIZE=10000" >> /etc/bash.bashrc',
                description="Increase bash history size",
                check_command="grep -q 'HISTSIZE=10000' /etc/bash.bashrc && echo exists",
                requires_sudo=True,
            )
        )

        return commands

    def _configure_bsd_syslog(self) -> list[CommandAction]:
        """Configure BSD syslogd"""
        commands = []

        commands.append(
            CommandAction(
                command="cp /etc/syslog.conf /etc/syslog.conf.backup.$(date +%Y%m%d_%H%M%S)",
                description="Backup BSD syslog configuration",
                check_command="test -f /etc/syslog.conf && echo exists",
                requires_sudo=True,
            )
        )

        bsd_syslog_config = self._read_config_file("bsd_syslog.conf")

        if bsd_syslog_config:
            commands.append(
                CommandAction(
                    command=f'cat > /etc/syslog.conf << "EOF"\n{bsd_syslog_config}\nEOF',
                    description="Configure BSD syslog",
                    check_command="test -f /etc/syslog.conf && echo exists",
                    requires_sudo=True,
                )
            )

        commands.append(
            CommandAction(
                command="touch /var/log/auth.log /var/log/authpriv /var/log/daemon.log /var/log/kern.log /var/log/ssh.log",
                description="Create BSD log files",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command="chmod 640 /var/log/auth.log /var/log/authpriv /var/log/security /var/log/ssh.log",
                description="Set restrictive permissions on security logs",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command=self._get_service_restart_cmd("syslogd"),
                description="Restart BSD syslogd service",
                requires_sudo=True,
            )
        )

        return commands

    def _configure_newsyslog(self) -> list[CommandAction]:
        """Configure BSD newsyslog (log rotation)"""
        commands = []

        newsyslog_entries = self._read_config_file("bsd_newsyslog.conf")

        if newsyslog_entries:
            commands.append(
                CommandAction(
                    command=f'echo "{newsyslog_entries}" >> /etc/newsyslog.conf',
                    description="Configure BSD log rotation",
                    check_command="grep -q 'CCDC Security Log Rotation' /etc/newsyslog.conf && echo exists",
                    requires_sudo=True,
                )
            )

        return commands

    def _configure_bsd_security_logging(self) -> list[CommandAction]:
        """Configure additional BSD security logging"""
        commands = []

        # Enable process accounting on BSD IF Audit is NOT enabled
        # We check if auditd is running/enabled using 'service auditd status'
        accton_cmd = (
            "if ! service auditd status >/dev/null 2>&1; then "
            "  mkdir -p /var/account && touch /var/account/acct && "
            "  accton /var/account/acct 2>/dev/null || echo 'process accounting not configured'; "
            "else echo 'BSD Audit present, skipping accton'; fi"
        )

        commands.append(
            CommandAction(
                command=accton_cmd,
                description="Enable BSD process accounting (if auditd is missing)",
                requires_sudo=True,
            )
        )

        commands.append(
            CommandAction(
                command='echo "set history = 10000" >> /etc/csh.cshrc',
                description="Increase csh history size",
                check_command="grep -q 'set history = 10000' /etc/csh.cshrc && echo exists",
                requires_sudo=True,
            )
        )

        return commands

    def is_applicable(self) -> bool:
        """This module is applicable to Linux and BSD systems"""
        try:
            OSFamily(self.os_family)
            return True
        except ValueError:
            return True

    def apply_all(self, dry_run: bool = False):
        """Apply all hardening commands - write commands to file to reduce stdout noise"""
        import logging
        from datetime import datetime
        from pathlib import Path

        logger = logging.getLogger(__name__)
        module_name = self.get_name()

        if not self.is_applicable():
            logger.info(f"Module {module_name} is not applicable to this system")
            return []

        commands = self.get_commands()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = Path(
            f"/tmp/ccdc_logging_commands_{self.server_info.hostname}_{timestamp}.txt"
        )
        try:
            with open(log_file, "w") as f:
                f.write(
                    f"CCDC Logging Setup Commands for {self.server_info.hostname}\n"
                )
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

        logger.info(f"Executing {len(commands)} commands...")

        for i, cmd in enumerate(commands, 1):
            if dry_run:
                logger.info(
                    f"[DRY RUN] {cmd.description}"
                )
                self.results.append(
                    HardeningResult(
                        success=True,
                        command=cmd.command
                        if not isinstance(cmd, PythonAction)
                        else cmd.function.__name__,
                        description=cmd.description,
                        output="DRY RUN - not executed",
                        already_applied=False,
                    )
                )
            else:
                result = self.apply_action(cmd)
                self.results.append(result)

                if result.success:
                    if result.already_applied:
                        logger.info(
                            f"{cmd.description} → ✓ (already applied)"
                        )
                    else:
                        logger.info(
                            f"{cmd.description} → ✓"
                        )
                else:
                    error_msg = result.error or "Unknown error"
                    logger.error(
                        f"{cmd.description} → ✗ {error_msg}"
                    )

        logger.info(f"Completed. Details in: {log_file}")
        return self.results
