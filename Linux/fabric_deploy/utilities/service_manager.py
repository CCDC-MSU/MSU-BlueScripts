"""
Service management utilities for CCDC hardening framework.
Provides cross-platform service commands (systemd, OpenRC, SysVinit, BSD rc.d, etc.)

Similar to UserManager, this class generates shell commands for service operations
rather than executing them directly.
"""

import logging

logger = logging.getLogger(__name__)


class ServiceManager:
    """
    Cross-platform service management command generator.

    Similar to UserManager, this class provides methods that return shell commands
    for common service operations. It adapts to the available init system.

    Usage:
        svc_mgr = ServiceManager(init_system="systemd", available_commands=["systemctl"])
        restart_cmd = svc_mgr.restart("sshd")
        # Returns: "systemctl restart sshd"
    """

    # Init system constants
    SYSTEMD = "systemd"
    OPENRC = "openrc"
    SYSVINIT = "sysvinit"
    BSD_RC = "bsd_rc"
    LAUNCHD = "launchd"
    UNKNOWN = "unknown"

    def __init__(
        self,
        init_system: str = UNKNOWN,
        available_commands: list[str] | None = None,
    ):
        """
        Initialize ServiceManager with detected init system info.

        Args:
            init_system: Detected init system (systemd, openrc, sysvinit, bsd_rc, launchd)
            available_commands: List of available commands on the system (systemctl, service, etc.)
        """
        self.init_system = init_system.lower() if init_system else self.UNKNOWN
        self.available_commands = set(available_commands or [])
        logger.debug(
            "ServiceManager init: init_system=%s available_commands=%s",
            self.init_system,
            self.available_commands,
        )

    def _has(self, cmd: str) -> bool:
        """Check if a command is available."""
        return cmd in self.available_commands

    def _log_choice(self, action: str, choice: str) -> None:
        logger.debug("ServiceManager %s: %s", action, choice)

    # ========================================================================
    # CORE SERVICE OPERATIONS
    # ========================================================================

    def restart(self, service: str) -> str:
        """
        Generate command to restart a service.

        Tries init-system-specific commands first, then falls back through
        alternatives in order of preference.
        """
        # Systemd
        if self.init_system == self.SYSTEMD or self._has("systemctl"):
            self._log_choice(f"restart:{service}", "systemctl")
            return f"systemctl restart {service}"

        # OpenRC
        if self.init_system == self.OPENRC or self._has("rc-service"):
            self._log_choice(f"restart:{service}", "rc-service")
            return f"rc-service {service} restart"

        # SysVinit / traditional service command
        if self._has("service"):
            self._log_choice(f"restart:{service}", "service")
            return f"service {service} restart"

        # Direct init.d script (Slackware, older systems)
        if self._has("/etc/init.d"):
            self._log_choice(f"restart:{service}", "/etc/init.d")
            return f"/etc/init.d/{service} restart"

        # BSD rc.d
        if self.init_system == self.BSD_RC:
            self._log_choice(f"restart:{service}", "bsd_rc")
            return f"service {service} restart"

        # Fallback: try everything
        self._log_choice(f"restart:{service}", "fallback_chain")
        return self._fallback_restart(service)

    def _fallback_restart(self, service: str) -> str:
        """Fallback restart command that tries all known methods."""
        return (
            f"(systemctl restart {service} 2>/dev/null || "
            f"service {service} restart 2>/dev/null || "
            f"/etc/init.d/{service} restart 2>/dev/null || "
            f"rc-service {service} restart 2>/dev/null || "
            f"/etc/rc.d/rc.{service} restart 2>/dev/null || "
            f"/etc/rc.d/{service} restart 2>/dev/null || "
            f"echo 'Failed to restart {service}')"
        )

    def start(self, service: str) -> str:
        """Generate command to start a service."""
        if self.init_system == self.SYSTEMD or self._has("systemctl"):
            self._log_choice(f"start:{service}", "systemctl")
            return f"systemctl start {service}"

        if self.init_system == self.OPENRC or self._has("rc-service"):
            self._log_choice(f"start:{service}", "rc-service")
            return f"rc-service {service} start"

        if self._has("service"):
            self._log_choice(f"start:{service}", "service")
            return f"service {service} start"

        if self.init_system == self.BSD_RC:
            self._log_choice(f"start:{service}", "bsd_rc")
            return f"service {service} onestart"

        # Fallback
        self._log_choice(f"start:{service}", "fallback_chain")
        return (
            f"(systemctl start {service} 2>/dev/null || "
            f"rc-service {service} start 2>/dev/null || "
            f"service {service} start 2>/dev/null || "
            f"/etc/init.d/{service} start 2>/dev/null || "
            f"echo 'Could not start {service}')"
        )

    def stop(self, service: str) -> str:
        """Generate command to stop a service."""
        if self.init_system == self.SYSTEMD or self._has("systemctl"):
            self._log_choice(f"stop:{service}", "systemctl")
            return f"systemctl stop {service}"

        if self.init_system == self.OPENRC or self._has("rc-service"):
            self._log_choice(f"stop:{service}", "rc-service")
            return f"rc-service {service} stop"

        if self._has("service"):
            self._log_choice(f"stop:{service}", "service")
            return f"service {service} stop"

        if self.init_system == self.BSD_RC:
            self._log_choice(f"stop:{service}", "bsd_rc")
            return f"service {service} onestop"

        # Fallback
        self._log_choice(f"stop:{service}", "fallback_chain")
        return (
            f"(systemctl stop {service} 2>/dev/null || "
            f"rc-service {service} stop 2>/dev/null || "
            f"service {service} stop 2>/dev/null || "
            f"/etc/init.d/{service} stop 2>/dev/null || "
            f"echo 'Could not stop {service}')"
        )

    def enable(self, service: str) -> str:
        """Generate command to enable a service at boot."""
        if self.init_system == self.SYSTEMD or self._has("systemctl"):
            self._log_choice(f"enable:{service}", "systemctl")
            return f"systemctl enable {service}"

        if self.init_system == self.OPENRC or self._has("rc-update"):
            self._log_choice(f"enable:{service}", "rc-update")
            return f"rc-update add {service} default"

        if self._has("chkconfig"):
            self._log_choice(f"enable:{service}", "chkconfig")
            return f"chkconfig {service} on"

        if self._has("update-rc.d"):
            self._log_choice(f"enable:{service}", "update-rc.d")
            return f"update-rc.d {service} defaults"

        if self.init_system == self.BSD_RC or self._has("sysrc"):
            self._log_choice(f"enable:{service}", "sysrc")
            return f"sysrc {service}_enable=YES"

        # Fallback
        self._log_choice(f"enable:{service}", "fallback_chain")
        return (
            f"(systemctl enable {service} 2>/dev/null || "
            f"rc-update add {service} default 2>/dev/null || "
            f"chkconfig {service} on 2>/dev/null || "
            f"sysrc {service}_enable=YES 2>/dev/null || "
            f"echo 'Failed to enable {service}')"
        )

    def disable(self, service: str) -> str:
        """Generate command to disable a service at boot."""
        if self.init_system == self.SYSTEMD or self._has("systemctl"):
            self._log_choice(f"disable:{service}", "systemctl")
            return f"systemctl disable {service}"

        if self.init_system == self.OPENRC or self._has("rc-update"):
            self._log_choice(f"disable:{service}", "rc-update")
            return f"rc-update del {service} default"

        if self._has("chkconfig"):
            self._log_choice(f"disable:{service}", "chkconfig")
            return f"chkconfig {service} off"

        if self._has("update-rc.d"):
            self._log_choice(f"disable:{service}", "update-rc.d")
            return f"update-rc.d {service} remove"

        if self.init_system == self.BSD_RC or self._has("sysrc"):
            self._log_choice(f"disable:{service}", "sysrc")
            return f"sysrc {service}_enable=NO"

        # Fallback
        self._log_choice(f"disable:{service}", "fallback_chain")
        return (
            f"(systemctl disable {service} 2>/dev/null || "
            f"rc-update del {service} default 2>/dev/null || "
            f"chkconfig {service} off 2>/dev/null || "
            f"sysrc {service}_enable=NO 2>/dev/null || "
            f"echo 'Failed to disable {service}')"
        )

    def status(self, service: str) -> str:
        """Generate command to check if a service is running."""
        if self.init_system == self.SYSTEMD or self._has("systemctl"):
            self._log_choice(f"status:{service}", "systemctl")
            return f"systemctl is-active {service}"

        if self.init_system == self.OPENRC or self._has("rc-service"):
            self._log_choice(f"status:{service}", "rc-service")
            return f"rc-service {service} status"

        if self._has("service"):
            self._log_choice(f"status:{service}", "service")
            return f"service {service} status"

        if self.init_system == self.BSD_RC:
            self._log_choice(f"status:{service}", "bsd_rc")
            return f"service {service} status"

        # Fallback: check if process is running
        self._log_choice(f"status:{service}", "pgrep_fallback")
        return f"pgrep -x {service}"

    def is_running(self, service: str) -> str:
        """
        Generate command to check if a service is running.
        Returns exit code 0 if running, non-zero otherwise.
        """
        return (
            f"(systemctl is-active {service} 2>/dev/null | grep -q '^active$' || "
            f"service {service} status 2>/dev/null | grep -qiE 'running|started' || "
            f"rc-service {service} status 2>/dev/null | grep -qi 'started' || "
            f"pgrep -x {service} >/dev/null 2>&1)"
        )

    def start_or_restart(self, service: str) -> str:
        """
        Generate command to start a service if stopped, or restart if running.
        Useful when you don't know the current state.
        """
        if self.init_system == self.SYSTEMD or self._has("systemctl"):
            # systemctl restart works for both started and stopped services
            return f"systemctl restart {service}"

        # For other init systems, try start first (won't fail if already running on most)
        return f"({self.start(service)}) && echo '{service} started/restarted'"

    def reload(self, service: str) -> str:
        """Generate command to reload a service configuration without restart."""
        if self.init_system == self.SYSTEMD or self._has("systemctl"):
            self._log_choice(f"reload:{service}", "systemctl")
            return f"systemctl reload {service}"

        if self.init_system == self.OPENRC or self._has("rc-service"):
            # OpenRC doesn't have a universal reload, fall back to restart
            self._log_choice(f"reload:{service}", "rc-service (restart)")
            return f"rc-service {service} restart"

        if self._has("service"):
            self._log_choice(f"reload:{service}", "service")
            return f"service {service} reload"

        if self.init_system == self.BSD_RC:
            self._log_choice(f"reload:{service}", "bsd_rc")
            return f"service {service} reload"

        # Fallback: just restart
        self._log_choice(f"reload:{service}", "fallback_restart")
        return self.restart(service)

    # ========================================================================
    # CONVENIENCE METHODS
    # ========================================================================

    def enable_and_start(self, service: str) -> str:
        """Generate command to enable and start a service."""
        return f"{self.enable(service)} && {self.start(service)}"

    def enable_and_restart(self, service: str) -> str:
        """Generate command to enable and restart a service."""
        return f"{self.enable(service)} && {self.restart(service)}"

    def stop_and_disable(self, service: str) -> str:
        """Generate command to stop and disable a service."""
        return f"{self.stop(service)}; {self.disable(service)}"
