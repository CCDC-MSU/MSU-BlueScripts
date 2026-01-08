"""
C2 Detection Module - Deploy Hawk file access monitor with YARA-based beacon discovery.

This module deploys a C2 beacon detection system that:
1. Installs YARA and deploys detection rules
2. Scans the filesystem for C2 beacon UUID files
3. Deploys the Hawk daemon to monitor discovered files via fanotify
4. Alerts when processes access watched files (indicating beacon activation)
"""

import logging
from pathlib import Path

from ..service_manager import ServiceManager
from .base import CommandAction, HardeningModule, HardeningResult, PythonAction

logger = logging.getLogger(__name__)

# Package names for YARA across different package managers
YARA_PACKAGE_NAMES = {
    "apt": "yara",
    "dnf": "yara",
    "yum": "yara",
    "pacman": "yara",
    "apk": "yara",
    "zypper": "yara",
    "emerge": "app-forensics/yara",
}

# Package manager install commands
PACKAGE_INSTALL_CMD = {
    "apt": "DEBIAN_FRONTEND=noninteractive apt-get install -y {}",
    "dnf": "dnf install -y {}",
    "yum": "yum install -y {}",
    "pacman": "pacman -S --noconfirm {}",
    "apk": "apk add {}",
    "zypper": "zypper --non-interactive install {}",
    "emerge": "PAGER=cat emerge --ask=n {}",
}


class C2DetectionModule(HardeningModule):
    """Deploy Hawk C2 detection system with YARA-based beacon discovery."""

    def __init__(self, connection, server_info, os_family):
        super().__init__(connection, server_info, os_family)
        # Base paths
        self.repo_root = Path(__file__).parent.parent.parent.parent.parent
        self.threathunting_dir = self.repo_root / "Threathunting"
        self.scripts_dir = Path(__file__).parent.parent.parent / "scripts" / "all"

        # Source files
        self.hawk_binary = self.threathunting_dir / "hawk"
        self.hawk_service = self.threathunting_dir / "hawk.service"
        self.uuid_yar = self.threathunting_dir / "uuid.yar"
        self.sliver_yar = self.threathunting_dir / "sliver.yar"
        self.search_script = self.scripts_dir / "search_yara.sh"

        # Remote paths
        self.remote_hawk_bin = "/usr/local/sbin/hawk"
        self.remote_yara_dir = "/etc/yara"
        self.remote_watchlist = "/etc/hawk.watchlist"
        self.remote_service = "/etc/systemd/system/hawk.service"

    def get_name(self) -> str:
        return "c2_detection"

    def _get_package_manager(self) -> str | None:
        """Get the first supported package manager from server_info."""
        for pm in getattr(self.server_info, "package_managers", []):
            if pm in PACKAGE_INSTALL_CMD:
                return pm
        return None

    def _get_service_manager(self) -> ServiceManager:
        """Get a ServiceManager instance configured for this system."""
        init_system = getattr(self.server_info, "init_system", ServiceManager.UNKNOWN)
        available_commands = getattr(self.server_info, "available_commands", [])
        return ServiceManager(
            init_system=init_system, available_commands=available_commands
        )

    def _read_file_content(self, path: Path) -> str:
        """Read file content, return empty string on error."""
        try:
            with open(path) as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read {path}: {e}")
            return ""

    def is_applicable(self) -> bool:
        """Check if this module can run on this system."""
        # Requires systemd for service management
        init_system = getattr(self.server_info, "init_system", "unknown")
        if init_system != "systemd":
            logger.info(f"C2 detection requires systemd, found: {init_system}")
            return False

        # Check source files exist
        required_files = [self.hawk_binary, self.hawk_service, self.uuid_yar]
        for f in required_files:
            if not f.exists():
                logger.warning(f"Required file missing: {f}")
                return False

        return True

    def get_commands(self) -> list[CommandAction | PythonAction]:
        """Generate commands to deploy C2 detection system."""
        commands = []
        pkg_mgr = self._get_package_manager()

        # 1. Install YARA package
        if pkg_mgr and pkg_mgr in YARA_PACKAGE_NAMES:
            yara_pkg = YARA_PACKAGE_NAMES[pkg_mgr]
            install_cmd = PACKAGE_INSTALL_CMD[pkg_mgr].format(yara_pkg)
            commands.append(
                CommandAction(
                    command=install_cmd,
                    description="Install YARA package",
                    check_command="false",  # we are touching /usr/bin/yara this causes false positives, so just install it
                    requires_sudo=True,
                )
            )

        # 2. Create YARA rules directory
        commands.append(
            CommandAction(
                command=f"mkdir -p {self.remote_yara_dir}",
                description="Create YARA rules directory",
                check_command=f"test -d {self.remote_yara_dir} && echo exists",
                requires_sudo=True,
            )
        )

        # 3. Upload uuid.yar
        uuid_content = self._read_file_content(self.uuid_yar)
        if uuid_content:
            commands.append(
                CommandAction(
                    command=f"cat > {self.remote_yara_dir}/uuid.yar << 'YARA_EOF'\n{uuid_content}YARA_EOF",
                    description="Upload uuid.yar rule",
                    check_command=f"test -f {self.remote_yara_dir}/uuid.yar && echo exists",
                    requires_sudo=True,
                )
            )

        # 4. Upload sliver.yar
        sliver_content = self._read_file_content(self.sliver_yar)
        if sliver_content:
            commands.append(
                CommandAction(
                    command=f"cat > {self.remote_yara_dir}/sliver.yar << 'YARA_EOF'\n{sliver_content}YARA_EOF",
                    description="Upload sliver.yar rule",
                    check_command=f"test -f {self.remote_yara_dir}/sliver.yar && echo exists",
                    requires_sudo=True,
                )
            )

        # 5. Upload hawk binary (PythonAction for binary file)
        commands.append(
            PythonAction(
                function=self._upload_hawk_binary,
                description="Upload hawk binary",
                requires_sudo=True,
            )
        )

        # 6. Make hawk executable
        commands.append(
            CommandAction(
                command=f"chmod 755 {self.remote_hawk_bin}",
                description="Make hawk binary executable",
                requires_sudo=True,
            )
        )

        # 7. Create empty watchlist (will be populated by scan)
        commands.append(
            CommandAction(
                command=f"touch {self.remote_watchlist}",
                description="Create empty watchlist file",
                check_command=f"test -f {self.remote_watchlist} && echo exists",
                requires_sudo=True,
            )
        )

        # 8. Upload and run search_yara.sh to populate watchlist
        if self.search_script.exists():
            script_content = self._read_file_content(self.search_script)
            if script_content:
                commands.append(
                    CommandAction(
                        command=f"cat > /tmp/search_yara.sh << 'SCRIPT_EOF'\n{script_content}SCRIPT_EOF",
                        description="Upload search_yara.sh script",
                        requires_sudo=True,
                    )
                )
                commands.append(
                    CommandAction(
                        command="chmod +x /tmp/search_yara.sh && /tmp/search_yara.sh 2>&1 | tee /root/logs/hardening-scripts/uuid-search.log && rm -f /tmp/search_yara.sh",
                        description="Run YARA scan to populate watchlist",
                        requires_sudo=True,
                    )
                )

        # 9. Upload hawk.service
        service_content = self._read_file_content(self.hawk_service)
        if service_content:
            commands.append(
                CommandAction(
                    command=f"cat > {self.remote_service} << 'SERVICE_EOF'\n{service_content}SERVICE_EOF",
                    description="Upload hawk.service unit file",
                    check_command=f"test -f {self.remote_service} && echo exists",
                    requires_sudo=True,
                )
            )

        # 10. Reload systemd daemon
        commands.append(
            CommandAction(
                command="systemctl daemon-reload",
                description="Reload systemd daemon",
                requires_sudo=True,
            )
        )

        # 11. Enable hawk service
        commands.append(
            CommandAction(
                command="systemctl enable hawk.service",
                description="Enable hawk service",
                check_command="systemctl is-enabled hawk.service 2>/dev/null | grep -q enabled && echo enabled",
                requires_sudo=True,
            )
        )

        # 12. Start hawk service (separate step with sleep to allow activation)
        commands.append(
            CommandAction(
                command="systemctl start hawk.service && sleep 2",
                description="Start hawk service",
                check_command="systemctl is-active hawk.service 2>/dev/null | grep -qE '(active|activating)' && echo running",
                requires_sudo=True,
            )
        )

        return commands

    def _upload_hawk_binary(self, conn, server_info) -> HardeningResult:
        """Upload the hawk binary using Fabric's put() for binary transfer."""
        try:
            if not self.hawk_binary.exists():
                return HardeningResult(
                    success=False,
                    command="upload_hawk_binary",
                    description="Upload hawk binary",
                    error=f"Binary not found: {self.hawk_binary}",
                )

            # Upload to temporary location first (put doesn't support direct sudo)
            temp_path = "/tmp/hawk_upload"
            conn.put(str(self.hawk_binary), temp_path)

            # Move to final location with sudo
            result = conn.run(
                f"mv {temp_path} {self.remote_hawk_bin}",
                hide=True,
                warn=True,
            )

            if not result.ok:
                return HardeningResult(
                    success=False,
                    command="upload_hawk_binary",
                    description="Upload hawk binary",
                    error=f"Failed to move binary: {result.stderr}",
                )

            return HardeningResult(
                success=True,
                command="upload_hawk_binary",
                description="Upload hawk binary",
                output=f"Uploaded to {self.remote_hawk_bin}",
            )

        except Exception as e:
            logger.error(f"Failed to upload hawk binary: {e}")
            return HardeningResult(
                success=False,
                command="upload_hawk_binary",
                description="Upload hawk binary",
                error=str(e),
            )
