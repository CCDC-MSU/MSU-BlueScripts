"""
Shell script deployment module for CCDC framework
"""

import logging
from pathlib import Path

from .base import CommandAction, HardeningModule

logger = logging.getLogger(__name__)


class ShellScriptHardeningModule(HardeningModule):
    """Deploy and execute shell scripts directly (sh/POSIX compatible)"""

    def __init__(
        self, connection, server_info, os_family, script_paths: list[str] | None = None
    ):
        super().__init__(connection, server_info, os_family)
        self.script_paths = script_paths or []
        self.scripts_base_path = Path(__file__).parent.parent.parent / "scripts"
        self.default_shell = server_info.default_shell

    def get_name(self) -> str:
        return "shell_scripts"

    def is_applicable(self) -> bool:
        """Check if we have scripts to run"""
        return len(self.script_paths) > 0

    def get_commands(self) -> list[CommandAction]:
        """Generate commands to deploy and execute shell scripts"""
        commands = []

        if not self.script_paths:
            logger.info("No shell scripts configured for this system")
            return commands

        # Create directories
        commands.append(
            CommandAction(
                command="mkdir -p /tmp/ccdc_scripts /root/logs/hardening-scripts && chmod 755 /tmp/ccdc_scripts",
                description="Create script staging and log directories",
                check_command="test -d /tmp/ccdc_scripts && test -d /root/logs/hardening-scripts && echo exists",
                requires_sudo=True,
            )
        )

        # Deploy and execute each script
        for script_rel_path in self.script_paths:
            script_path = self.scripts_base_path / script_rel_path

            if not script_path.exists():
                logger.warning(f"Script not found: {script_path}")
                continue

            script_name = script_path.name
            remote_path = f"/tmp/ccdc_scripts/{script_name}"
            log_path = f"/root/logs/hardening-scripts/{script_name}.log"

            # Upload script command
            commands.append(self._create_upload_command(script_path, remote_path))

            # Make executable
            commands.append(
                CommandAction(
                    command=f"chmod +x {remote_path}",
                    description=f"Make {script_name} executable",
                    requires_sudo=True,
                )
            )

            # Execute script with logging
            # Use pipefail to catch errors even when piping to tee
            commands.append(
                CommandAction(
                    command=f"cd /tmp/ccdc_scripts && timeout 300 {self.default_shell} {remote_path} 2>&1 | tee {log_path}",
                    description=f"Execute {script_name} (logs at {log_path})",
                    requires_sudo=True,
                )
            )

        # Clean up staging directory
        commands.append(
            CommandAction(
                command="rm -rf /tmp/ccdc_scripts",
                description="Clean up script staging directory",
                requires_sudo=True,
            )
        )

        return commands

    def _create_upload_command(
        self, local_path: Path, remote_path: str
    ) -> CommandAction:
        """Create a command to upload a script file"""
        try:
            with open(local_path) as f:
                script_content = f.read()

            return CommandAction(
                command=f"cat > {remote_path} << 'CCDC_SCRIPT_EOF'\n{script_content}\nCCDC_SCRIPT_EOF",
                description=f"Upload {local_path.name}",
                check_command=f"test -f {remote_path} && echo exists",
                requires_sudo=True,
            )
        except Exception as e:
            logger.error(f"Failed to read script {local_path}: {e}")
            return CommandAction(
                command=f"echo 'Failed to upload {local_path.name}: {e}' && false",
                description=f"Upload {local_path.name} (FAILED)",
                requires_sudo=True,
            )
