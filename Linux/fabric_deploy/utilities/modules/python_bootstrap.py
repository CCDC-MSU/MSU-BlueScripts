"""
Python Bootstrap Module
Installs uv and Python 3.12 for consistent Ansible execution.

This module MUST run before any module that uses Ansible.
"""

import logging
import json
from pathlib import Path
from typing import List
from datetime import datetime
from .base import HardeningModule, HardeningCommand, HardeningResult, PythonAction

logger = logging.getLogger(__name__)

# Target Python installation
PYTHON_VERSION = "3.12"
PYTHON_INSTALL_DIR = "/root/python"
PYTHON_BIN_DIR = "/root/python/bin"
PYTHON_BIN = f"{PYTHON_BIN_DIR}/python{PYTHON_VERSION}"

# UV installer URL
UV_INSTALL_URL = "https://astral.sh/uv/install.sh"

# State file for tracking successful installations
STATE_FILE = Path(__file__).parent.parent.parent / "ansible" / "python_bootstrap_state.json"


class PythonBootstrapModule(HardeningModule):
    """Bootstrap Python 3.12 via uv for Ansible compatibility"""

    def get_name(self) -> str:
        return "python_bootstrap"

    def get_commands(self) -> List[HardeningCommand]:
        commands = []

        # Step 1: Verify dependencies
        commands.append(PythonAction(
            function=self._verify_uv_dependencies,
            description="Verify uv installer dependencies are present",
            requires_sudo=False
        ))

        # Step 2: Install uv
        commands.append(HardeningCommand(
            command=self._get_install_uv_command(),
            description="Install uv package manager",
            check_command="(command -v uv || test -f ~/.local/bin/uv) && echo 'uv_installed'",
            requires_sudo=False  # uv installs to user's home
        ))

        # Step 3: Source uv environment
        commands.append(HardeningCommand(
            command='test -f "$HOME/.cargo/env" && . "$HOME/.cargo/env" || true',
            description="Source uv environment",
            requires_sudo=False
        ))

        # Step 4: Install Python 3.12
        commands.append(HardeningCommand(
            command=self._get_install_python_command(),
            description=f"Install Python {PYTHON_VERSION} via uv",
            check_command=f"test -f {PYTHON_BIN} && echo 'python_installed'",
            requires_sudo=False
        ))

        # Step 5: Verify Python installation
        commands.append(HardeningCommand(
            command=f"{PYTHON_BIN} --version",
            description="Verify Python installation",
            requires_sudo=False
        ))

        return commands

    def _verify_uv_dependencies(self, conn, server_info) -> HardeningResult:
        """
        Verify all required utilities for uv installer are present.
        Returns failure with detailed message if any are missing.
        """
        missing = []
        warnings = []

        # Required utilities
        required_utils = [
            'tar', 'gzip', 'uname', 'mktemp', 'chmod',
            'awk', 'grep', 'sed', 'cut'
        ]

        # Linux-specific utilities
        linux_utils = ['ldd']

        # Check required utilities
        for util in required_utils:
            result = conn.run(f"command -v {util}", warn=True, hide=True)
            if not result.ok:
                missing.append(util)

        # Check Linux-specific (only if on Linux)
        if self.os_family not in ['freebsd', 'openbsd', 'netbsd']:
            for util in linux_utils:
                result = conn.run(f"command -v {util}", warn=True, hide=True)
                if not result.ok:
                    missing.append(util)

        # Check for curl OR wget
        curl_ok = conn.run("command -v curl", warn=True, hide=True).ok
        wget_ok = conn.run("command -v wget", warn=True, hide=True).ok
        if not curl_ok and not wget_ok:
            missing.append("curl or wget")

        # Check getent OR $HOME
        getent_ok = conn.run("command -v getent", warn=True, hide=True).ok
        home_set = conn.run('test -n "$HOME"', warn=True, hide=True).ok
        if not getent_ok and not home_set:
            warnings.append("getent missing and $HOME not set - will set HOME=/root")

        # Check SSL connectivity (ca-certificates)
        if curl_ok:
            ssl_check = conn.run("curl -sSf https://astral.sh >/dev/null 2>&1", warn=True, hide=True)
        else:
            ssl_check = conn.run("wget -q --spider https://astral.sh 2>/dev/null", warn=True, hide=True)

        if not ssl_check.ok:
            # This might mean missing ca-certificates OR no network
            warnings.append("SSL verification failed - may need ca-certificates or network access")

        if missing:
            return HardeningResult(
                success=False,
                command="verify_uv_deps",
                description="Verify uv installer dependencies",
                error=f"Missing required utilities: {', '.join(missing)}. Install these before proceeding."
            )

        output = "All dependencies present"
        if warnings:
            output += f". Warnings: {'; '.join(warnings)}"

        return HardeningResult(
            success=True,
            command="verify_uv_deps",
            description="Verify uv installer dependencies",
            output=output
        )

    def _get_install_uv_command(self) -> str:
        """Generate command to install uv"""
        return (
            'if command -v uv >/dev/null 2>&1 || test -f "$HOME/.local/bin/uv"; then '
            '  echo "uv already installed"; '
            'else '
            '  export HOME="${HOME:-/root}"; '
            '  if command -v curl >/dev/null 2>&1; then '
            f'    curl -LsSf {UV_INSTALL_URL} | sh; '
            '  else '
            f'    wget -qO- {UV_INSTALL_URL} | sh; '
            '  fi; '
            'fi'
        )

    def _get_install_python_command(self) -> str:
        """Generate command to install Python via uv"""
        return (
            f'export HOME="${{HOME:-/root}}"; '
            f'export UV_PYTHON_INSTALL_DIR={PYTHON_INSTALL_DIR}; '
            f'export UV_PYTHON_BIN_DIR={PYTHON_BIN_DIR}; '
            f'mkdir -p {PYTHON_INSTALL_DIR} {PYTHON_BIN_DIR}; '
            # Find uv binary
            'UV_BIN=""; '
            'if command -v uv >/dev/null 2>&1; then '
            '  UV_BIN=$(command -v uv); '
            'elif test -f "$HOME/.local/bin/uv"; then '
            '  UV_BIN="$HOME/.local/bin/uv"; '
            'elif test -f "$HOME/.cargo/bin/uv"; then '
            '  UV_BIN="$HOME/.cargo/bin/uv"; '
            'fi; '
            'if [ -z "$UV_BIN" ]; then '
            '  echo "ERROR: uv not found"; exit 1; '
            'fi; '
            f'"$UV_BIN" python install {PYTHON_VERSION}'
        )

    def is_applicable(self) -> bool:
        """Applicable to all Linux systems"""
        # Skip BSD for now - uv may have different behavior
        return self.os_family not in ['freebsd', 'openbsd', 'netbsd']

    @staticmethod
    def _load_state() -> dict:
        """Load installation state from file"""
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load state file: {e}")
        return {}

    @staticmethod
    def _save_state(state: dict):
        """Save installation state to file"""
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)
            logger.debug(f"State saved to {STATE_FILE}")
        except Exception as e:
            logger.warning(f"Failed to save state file: {e}")

    def _update_host_state(self, success: bool):
        """Update state for current host"""
        state = self._load_state()

        # Use host IP as key
        host_key = self.conn.host

        state[host_key] = {
            'success': success,
            'python_version': PYTHON_VERSION,
            'python_path': PYTHON_BIN if success else None,
            'timestamp': datetime.now().isoformat(),
            'hostname': getattr(self.server_info, 'hostname', 'unknown'),
        }

        self._save_state(state)

    def save_state_from_results(self, results: List[HardeningResult]):
        """
        Save installation state based on results.
        This is called after module execution (both in normal flow and test flow)
        """
        # Determine if installation was successful
        # Success means all critical steps passed (dependency check, uv install, python install)
        critical_failures = [r for r in results if not r.success and not r.already_applied]
        success = len(critical_failures) == 0

        # Update state for this host
        self._update_host_state(success)

        if success:
            logger.info(f"Python bootstrap successful on {self.conn.host} - state saved for Ansible config generation")
        else:
            logger.warning(f"Python bootstrap failed on {self.conn.host} - Ansible will use auto-discovery")

    def apply_all(self, dry_run: bool = False) -> List[HardeningResult]:
        """Apply all hardening actions and save state"""
        results = super().apply_all(dry_run=dry_run)

        if not dry_run:
            self.save_state_from_results(results)

        return results
