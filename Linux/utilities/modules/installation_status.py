"""
Installation status checker module for CCDC framework
Provides commands to check background installation progress
"""

from typing import List
from .base import HardeningModule, HardeningCommand


class InstallationStatusModule(HardeningModule):
    """Check status of background package installations"""
    
    def get_name(self) -> str:
        return "installation_status"
    
    def get_commands(self) -> List[HardeningCommand]:
        commands = []
        
        # Check installation status
        commands.append(HardeningCommand(
            command='echo "=== Package Installation Status ===" && '
                   'if [ -f /tmp/ccdc_install/status ]; then '
                   'echo "Status: $(cat /tmp/ccdc_install/status)"; '
                   'else echo "Status: No installation found"; fi',
            description="Check package installation status",
            requires_sudo=False
        ))
        
        # Show installation log tail
        commands.append(HardeningCommand(
            command='if [ -f /tmp/ccdc_install/install.log ]; then '
                   'echo "=== Last 10 lines of installation log ===" && '
                   'tail -10 /tmp/ccdc_install/install.log; '
                   'else echo "No installation log found"; fi',
            description="Show recent installation log entries",
            requires_sudo=False
        ))
        
        # Check if installation process is still running
        commands.append(HardeningCommand(
            command='if [ -f /tmp/ccdc_install/install.pid ]; then '
                   'pid=$(cat /tmp/ccdc_install/install.pid); '
                   'if ps -p $pid > /dev/null 2>&1; then '
                   'echo "Installation process (PID: $pid) is still running"; '
                   'else echo "Installation process has finished"; fi; '
                   'else echo "No installation PID file found"; fi',
            description="Check if installation process is running",
            requires_sudo=False
        ))
        
        # Show disk space (installations can fill up disk)
        commands.append(HardeningCommand(
            command='echo "=== Disk Space ===" && df -h / /tmp 2>/dev/null || df -h',
            description="Check available disk space",
            requires_sudo=False
        ))
        
        return commands
    
    def is_applicable(self) -> bool:
        """This module is always applicable for status checking"""
        return True