"""
Service hardening module for CCDC framework
"""

from typing import List
from .base import HardeningModule, HardeningCommand


class ServiceHardeningModule(HardeningModule):
    """Disable unnecessary services"""
    
    def get_name(self) -> str:
        return "service_hardening"
    
    def is_applicable(self) -> bool:
        """Only applicable to systems with systemd for now"""
        # Check if we have init system info
        init_system = getattr(self.server_info, 'init_system', 'unknown')
        return init_system == "systemd"
    
    def get_commands(self) -> List[HardeningCommand]:
        commands = []
        
        # Services to disable (if they exist)
        unnecessary_services = [
            ("bluetooth.service", "Bluetooth service"),
            ("cups.service", "Print service"),
            ("avahi-daemon.service", "Avahi daemon"),
        ]
        
        for service, desc in unnecessary_services:
            commands.append(HardeningCommand(
                command=f"systemctl is-enabled {service} >/dev/null 2>&1 && systemctl disable {service} || true",
                description=f"Disable {desc}",
                check_command=f"systemctl is-enabled {service} 2>/dev/null | grep -q disabled && echo disabled",
                requires_sudo=True
            ))
        
        return commands