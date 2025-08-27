"""
File permissions hardening module for CCDC framework
"""

from typing import List
from .base import HardeningModule, HardeningCommand


class FilePermissionsModule(HardeningModule):
    """Fix file permissions for sensitive files"""
    
    def get_name(self) -> str:
        return "file_permissions"
    
    def get_commands(self) -> List[HardeningCommand]:
        commands = []
        
        # Important files and their permissions
        permission_fixes = [
            ("/etc/passwd", "644", "Set /etc/passwd permissions"),
            ("/etc/shadow", "000", "Set /etc/shadow permissions"),
            ("/etc/group", "644", "Set /etc/group permissions"),
            ("/etc/gshadow", "000", "Set /etc/gshadow permissions"),
            ("/etc/ssh/sshd_config", "600", "Set SSH config permissions"),
            ("/boot/grub/grub.cfg", "600", "Set GRUB config permissions"),
        ]
        
        for file_path, perms, desc in permission_fixes:
            commands.append(HardeningCommand(
                command=f"test -f {file_path} && chmod {perms} {file_path} || true",
                description=desc,
                check_command=f"test -f {file_path} && stat -c %a {file_path} | grep -q {perms} && echo correct",
                requires_sudo=True
            ))
        
        return commands