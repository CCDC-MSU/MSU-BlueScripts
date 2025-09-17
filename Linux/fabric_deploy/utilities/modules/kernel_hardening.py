"""
Kernel parameter hardening module for CCDC framework
"""

from typing import List
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily


class KernelHardeningModule(HardeningModule):
    """Kernel parameter hardening"""
    
    def get_name(self) -> str:
        return "kernel_hardening"
    
    def get_commands(self) -> List[HardeningCommand]:
        os_family = OSFamily(self.os_family)

        if os_family in [OSFamily.FREEBSD, OSFamily.NETBSD, OSFamily.OPENBSD, OSFamily.BSDGENERIC]:
            # BSD sysctl parameters
            bsd_params = [
                ("net.inet.ip.forwarding", "0", "Disable IP forwarding"),
                ("net.inet.ip.accept_sourceroute", "0", "Disable source routing"),
                ("net.inet.icmp.bmcastecho", "0", "Ignore ICMP broadcast echo (smurf protection)"),
                ("net.inet.icmp.maskrepl", "0", "Disable ICMP address mask replies"),
                ("kern.randompid", "1", "Enable PID randomization"),
                ("security.bsd.see_other_uids", "0", "Hide processes from other users"),
                ("security.bsd.see_other_gids", "0", "Hide group processes"),
                ("security.bsd.unprivileged_read_msgbuf", "0", "Restrict dmesg access"),
                ("security.bsd.unprivileged_proc_debug", "0", "Restrict ptrace-like behavior"),
                ("security.bsd.hardlink_check_uid", "1", "Protect hardlinks"),
                ("security.bsd.hardlink_check_gid", "1", "Protect hardlinks by group"),
                ("security.bsd.symlinkown_gid", "1", "Protect symlinks"),
                ("kern.sugid_coredump", "0", "Disable SUID core dumps"),
            ]

            for param, value, desc in bsd_params:
                commands.append(HardeningCommand(
                    command=f'sysctl {param}={value}',
                    description=desc,
                    check_command=f'sysctl {param} | grep -q ": {value}" && echo set',
                    requires_sudo=True
                ))
            return commands

        commands = []
        
        # Create sysctl config directory if needed
        commands.append(HardeningCommand(
            command="mkdir -p /etc/sysctl.d",
            description="Create sysctl.d directory",
            check_command="test -d /etc/sysctl.d && echo exists",
            requires_sudo=True
        ))
        
        # Kernel parameters
        kernel_params = [
            # Network security
            ("net.ipv4.ip_forward", "0", "Disable IP forwarding"),
            ("net.ipv4.conf.all.send_redirects", "0", "Disable send redirects"),
            ("net.ipv4.conf.default.send_redirects", "0", "Disable default send redirects"),
            ("net.ipv4.conf.all.accept_source_route", "0", "Disable source routing"),
            ("net.ipv4.conf.all.accept_redirects", "0", "Disable ICMP redirects"),
            ("net.ipv4.conf.all.secure_redirects", "0", "Disable secure redirects"),
            ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "Ignore ICMP broadcasts"),
            ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "Ignore bogus ICMP errors"),
            ("net.ipv4.tcp_syncookies", "1", "Enable TCP SYN cookies"),
            ("net.ipv4.conf.all.rp_filter", "1", "Enable reverse path filtering"),
            
            # Kernel security
            ("kernel.randomize_va_space", "2", "Enable ASLR"),
            ("kernel.kptr_restrict", "2", "Restrict kernel pointer access"),
            ("kernel.yama.ptrace_scope", "1", "Restrict ptrace scope"),
            ("kernel.dmesg_restrict", "1", "Restrict dmesg access"),
            ("fs.protected_hardlinks", "1", "Protect hardlinks"),
            ("fs.protected_symlinks", "1", "Protect symlinks"),
            ("fs.suid_dumpable", "0", "Disable SUID dumps"),
        ]
        
        for param, value, desc in kernel_params:
            commands.append(HardeningCommand(
                command=f'echo "{param} = {value}" > /etc/sysctl.d/99-hardening-{param.replace(".", "-")}.conf',
                description=desc,
                check_command=f'sysctl {param} | grep -q "= {value}" && echo set',
                requires_sudo=True
            ))
        
        # Apply sysctl settings
        commands.append(HardeningCommand(
            command="sysctl --system",
            description="Apply all sysctl settings",
            requires_sudo=True
        ))
        
        return commands