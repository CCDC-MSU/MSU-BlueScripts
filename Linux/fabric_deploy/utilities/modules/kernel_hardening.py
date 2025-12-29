"""
Kernel parameter hardening module for CCDC framework
"""

from typing import List
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily

# net.ipv4.icmp_echo_ignore_broadcasts=1
# net.ipv4.conf.interface.forwarding=0
# net.ipv4.conf.interface.send_redirects=0
# net.ipv4.tcp_fin_timeout=60
# net.ipv4.tcp_challenge_ack_limit=50
# net.ipv4.tcp_keepalive_intvl=60
# net.ipv4.tcp_synack_retries=5
# net.ipv4.conf.interface.accept_redirects=0
# net.ipv4.conf.interface.arp_accept=0
# net.ipv4.icmp_errors_use_inbound_ifaddr=1
# net.ipv4.icmp_msgs_per_sec=100
# net.ipv4.ip_default_ttl=64
# net.ipv4.ip_forward=0
# net.ipv4.ip_nonlocal_bind=0
# net.ipv4.conf.interface.log_martians=2
# net.ipv4.conf.interface.mcast_solicit=3
# net.ipv4.conf.interface.rp_filter=1
# net.ipv4.conf.interface.shared_media=0
# net.ipv4.tcp_keepalive_probes=7
# net.ipv4.tcp_syncookies=1
# net.ipv4.icmp_echo_ignore_all=1
# net.ipv4.icmp_ignore_bogus_error_responses=1
# net.ipv4.icmp_ratelimit=500
# net.ipv4.conf.interface.secure_redirects=1
# net.ipv4.tcp_syn_retries=5
# net.ipv4.conf.interface.ucast_solicit=3
# net.ipv6.conf.interface.force_mld_version=2
# net.ipv6.conf.all.accept_ra=0
# net.ipv6.conf.all.accept_ra_defrtr=0
# net.ipv6.conf.all.accept_redirects=0
# net.ipv6.conf.all.autoconf=0
# net.ipv6.conf.all.router_solicitations=0
# net.ipv6.conf.all.use_tempaddr=0
# net.ipv6.conf.all.rp_filter=1
# net.ipv6.conf.all.secure_redirects=1
# net.ipv6.conf.all.accept_dad=1
# net.ipv6.conf.all.accept_source_route=0
# net.ipv6.conf.all.forwarding=0
# net.ipv6.conf.all.accept_ra_rtr_pref=0
# net.ipv6.conf.all.accept_ra_pinfo=0
# net.ipv6.conf.all.anycast_src_echo_ignore_all=1
# net.ipv4.tcp_timestamps=1
# net.ipv4.conf.all.rp_filter=1
# net.ipv4.tcp_sack=1
# fs.protected_hardlinks=1
# fs.protected_symlinks=1
# fs.suid_dumpable=0
# kernel.dmesg_restrict=1
# kernel.kptr_restrict=2
# kernel.sysrq=0
# kernel.yama.ptrace_scop=3
# vm.mmap_min_addr=65355
# vm.panic_on_oom=1
# vm.panic_on_stackoverflow=1
# vm.max_map_count=65355
# dev.tty.ldisc_autoload=0
# fs.protected_fifos=2
# fs.protected_regular=2
# kernel.ctrl-alt-del=0
# kernel.perf_event_paranoid=3
# kernel.randomize_va_space=2
# kernel.unprivileged_bpf_disabled=1
# kernel.yama.ptrace_scope=3
# net.core.bpf_jit_harden=2
# net.ipv4.conf.all.accept_redirects=0
# net.ipv4.conf.all.accept_source_route=0
# net.ipv4.conf.all.bootp_relay=0
# net.ipv4.conf.all.forwarding=0
# net.ipv4.conf.all.log_martians=1
# net.ipv4.conf.all.mc_forwarding=0
# net.ipv4.conf.all.proxy_arp=0
# net.ipv4.conf.all.send_redirects=0
# net.ipv4.conf.default.accept_redirects=0
# net.ipv4.conf.default.accept_source_route=0
# net.ipv4.conf.default.log_martians=1
# net.ipv4.tcp_timestamps=0
# net.ipv6.conf.default.accept_redirects=0
# net.ipv6.conf.default.accept_source_route=0
# net.ipv4.tcp_rfc1337=1
# kernel.core_uses_pid=1
# kernel.modules_disabled=1
# crypto.fips_enabled = 1
# kernel.ctrlaltdel=0
# kernel.panic_on_io_nmi=1
# kernel.panic_on_stackoverflow=1
# kernel.hung_task_panic=1
# kernel.unprivileged_userns_clone=0

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
            ("net.ipv4.tcp_rfc1337", "1", "protect against TIME-WAIT assassination"),

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