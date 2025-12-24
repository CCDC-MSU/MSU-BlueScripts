# Kernel Hardening Module

**Go back to [main README](README.md)**

This module hardens the kernel of the target system by setting various `sysctl` parameters. It applies a set of security best practices to both Linux and BSD systems.

## Overview

The `kernel_hardening` module modifies kernel parameters to improve the security and resilience of the operating system. It differentiates between Linux and BSD systems to apply the appropriate settings.

### Key Features

-   **Cross-Platform Support**: Automatically detects the OS and applies the correct kernel parameters for Linux and BSD.
-   **Network Security**: Hardens the network stack against common attacks like IP spoofing and ICMP abuse.
-   **Memory Protections**: Enables Address Space Layout Randomization (ASLR) and other memory-related security features.
-   **Filesystem Security**: Protects against insecure hardlinks and symlinks.

## Linux Hardening Parameters

For Linux systems, the module creates one file per setting in `/etc/sysctl.d/` (prefixed with `99-hardening-`) and applies them with `sysctl --system`:

### Network Security

*   `net.ipv4.ip_forward = 0`: Disables IP forwarding.
*   `net.ipv4.conf.all.send_redirects = 0`: Disables sending of ICMP redirects.
*   `net.ipv4.conf.default.send_redirects = 0`: Disables sending of ICMP redirects by default.
*   `net.ipv4.conf.all.accept_source_route = 0`: Disables acceptance of source-routed packets.
*   `net.ipv4.conf.all.accept_redirects = 0`: Disables acceptance of ICMP redirects.
*   `net.ipv4.conf.all.secure_redirects = 0`: Disables acceptance of secure ICMP redirects.
*   `net.ipv4.icmp_echo_ignore_broadcasts = 1`: Ignores ICMP broadcast requests to prevent smurf attacks.
*   `net.ipv4.icmp_ignore_bogus_error_responses = 1`: Ignores bogus ICMP error responses.
*   `net.ipv4.tcp_syncookies = 1`: Enables TCP SYN cookies to help prevent SYN flood attacks.
*   `net.ipv4.conf.all.rp_filter = 1`: Enables reverse path filtering to prevent IP spoofing.

### Kernel Security

*   `kernel.randomize_va_space = 2`: Enables Address Space Layout Randomization (ASLR).
*   `kernel.kptr_restrict = 2`: Restricts access to kernel pointers.
*   `kernel.yama.ptrace_scope = 1`: Restricts the use of `ptrace`.
*   `kernel.dmesg_restrict = 1`: Restricts access to the kernel log buffer.
*   `fs.protected_hardlinks = 1`: Protects against hardlink-based attacks.
*   `fs.protected_symlinks = 1`: Protects against symlink-based attacks.
*   `fs.suid_dumpable = 0`: Disables core dumps for SUID/SGID executables.

## BSD Hardening Parameters

For BSD systems, the module uses the `sysctl` command to set the following parameters directly:

*   `net.inet.ip.forwarding=0`: Disables IP forwarding.
*   `net.inet.ip.accept_sourceroute=0`: Disables source routing.
*   `net.inet.icmp.bmcastecho=0`: Ignores ICMP broadcast echo (smurf protection).
*   `net.inet.icmp.maskrepl=0`: Disables ICMP address mask replies.
*   `kern.randompid=1`: Enable PID randomization.
*   `security.bsd.see_other_uids=0`: Hide processes from other users.
*   `security.bsd.see_other_gids=0`: Hide group processes.
*   `security.bsd.unprivileged_read_msgbuf=0`: Restrict dmesg access.
*   `security.bsd.unprivileged_proc_debug=0`: Restrict ptrace-like behavior.
*   `security.bsd.hardlink_check_uid=1`: Protect hardlinks.
*   `security.bsd.hardlink_check_gid=1`: Protect hardlinks by group.
*   `security.bsd.symlinkown_gid=1`: Protect symlinks.
*   `kern.sugid_coredump=0`: Disable SUID core dumps.

## Discovery Context

-   Uses the discovered OS family to select Linux vs BSD sysctl behavior.
-   Discovery summaries include a `sudoers` block (dump + parsed lists) for privilege auditing alongside kernel changes.

## Usage

This module is typically run as part of the main hardening pipeline, but it can also be tested individually.

*   **Test in Dry-Run Mode (Safe)**:
    ```bash
    fab test-module --module=kernel_hardening
    ```

*   **Execute in Live Mode**:
    ```bash
    fab test-module --module=kernel_hardening --live
    ```
