#!/bin/sh
#
# prepare-auditd-paths.sh
# Creates all files and directories required by auditd rules
# Run this BEFORE loading auditd rules to prevent load failures
#
# Usage: sudo ./prepare-auditd-paths.sh
#

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Warning: Not running as root. Some paths may fail to create."
    echo "Consider running with: sudo $0"
    echo ""
fi

echo "=== Creating directories ==="

for dir in \
    "/.config" \
    "/.mozilla" \
    "/etc/NetworkManager" \
    "/etc/NetworkManager/system-connections" \
    "/etc/ansible" \
    "/etc/apt/sources.list.d" \
    "/etc/audisp" \
    "/etc/audit" \
    "/etc/audit/rules.d" \
    "/etc/chef" \
    "/etc/clustershell" \
    "/etc/containers" \
    "/etc/cron.d" \
    "/etc/cron.daily" \
    "/etc/cron.hourly" \
    "/etc/cron.monthly" \
    "/etc/cron.weekly" \
    "/etc/default" \
    "/etc/docker" \
    "/etc/exim4" \
    "/etc/firewalld" \
    "/etc/fish" \
    "/etc/httpd" \
    "/etc/incron.d" \
    "/etc/inetd.d" \
    "/etc/init" \
    "/etc/init.d" \
    "/etc/iptables" \
    "/etc/ld.so.conf.d" \
    "/etc/modprobe.d" \
    "/etc/netplan" \
    "/etc/network" \
    "/etc/openvpn" \
    "/etc/pacman.d" \
    "/etc/pam.d" \
    "/etc/pki" \
    "/etc/postfix" \
    "/etc/profile.d" \
    "/etc/puppet" \
    "/etc/puppetlabs" \
    "/etc/rc.d" \
    "/etc/salt" \
    "/etc/samba" \
    "/etc/security" \
    "/etc/security/limits.d" \
    "/etc/security/namespace.d" \
    "/etc/selinux" \
    "/etc/ssh" \
    "/etc/ssh/sshd_config.d" \
    "/etc/sudoers.d" \
    "/etc/sysconfig" \
    "/etc/sysctl.d" \
    "/etc/systemd" \
    "/etc/systemd/system" \
    "/etc/systemd/system-generators" \
    "/etc/systemd/user-generators" \
    "/etc/udev/rules.d" \
    "/etc/ufw" \
    "/etc/update-motd.d" \
    "/etc/xinetd.d" \
    "/etc/yum.repos.d" \
    "/etc/zsh" \
    "/lib/modules" \
    "/lib/systemd/system" \
    "/lib/systemd/system-generators" \
    "/lib64/dbus-1" \
    "/lib64/vte-2.91" \
    "/media" \
    "/mnt" \
    "/root/.ssh" \
    "/run/systemd" \
    "/srv/salt" \
    "/tmp" \
    "/usr/games" \
    "/usr/lib/systemd/system" \
    "/usr/lib/systemd/system-generators" \
    "/usr/lib/vmware-tools" \
    "/usr/lib64/dbus-1" \
    "/usr/lib64/vte-2.91" \
    "/usr/libexec/kde4" \
    "/usr/libexec/sssd" \
    "/usr/local/bin" \
    "/usr/local/etc" \
    "/usr/local/games" \
    "/usr/local/lib/systemd/system-generators" \
    "/usr/local/lib/systemd/user-generators" \
    "/usr/local/rc.d" \
    "/usr/local/sbin" \
    "/var/audit" \
    "/var/chef" \
    "/var/lib/containers" \
    "/var/lib/docker" \
    "/var/lib/puppet" \
    "/var/lib/samba" \
    "/var/lib/terraform" \
    "/var/lock" \
    "/var/log/audit" \
    "/var/opt/BESClient" \
    "/var/spool/anacron" \
    "/var/spool/at" \
    "/var/spool/cron" \
    "/var/www/html" \
    "/Library/LaunchDaemons" \
    "/Library/Preferences"
do
    if [ ! -d "$dir" ]; then
        if mkdir -p "$dir" 2>/dev/null; then
            echo "  [DIR]  $dir"
        else
            echo "  [FAIL] $dir"
        fi
    fi
done

echo ""
echo "=== Creating files ==="

for file in \
    "/etc/DIR_COLORS" \
    "/etc/DIR_COLORS.lightbgcolor" \
    "/etc/aliases" \
    "/etc/anacrontab" \
    "/etc/apt/sources.list" \
    "/etc/at.allow" \
    "/etc/at.deny" \
    "/etc/audit/audit.rules" \
    "/etc/audit/auditd.conf" \
    "/etc/bash.bash_logout" \
    "/etc/bash.bashrc" \
    "/etc/bash_completion" \
    "/etc/bash_completion.d" \
    "/etc/bashrc" \
    "/etc/clustershell/clush.conf" \
    "/etc/cron.allow" \
    "/etc/cron.deny" \
    "/etc/crontab" \
    "/etc/csh.cshrc" \
    "/etc/csh.login" \
    "/etc/default/cron" \
    "/etc/default/knockd.conf" \
    "/etc/dircolors" \
    "/etc/environment" \
    "/etc/group" \
    "/etc/gshadow" \
    "/etc/hostname" \
    "/etc/hosts" \
    "/etc/incron.allow" \
    "/etc/incron.conf" \
    "/etc/incron.deny" \
    "/etc/inetd.conf" \
    "/etc/inittab" \
    "/etc/issue" \
    "/etc/issue.net" \
    "/etc/knockd.conf" \
    "/etc/ld.so.conf" \
    "/etc/ld.so.preload" \
    "/etc/libaudit.conf" \
    "/etc/localtime" \
    "/etc/login.defs" \
    "/etc/modprobe.conf" \
    "/etc/network/interfaces" \
    "/etc/nftables.conf" \
    "/etc/nsswitch.conf" \
    "/etc/otter" \
    "/etc/pacman.conf" \
    "/etc/passwd" \
    "/etc/profile" \
    "/etc/protocols" \
    "/etc/proxychains.conf" \
    "/etc/puppet/ssl" \
    "/etc/rc.boot" \
    "/etc/rc.local" \
    "/etc/resolv.conf" \
    "/etc/samba/smb.conf" \
    "/etc/securetty" \
    "/etc/security/limits.conf" \
    "/etc/security/namespace.conf" \
    "/etc/security/namespace.init" \
    "/etc/security/opasswd" \
    "/etc/security/pam_env.conf" \
    "/etc/security/pwquality.conf" \
    "/etc/services" \
    "/etc/shadow" \
    "/etc/shells" \
    "/etc/ssh/sshd_config" \
    "/etc/sudoers" \
    "/etc/sysconfig/docker" \
    "/etc/sysconfig/docker-storage" \
    "/etc/sysconfig/network" \
    "/etc/sysconfig/network-scripts" \
    "/etc/sysctl.conf" \
    "/etc/systemd/logind.conf" \
    "/etc/systemd/sleep.conf" \
    "/etc/xinetd.conf" \
    "/lib/systemd/system/atftpd.service" \
    "/lib/systemd/system/atftpd.socket" \
    "/lib/systemd/system/uftp.service" \
    "/lib64/dbus-1/dbus-daemon-launch-helper" \
    "/lib64/vte-2.91/gnome-pty-helper" \
    "/opt/filebeat" \
    "/root/.bash_profile" \
    "/root/.bashrc" \
    "/usr/lib/systemd/system/atftpd.service" \
    "/usr/lib/systemd/system/atftpd.socket" \
    "/usr/lib/systemd/system/docker.service" \
    "/usr/lib/systemd/system/docker.socket" \
    "/usr/lib/systemd/system/uftp.service" \
    "/usr/lib64/dbus-1/dbus-daemon-launch-helper" \
    "/usr/lib64/vte-2.91/gnome-pty-helper" \
    "/usr/libexec/kde4/kdesud" \
    "/usr/libexec/kde4/kpac_dhcp_helper" \
    "/usr/libexec/sssd/krb5_child" \
    "/usr/libexec/sssd/ldap_child" \
    "/usr/libexec/sssd/p11_child" \
    "/usr/libexec/sssd/proxy_child" \
    "/usr/libexec/sssd/selinux_child" \
    "/usr/local/etc/salt" \
    "/usr/local/rc.boot" \
    "/usr/local/rc.local" \
    "/var/lock/lvm" \
    "/var/log/auth.log" \
    "/var/log/btmp" \
    "/var/log/faillog" \
    "/var/log/lastlog" \
    "/var/log/messages" \
    "/var/log/syslog" \
    "/var/log/tallylog" \
    "/var/log/wtmp" \
    "/var/run/utmp" \
    "/var/spool/at/spool" \
    "/var/spool/atspool" \
    "/var/spool/cron/atjobs" \
    "/var/spool/cron/atspool" \
    "/var/spool/cron/root" \
    "/Library/Application" \
    "/Library/LaunchDaemons/org.virtualbox.startup.plist" \
    "/Library/Preferences/Parallels"
do
    if [ ! -e "$file" ]; then
        # Ensure parent directory exists
        parent=$(dirname "$file")
        [ ! -d "$parent" ] && mkdir -p "$parent" 2>/dev/null
        
        if touch "$file" 2>/dev/null; then
            echo "  [FILE] $file"
        else
            echo "  [FAIL] $file"
        fi
    fi
done

echo ""
echo "=== Skipping virtual filesystem paths ==="
echo "  [SKIP] /proc/self/maps"
echo "  [SKIP] /proc/self/mem"
echo "  [SKIP] /proc/sys/net/ipv4/icmp_echo_ignore_all"
echo ""
echo "=== Done ==="
echo "You can now load your auditd rules with: sudo augenrules --load"