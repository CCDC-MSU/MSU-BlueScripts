"""
User hardening module for CCDC framework
Manages user accounts, passwords, sudo access, and account security
Supports Linux and BSD/Unix systems
"""
# TODO: terminate all running processes owned by the user being disabled.
# TODO: get a list of orphaned files
# TODO: removing old authorized_keys files and generating new key pairs for users.

import json
import os
from typing import List, Dict, Set
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily


class UserHardeningModule(HardeningModule):
    """Comprehensive user account hardening and management"""
    
    def __init__(self, connection, server_info, os_family):
        super().__init__(connection, server_info, os_family)
        self.users_config = self._load_users_config()
        self.system_accounts = self._get_system_accounts()
        
    def get_name(self) -> str:
        return "user_hardening"
    
    def _load_users_config(self) -> Dict:
        """Load users configuration from users.json"""
        config_path = os.path.join(os.path.dirname(__file__), '../../users.json')
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default config if file doesn't exist
            return {
                "regular_users": {},
                "super_users": {},
                "dontchange_accounts": {
                    "root": "system account",
                    "scan-agent": "do not change"
                }
            }
    
    def _get_system_accounts(self) -> Set[str]:
        """Get list of common system accounts that should not be modified"""
        linux_system_accounts = {
            'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 
            'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list',
            'irc', 'gnats', 'nobody', 'systemd-network', 'systemd-resolve',
            'messagebus', 'systemd-timesync', 'syslog', 'uuidd', 'tcpdump',
            'tss', 'landscape', 'fwupd-refresh', '_apt', 'lxd', 'mysql',
            'postgres', 'redis', 'mongodb', 'nginx', 'apache', 'httpd',
            'postfix', 'dovecot', 'bind', 'named', 'ntp', 'ssh', 'sshd'
        }
        
        bsd_system_accounts = {
            'root', 'daemon', 'operator', 'bin', 'tty', 'kmem', 'games',
            'news', 'man', 'bind', 'uucp', 'proxy', 'authpf', '_pflogd',
            '_dhcp', '_tcpdump', '_tftpd', '_rbootd', '_ppp', '_ntp',
            '_ftp', '_identd', '_rstatd', '_rusersd', '_fingerd', '_sshd',
            '_x11', '_ipsec', '_isakmpd', '_afs', '_bgpd', '_unbound',
            '_httpd', '_smtpd', '_smtpq', '_file', '_radiusd', '_eigrpd',
            '_vmd', '_sndiop', '_syspatch', '_slaacd'
        }
        
        try:
            os_family = OSFamily(self.os_family)
            if os_family in [OSFamily.FREEBSD, OSFamily.OPENBSD, OSFamily.NETBSD, OSFamily.BSDGENERIC]:
                return bsd_system_accounts
            else:
                return linux_system_accounts
        except ValueError:
            # Default to Linux system accounts
            return linux_system_accounts
    
    def get_commands(self) -> List[HardeningCommand]:
        commands = []
        
        # Step 1: Backup current user configuration
        shell = self.server_info.default_shell
        commands.append(HardeningCommand(
            command=f"{shell} -c \"cp /etc/passwd /etc/passwd.backup.$(date +%Y%m%d_%H%M%S) && cp /etc/shadow /etc/shadow.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || cp /etc/master.passwd /etc/master.passwd.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null\"",
            description="Backup user account files",
            requires_sudo=True
        ))
        
        # Step 2: Skip user creation - users must already exist
        # No longer creating regular_users or super_users from config
        
        # Step 4: Remove sudo access from regular users (if they exist)
        for username in self.users_config.get('regular_users', {}).keys():
            commands.extend(self._remove_sudo_access_commands(username))
        
        # Step 5: Grant sudo access to super users (if they exist)
        for username in self.users_config.get('super_users', {}).keys():
            commands.extend(self._grant_sudo_access_commands(username))
        
        # Step 6: Set passwords for authorized users (if they exist)
        all_users = {**self.users_config.get('regular_users', {}), 
                    **self.users_config.get('super_users', {})}
        for username, password in all_users.items():
            commands.append(self._set_password_command(username, password))
        
        # Step 7: Disable shells for unauthorized users
        commands.extend(self._secure_unauthorized_users_commands())
        
        # Step 8: Create user management report
        commands.append(HardeningCommand(
            command=self._generate_user_report_command(),
            description="Generate user account security report",
            requires_sudo=True
        ))
        
        return commands
        
    def _remove_sudo_access_commands(self, username: str) -> List[HardeningCommand]:
        """Create commands to remove sudo access from a user"""
        commands = []
        shell = self.server_info.default_shell
        
        try:
            os_family = OSFamily(self.os_family)
            
            if os_family in [OSFamily.FREEBSD, OSFamily.OPENBSD, OSFamily.NETBSD, OSFamily.BSDGENERIC]:
                # BSD sudo removal
                commands.append(HardeningCommand(
                    command=f"{shell} -c \"pw groupmod wheel -d {username} 2>/dev/null || gpasswd -d {username} wheel 2>/dev/null || true\"",
                    description=f"Remove sudo access: {username} (BSD)",
                    requires_sudo=True
                ))
            else:
                # Linux sudo removal - check multiple locations
                commands.append(HardeningCommand(
                    command=f"""{shell} -c \"
                    # Remove from sudo group
                    gpasswd -d {username} sudo 2>/dev/null || deluser {username} sudo 2>/dev/null || usermod -G $(groups {username} | sed 's/{username} : //g' | sed 's/sudo //g' | tr ' ' ',') {username} 2>/dev/null || true
                    
                    # Remove from wheel group  
                    gpasswd -d {username} wheel 2>/dev/null || deluser {username} wheel 2>/dev/null || true
                    
                    # Remove from admin group
                    gpasswd -d {username} admin 2>/dev/null || deluser {username} admin 2>/dev/null || true
                    
                    # Remove individual sudoers entries
                    sed -i '/^{username}[[:space:]]/d' /etc/sudoers 2>/dev/null || true
                    rm -f /etc/sudoers.d/{username} 2>/dev/null || true
                    \"""".strip(),
                    description=f"Remove all sudo access: {username}",
                    requires_sudo=True
                ))
        except ValueError:
            # Default to Linux
            commands.append(HardeningCommand(
                command=f"{shell} -c \"gpasswd -d {username} sudo 2>/dev/null || gpasswd -d {username} wheel 2>/dev/null || gpasswd -d {username} admin 2>/dev/null || true\"",
                description=f"Remove sudo access: {username}",
                requires_sudo=True
            ))
            
        return commands
    
    def _grant_sudo_access_commands(self, username: str) -> List[HardeningCommand]:
        """Create commands to grant sudo access to a user"""
        commands = []
        shell = self.server_info.default_shell
        
        try:
            os_family = OSFamily(self.os_family)
            
            if os_family in [OSFamily.FREEBSD, OSFamily.OPENBSD, OSFamily.NETBSD, OSFamily.BSDGENERIC]:
                # BSD sudo access
                commands.append(HardeningCommand(
                    command=f"{shell} -c \"pw groupmod wheel -m {username} 2>/dev/null || usermod -G wheel {username}\"",
                    description=f"Grant sudo access: {username} (BSD)",
                    check_command=f"{shell} -c \"groups {username} | grep -q wheel && echo has_sudo\"",
                    requires_sudo=True
                ))
            else:
                # Linux sudo access
                commands.append(HardeningCommand(
                    command=f"{shell} -c \"usermod -aG sudo {username} 2>/dev/null || usermod -aG wheel {username}\"",
                    description=f"Grant sudo access: {username}",
                    check_command=f"{shell} -c \"groups {username} | grep -E '(sudo|wheel)' >/dev/null && echo has_sudo\"",
                    requires_sudo=True
                ))
        except ValueError:
            # Default to Linux
            commands.append(HardeningCommand(
                command=f"{shell} -c \"usermod -aG sudo {username} 2>/dev/null || usermod -aG wheel {username}\"",
                description=f"Grant sudo access: {username}",
                check_command=f"{shell} -c \"groups {username} | grep -E '(sudo|wheel)' >/dev/null && echo has_sudo\"",
                requires_sudo=True
            ))
            
        return commands
    
    def _set_password_command(self, username: str, password: str) -> HardeningCommand:
        """Create command to set user password"""
        shell = self.server_info.default_shell
        
        try:
            os_family = OSFamily(self.os_family)
            
            if os_family in [OSFamily.FREEBSD, OSFamily.OPENBSD, OSFamily.NETBSD, OSFamily.BSDGENERIC]:
                # BSD password setting
                return HardeningCommand(
                    command=f"{shell} -c \"echo '{password}' | pw usermod {username} -h 0 2>/dev/null || echo '{username}:{password}' | chpasswd\"",
                    description=f"Set password for user: {username}",
                    requires_sudo=True
                )
            else:
                # Linux password setting
                return HardeningCommand(
                    command=f"{shell} -c \"usermod --password $(openssl passwd -6 '{password}') {username} || echo '{username}:{password}' | chpasswd\"",
                    description=f"Set password for user: {username}",
                    requires_sudo=True
                )
        except ValueError:
            # Default to Linux
            return HardeningCommand(
                command=f"{shell} -c \"usermod --password $(openssl passwd -6 '{password}') {username} || echo '{username}:{password}' | chpasswd\"",
                description=f"Set password for user: {username}",
                requires_sudo=True
            )
    
    def _secure_unauthorized_users_commands(self) -> List[HardeningCommand]:
        """Create commands to secure unauthorized user accounts"""
        commands = []
        shell = self.server_info.default_shell
        
        # Get all authorized users (only from config, not system accounts)
        authorized_users = set()
        authorized_users.update(self.users_config.get('regular_users', {}).keys())
        authorized_users.update(self.users_config.get('super_users', {}).keys())
        authorized_users.update(self.users_config.get('dontchange_accounts', {}).keys())
        
        try:
            os_family = OSFamily(self.os_family)
            
            if os_family in [OSFamily.FREEBSD, OSFamily.OPENBSD, OSFamily.NETBSD, OSFamily.BSDGENERIC]:
                # BSD unauthorized user handling
                commands.append(HardeningCommand(
                    command=f"""
                    # Get all users
                    for user in $(awk -F: '{{{{ print $1 }}}}' /etc/passwd); do
                        # Skip authorized users
                        case "$user" in
                            {"|".join(authorized_users)})
                                echo "Skipping authorized user: $user"
                                ;;
                            *)
                                echo "Disabling unauthorized user: $user"
                                # Disable shell
                                pw usermod $user -s /usr/sbin/nologin 2>/dev/null || chsh -s /usr/sbin/nologin $user 2>/dev/null || pw usermod $user -s /bin/false 2>/dev/null || chsh -s /bin/false $user 2>/dev/null || true
                                ;;
                        esac
                    done
                    """.strip(),
                    description="Disable unauthorized user accounts (BSD)",
                    requires_sudo=True
                ))
            else:
                # Linux unauthorized user handling
                commands.append(HardeningCommand(
                    command=f"""
                    # Get all users (not just UID >= 1000)
                    for user in $(awk -F: '{{{{ print $1 }}}}' /etc/passwd); do
                        # Skip authorized users
                        case "$user" in
                            {"|".join(authorized_users)})
                                echo "Skipping authorized user: $user"
                                ;;
                            *)
                                echo "Disabling unauthorized user: $user"
                                # Disable shell
                                usermod -s /bin/false $user 2>/dev/null || chsh -s /bin/false $user 2>/dev/null || true
                                ;;
                        esac
                    done
                    """.strip(),
                    description="Disable unauthorized user accounts",
                    requires_sudo=True
                ))
        except ValueError:
            # Default to Linux
            commands.append(HardeningCommand(
                command=f"""
                for user in $(awk -F: '{{{{ print $1 }}}}' /etc/passwd); do
                    case "$user" in
                        {"|".join(authorized_users)})
                            echo "Skipping authorized user: $user"
                            ;;
                        *)
                            echo "Disabling unauthorized user: $user"
                            usermod -s /bin/false $user 2>/dev/null || chsh -s /bin/false $user 2>/dev/null || true
                            ;;
                    esac
                done
                """.strip(),
                description="Disable unauthorized user accounts",
                requires_sudo=True
            ))
            
        return commands
    
    # TODO: write this as a script to /root/generate_users_report.sh, then execute it in the next command
    def _generate_user_report_command(self) -> str:
        """Generate command to create user security report"""
        return """
        cat > /root/user_security_report.txt << 'EOF'
User Security Report - Generated by CCDC User Hardening Module
============================================================

Regular Users (No sudo access):
EOF

for user in $(echo '{}' | tr ',' '\\n'); do
    if id "$user" >/dev/null 2>&1; then
        echo "✓ $user - $(getent passwd $user | cut -d: -f5) - Shell: $(getent passwd $user | cut -d: -f7)" >> /root/user_security_report.txt
        groups "$user" | grep -E '(sudo|wheel|admin)' >/dev/null && echo "  WARNING: User has sudo access!" >> /root/user_security_report.txt
    fi
done

echo "" >> /root/user_security_report.txt
echo "Super Users (Sudo access granted):" >> /root/user_security_report.txt

for user in $(echo '{}' | tr ',' '\\n'); do
    if id "$user" >/dev/null 2>&1; then
        echo "✓ $user - $(getent passwd $user | cut -d: -f5) - Shell: $(getent passwd $user | cut -d: -f7)" >> /root/user_security_report.txt
        groups "$user" | grep -E '(sudo|wheel|admin)' >/dev/null || echo "  WARNING: User lacks sudo access!" >> /root/user_security_report.txt
    fi
done

echo "" >> /root/user_security_report.txt
echo "Protected Accounts (No changes made):" >> /root/user_security_report.txt

for user in $(echo '{}' | tr ',' '\\n'); do
    if id "$user" >/dev/null 2>&1; then
        echo "✓ $user - $(getent passwd $user | cut -d: -f5) - Shell: $(getent passwd $user | cut -d: -f7)" >> /root/user_security_report.txt
    fi
done

echo "" >> /root/user_security_report.txt
echo "Secured/Locked Accounts:" >> /root/user_security_report.txt

for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {{ print $1 }}' /etc/passwd); do
    shell=$(getent passwd $user | cut -d: -f7)
    if [[ "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]]; then
        echo "🔒 $user - Shell disabled: $shell" >> /root/user_security_report.txt
    fi
done

echo "" >> /root/user_security_report.txt
echo "Report generated: $(date)" >> /root/user_security_report.txt
echo "User security hardening completed successfully!" >> /root/user_security_report.txt

echo "User security report generated at /root/user_security_report.txt"
        """.format(
            ",".join(self.users_config.get('regular_users', {}).keys()),
            ",".join(self.users_config.get('super_users', {}).keys()),
            ",".join(self.users_config.get('dontchange_accounts', {}).keys())
        ).strip()
    
    def is_applicable(self) -> bool:
        """This module is applicable to all Unix-like systems"""
        return True