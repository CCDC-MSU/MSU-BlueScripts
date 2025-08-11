"""
Package installation module for CCDC framework
Installs useful packages using the appropriate package manager
"""
# to-do: might want to thin this list out a bit more
from typing import List, Dict, Set
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily


class PackageInstallerModule(HardeningModule):
    """Install useful packages for CCDC scenarios"""
    
    def get_name(self) -> str:
        return "package_installer"
    
    def get_commands(self) -> List[HardeningCommand]:
        try:
            os_family = OSFamily(self.os_family)
        except ValueError:
            os_family = OSFamily.UNKNOWN
        
        # Get available package managers from server info
        available_pms = set(self.server_info.package_managers)
        
        if os_family in [OSFamily.FREEBSD, OSFamily.OPENBSD, OSFamily.NETBSD, OSFamily.BSDGENERIC]:
            return self._get_bsd_commands(available_pms)
        elif os_family == OSFamily.DARWIN:
            return self._get_macos_commands(available_pms)
        elif os_family == OSFamily.ALPINE:
            return self._get_alpine_commands()
        elif os_family == OSFamily.ARCH:
            return self._get_arch_commands()
        else:
            return self._get_linux_commands(available_pms)
    
    def _get_package_categories(self) -> Dict[str, List[str]]:
        """Define package categories"""
        return {
            'security': [
                'nmap', 'wireshark', 'tcpdump', 'netstat-nat', 'ss', 'lsof',
                'chkrootkit', 'rkhunter', 'clamav', 'fail2ban', 'aide'
            ],
            'monitoring': [
                'htop', 'iotop', 'nethogs', 'iftop', 'dstat', 'sysstat',
                'logwatch', 'rsyslog', 'auditd'
            ],
            'networking': [
                'curl', 'wget', 'netcat', 'socat', 'telnet', 'ftp', 'openssh-client',
                'bind-utils', 'dnsutils', 'traceroute', 'mtr'
            ],
            'system': [
                'vim', 'nano', 'less', 'tree', 'file', 'which', 'locate',
                'psmisc', 'procps', 'util-linux', 'coreutils'
            ],
            'forensics': [
                'strace', 'ltrace', 'gdb', 'hexdump', 'strings', 'binutils',
                'sleuthkit', 'volatility'
            ],
            'development': [
                'git', 'make', 'gcc', 'python3', 'python3-pip', 'perl',
                'build-essential'
            ]
        }
    
    def _get_linux_package_mappings(self) -> Dict[str, Dict[str, str]]:
        """Map generic package names to distro-specific names"""
        return {
            'apt': {  # Debian/Ubuntu
                'bind-utils': 'dnsutils',
                'netstat-nat': 'net-tools',
                'ss': 'iproute2',
                'which': 'debianutils',
                'locate': 'mlocate',
                'build-essential': 'build-essential',
                'openssh-client': 'openssh-client'
            },
            'yum': {  # RHEL/CentOS 7
                'dnsutils': 'bind-utils',
                'net-tools': 'net-tools',
                'ss': 'iproute',
                'which': 'which',
                'locate': 'mlocate',
                'build-essential': 'gcc gcc-c++ make',
                'openssh-client': 'openssh-clients'
            },
            'dnf': {  # RHEL/CentOS 8+, Fedora
                'dnsutils': 'bind-utils',
                'net-tools': 'net-tools',
                'ss': 'iproute',
                'which': 'which',
                'locate': 'mlocate',
                'build-essential': 'gcc gcc-c++ make',
                'openssh-client': 'openssh-clients'
            }
        }
    
    def _get_linux_commands(self, available_pms: Set[str]) -> List[HardeningCommand]:
        """Commands for Linux systems"""
        commands = []
        package_categories = self._get_package_categories()
        package_mappings = self._get_linux_package_mappings()
        
        # Determine primary package manager
        pm_info = self._detect_linux_package_manager(available_pms)
        if not pm_info:
            return commands
        
        pm_cmd, pm_name = pm_info
        mapping = package_mappings.get(pm_name, {})
        
        # Update package lists first (synchronous - this is quick)
        commands.append(HardeningCommand(
            command=self._get_update_command(pm_cmd, pm_name),
            description=f"Update package lists ({pm_name})",
            requires_sudo=True
        ))
        
        # Create background installation script
        commands.append(HardeningCommand(
            command="mkdir -p /tmp/ccdc_install && touch /tmp/ccdc_install/install.log",
            description="Create package installation directory",
            check_command="test -d /tmp/ccdc_install && echo exists",
            requires_sudo=True
        ))
        
        # Build comprehensive package list for background installation
        all_packages = []
        for category, packages in package_categories.items():
            for pkg in packages:
                mapped_pkg = mapping.get(pkg, pkg)
                if ' ' in mapped_pkg:  # Handle compound packages
                    all_packages.extend(mapped_pkg.split())
                else:
                    all_packages.append(mapped_pkg)
        
        # Remove duplicates while preserving order
        unique_packages = list(dict.fromkeys(all_packages))
        pkg_list = ' '.join(unique_packages)
        
        # Create background installation script
        install_script = f'''#!/bin/bash
# CCDC Background Package Installation Script
LOG_FILE="/tmp/ccdc_install/install.log"
STATUS_FILE="/tmp/ccdc_install/status"
PID_FILE="/tmp/ccdc_install/install.pid"

echo "RUNNING" > "$STATUS_FILE"
echo $$ > "$PID_FILE"

echo "$(date): Starting background package installation" >> "$LOG_FILE"
echo "$(date): Installing packages: {pkg_list}" >> "$LOG_FILE"

# Redirect all output to log file
exec 1>> "$LOG_FILE" 2>&1

echo "$(date): Running {pm_cmd} install -y {pkg_list}"
if {pm_cmd} install -y {pkg_list}; then
    echo "$(date): Package installation completed successfully"
    echo "COMPLETED" > "$STATUS_FILE"
else
    echo "$(date): Package installation failed with exit code $?"
    echo "FAILED" > "$STATUS_FILE"
fi

rm -f "$PID_FILE"
echo "$(date): Background installation finished" >> "$LOG_FILE"
'''
        
        commands.append(HardeningCommand(
            command=f'cat > /tmp/ccdc_install/install_packages.sh << "EOF"\n{install_script}\nEOF',
            description="Create background package installation script",
            requires_sudo=True
        ))
        
        # Make script executable
        commands.append(HardeningCommand(
            command="chmod +x /tmp/ccdc_install/install_packages.sh",
            description="Make installation script executable",
            requires_sudo=True
        ))
        
        # Start background installation (non-blocking)
        commands.append(HardeningCommand(
            command="nohup /tmp/ccdc_install/install_packages.sh </dev/null >/dev/null 2>&1 & echo 'Background installation started'",
            description=f"Start background package installation ({pm_name})",
            requires_sudo=True
        ))
        
        # Add status check command
        commands.append(HardeningCommand(
            command='echo "Package installation status: $(cat /tmp/ccdc_install/status 2>/dev/null || echo UNKNOWN)"',
            description="Show initial package installation status",
            requires_sudo=False
        ))
        
        return commands
    
    def _get_bsd_commands(self, available_pms: Set[str]) -> List[HardeningCommand]:
        """Commands for BSD systems"""
        commands = []
        
        # BSD package categories
        bsd_packages = {
            'security': ['nmap', 'wireshark', 'tcpdump', 'lsof', 'chkrootkit', 'clamav'],
            'monitoring': ['htop', 'iotop', 'iftop', 'sysstat'],
            'networking': ['curl', 'wget', 'netcat', 'socat', 'bind-tools', 'traceroute', 'mtr'],
            'system': ['vim', 'nano', 'tree', 'bash', 'zsh'],
            'development': ['git', 'gmake', 'gcc', 'python3', 'perl5']
        }
        
        if 'pkg' in available_pms:  # FreeBSD
            # Update package repository (quick operation)
            commands.append(HardeningCommand(
                command="pkg update",
                description="Update FreeBSD package repository",
                requires_sudo=True
            ))
            
            # Create background installation directory
            commands.append(HardeningCommand(
                command="mkdir -p /tmp/ccdc_install && touch /tmp/ccdc_install/install.log",
                description="Create package installation directory",
                check_command="test -d /tmp/ccdc_install && echo exists",
                requires_sudo=True
            ))
            
            # Build comprehensive package list
            all_packages = []
            for packages in bsd_packages.values():
                all_packages.extend(packages)
            pkg_list = ' '.join(all_packages)
            
            # Create background installation script for FreeBSD
            install_script = f'''#!/bin/sh
# CCDC Background Package Installation Script (FreeBSD)
LOG_FILE="/tmp/ccdc_install/install.log"
STATUS_FILE="/tmp/ccdc_install/status"
PID_FILE="/tmp/ccdc_install/install.pid"

echo "RUNNING" > "$STATUS_FILE"
echo $$ > "$PID_FILE"

echo "$(date): Starting FreeBSD background package installation" >> "$LOG_FILE"
echo "$(date): Installing packages: {pkg_list}" >> "$LOG_FILE"

# Redirect all output to log file
exec 1>> "$LOG_FILE" 2>&1

echo "$(date): Running pkg install -y {pkg_list}"
if pkg install -y {pkg_list}; then
    echo "$(date): Package installation completed successfully"
    echo "COMPLETED" > "$STATUS_FILE"
else
    echo "$(date): Package installation failed with exit code $?"
    echo "FAILED" > "$STATUS_FILE"
fi

rm -f "$PID_FILE"
echo "$(date): Background installation finished" >> "$LOG_FILE"
'''
            
            commands.append(HardeningCommand(
                command=f'cat > /tmp/ccdc_install/install_packages.sh << "EOF"\n{install_script}\nEOF',
                description="Create background package installation script",
                requires_sudo=True
            ))
            
            commands.append(HardeningCommand(
                command="chmod +x /tmp/ccdc_install/install_packages.sh",
                description="Make installation script executable", 
                requires_sudo=True
            ))
            
            commands.append(HardeningCommand(
                command="nohup /tmp/ccdc_install/install_packages.sh </dev/null >/dev/null 2>&1 & echo 'Background installation started'",
                description="Start background package installation (FreeBSD)",
                requires_sudo=True
            ))
            
        elif any(pm in available_pms for pm in ['pkg_add', 'pkg_info']):  # OpenBSD/NetBSD
            # For OpenBSD/NetBSD, install essential packages (these are usually quick)
            essential_packages = ['curl', 'wget', 'vim', 'htop', 'git', 'nmap']
            
            # Create installation tracking
            commands.append(HardeningCommand(
                command="mkdir -p /tmp/ccdc_install && echo 'RUNNING' > /tmp/ccdc_install/status",
                description="Create package installation directory",
                requires_sudo=True
            ))
            
            # Install essential packages in background
            pkg_list = ' '.join(essential_packages)
            install_script = f'''#!/bin/sh
LOG_FILE="/tmp/ccdc_install/install.log"
STATUS_FILE="/tmp/ccdc_install/status"

echo "$(date): Starting OpenBSD/NetBSD package installation" >> "$LOG_FILE"
failed=0
for pkg in {' '.join(essential_packages)}; do
    echo "$(date): Installing $pkg" >> "$LOG_FILE"
    if ! pkg_add "$pkg" >> "$LOG_FILE" 2>&1; then
        echo "$(date): Failed to install $pkg" >> "$LOG_FILE"
        failed=1
    fi
done

if [ $failed -eq 0 ]; then
    echo "COMPLETED" > "$STATUS_FILE"
else
    echo "PARTIAL" > "$STATUS_FILE"
fi
echo "$(date): Installation finished" >> "$LOG_FILE"
'''
            
            commands.append(HardeningCommand(
                command=f'cat > /tmp/ccdc_install/install_packages.sh << "EOF"\n{install_script}\nEOF && chmod +x /tmp/ccdc_install/install_packages.sh',
                description="Create BSD package installation script",
                requires_sudo=True
            ))
            
            commands.append(HardeningCommand(
                command="nohup /tmp/ccdc_install/install_packages.sh </dev/null >/dev/null 2>&1 & echo 'Background installation started'",
                description="Start background package installation (OpenBSD/NetBSD)",
                requires_sudo=True
            ))
        
        # Add status check command for BSD systems  
        commands.append(HardeningCommand(
            command='echo "Package installation status: $(cat /tmp/ccdc_install/status 2>/dev/null || echo UNKNOWN)"',
            description="Show initial package installation status",
            requires_sudo=False
        ))
        
        return commands
    
    def _get_macos_commands(self, available_pms: Set[str]) -> List[HardeningCommand]:
        """Commands for macOS systems"""
        commands = []
        
        if 'brew' in available_pms:
            # Homebrew packages for macOS
            macos_packages = {
                'security': ['nmap', 'wireshark', 'clamav'],
                'monitoring': ['htop', 'iftop'],
                'networking': ['curl', 'wget', 'netcat', 'socat', 'bind', 'traceroute', 'mtr'],
                'system': ['vim', 'tree', 'watch', 'gnu-sed', 'gnu-tar'],
                'development': ['git', 'make', 'gcc', 'python3']
            }
            
            # Update Homebrew
            commands.append(HardeningCommand(
                command="brew update",
                description="Update Homebrew package lists",
                requires_sudo=False
            ))
            
            # Install packages
            for category, packages in macos_packages.items():
                pkg_list = ' '.join(packages)
                commands.append(HardeningCommand(
                    command=f"brew install {pkg_list}",
                    description=f"Install {category} packages (Homebrew)",
                    requires_sudo=False
                ))
        else:
            # Install Homebrew first if not available
            commands.append(HardeningCommand(
                command='/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
                description="Install Homebrew package manager",
                requires_sudo=False
            ))
        
        return commands
    
    def _get_alpine_commands(self) -> List[HardeningCommand]:
        """Commands for Alpine Linux"""
        commands = []
        
        alpine_packages = {
            'security': ['nmap', 'tcpdump', 'lsof', 'clamav'],
            'monitoring': ['htop', 'iotop'],
            'networking': ['curl', 'wget', 'netcat-openbsd', 'socat', 'bind-tools'],
            'system': ['vim', 'nano', 'tree', 'bash'],
            'development': ['git', 'make', 'gcc', 'python3', 'py3-pip']
        }
        
        # Update package index
        commands.append(HardeningCommand(
            command="apk update",
            description="Update Alpine package index",
            requires_sudo=True
        ))
        
        # Install packages
        for category, packages in alpine_packages.items():
            pkg_list = ' '.join(packages)
            commands.append(HardeningCommand(
                command=f"apk add {pkg_list}",
                description=f"Install {category} packages (Alpine)",
                requires_sudo=True
            ))
        
        return commands
    
    def _get_arch_commands(self) -> List[HardeningCommand]:
        """Commands for Arch Linux"""
        commands = []
        
        arch_packages = {
            'security': ['nmap', 'wireshark-qt', 'tcpdump', 'lsof', 'chkrootkit', 'rkhunter', 'clamav'],
            'monitoring': ['htop', 'iotop', 'nethogs', 'iftop', 'sysstat'],
            'networking': ['curl', 'wget', 'gnu-netcat', 'socat', 'bind-tools', 'traceroute', 'mtr'],
            'system': ['vim', 'nano', 'tree', 'which', 'locate', 'psmisc'],
            'development': ['git', 'make', 'gcc', 'python', 'python-pip']
        }
        
        # Update package database
        commands.append(HardeningCommand(
            command="pacman -Sy",
            description="Update Arch package database",
            requires_sudo=True
        ))
        
        # Install packages
        for category, packages in arch_packages.items():
            pkg_list = ' '.join(packages)
            commands.append(HardeningCommand(
                command=f"pacman -S --noconfirm {pkg_list}",
                description=f"Install {category} packages (Arch)",
                requires_sudo=True
            ))
        
        return commands
    
    def _detect_linux_package_manager(self, available_pms: Set[str]) -> tuple:
        """Detect the primary package manager for Linux systems"""
        # Priority order for package managers
        pm_priority = [
            ('apt-get', 'apt'),
            ('dnf', 'dnf'), 
            ('yum', 'yum'),
            ('zypper', 'zypper'),
            ('pacman', 'pacman'),
            ('apk', 'apk')
        ]
        
        for pm_cmd, pm_name in pm_priority:
            if pm_name in available_pms:
                return (pm_cmd, pm_name)
        
        return None
    
    def _get_update_command(self, pm_cmd: str, pm_name: str) -> str:
        """Get the appropriate update command for the package manager"""
        update_commands = {
            'apt': 'apt-get update',
            'dnf': 'dnf check-update || true',  # dnf returns 100 when updates available
            'yum': 'yum check-update || true',   # yum returns 100 when updates available
            'zypper': 'zypper refresh',
            'pacman': 'pacman -Sy',
            'apk': 'apk update'
        }
        
        return update_commands.get(pm_name, f'{pm_cmd} update')
    
    def is_applicable(self) -> bool:
        """This module is applicable if we have any package managers available"""
        return len(self.server_info.package_managers) > 0