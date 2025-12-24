"""
Package installation module for CCDC framework
Installs useful packages using the appropriate package manager
"""

from typing import List, Dict, Set
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily

PACKAGE_MANAGER_INSTALL_CMD = {
    # Debian/Ubuntu
    "apt":      "DEBIAN_FRONTEND=noninteractive apt-get install -y {}",

    # RHEL/CentOS/Fedora
    "yum":      "yum install -y {}",
    "dnf":      "dnf install -y {}",

    # SUSE/openSUSE
    "zypper":   "zypper --non-interactive install {}",

    # Arch
    "pacman":   "pacman -S {} --noconfirm",

    # Gentoo
    "emerge":   "PAGER=cat emerge --ask=n {}",

    # Alpine
    "apk":      "apk add {}",

    # FreeBSD
    "pkg":      "pkg install -y {}",

    # macOS (Homebrew)
    "brew":     "brew install {}",

    # Snap
    "snap":     "snap install {}",

    # Flatpak (assumes flathub remote is configured)
    "flatpak":  "flatpak install -y --noninteractive flathub {}",

    # Slackware
    "slackpkg": "slackpkg -batch=on -default_answer=y install {}",
}

PACKAGE_MANAGER_UPDATE_CMD = {
    # Debian/Ubuntu
    # refresh + upgrade
    "apt":      "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",

    # RHEL/CentOS (yum)
    # makecache/metadata refresh + upgrade
    "yum":      "yum makecache -y && yum update -y",

    # Fedora/RHEL8+ (dnf)
    "dnf":      "dnf makecache -y && dnf upgrade -y",

    # SUSE/openSUSE
    # refresh repos + update
    "zypper":   "zypper --non-interactive refresh && zypper --non-interactive update",

    # Arch
    # updating keys + sync db + upgrade system
    "pacman":   "sudo pacman-key --init; sudo pacman-key --populate archlinux; sudo pacman-key --refresh-keys; sudo pacman -Sy --needed archlinux-keyring --noconfirm; pacman -Syu --noconfirm",

    # Gentoo
    # sync repo + update world (incl deps) + rebuild if needed
    # "emerge":   "PAGER=cat emerge --sync && PAGER=cat FEATURES="getbinpkg" ACCEPT_KEYWORDS="~amd64" emerge -uD @world --ask=n", 
    "emerge":   "true",  # can't afford 8 hour update times

    # Alpine
    # refresh index + upgrade
    "apk":      "apk update && apk upgrade",

    # FreeBSD
    # refresh catalogs + upgrade packages
    "pkg":      "pkg update -f && pkg upgrade -y",

    # macOS (Homebrew)
    # update formulae + upgrade installed
    "brew":     "brew update && brew upgrade",

    # Snap
    # snaps auto-refresh by default; explicit refresh updates all
    "snap":     "snap refresh",

    # Flatpak
    # update installed flatpaks (usually no separate "refresh" needed)
    "flatpak":  "flatpak update -y --noninteractive",

    # Slackware
    # update package lists + upgrade all
    "slackpkg": "slackpkg -batch=on -default_answer=y update && slackpkg -batch=on -default_answer=y upgrade-all",
}

PACKAGE_MANAGER_UNINSTALL_CMD = {
    # Debian/Ubuntu
    "apt":      "DEBIAN_FRONTEND=noninteractive apt-get remove -y {}",

    # RHEL/CentOS/Fedora
    "yum":      "yum remove -y {}",
    "dnf":      "dnf remove -y {}",

    # SUSE/openSUSE
    "zypper":   "zypper --non-interactive remove {}",

    # Arch
    "pacman":   "pacman -R --noconfirm {}",

    # Gentoo
    "emerge":   "PAGER=cat emerge --unmerge --ask=n {}",

    # Alpine
    "apk":      "apk del {}",

    # FreeBSD
    "pkg":      "pkg delete -y {}",

    # macOS (Homebrew)
    "brew":     "brew uninstall {}",

    # Snap
    "snap":     "snap remove {}",

    # Flatpak
    "flatpak":  "flatpak uninstall -y --noninteractive {}",

    # Slackware
    "slackpkg": "slackpkg -batch=on -default_answer=y remove {}",
}

PACKAGE_MANAGER_REMOVE_UNUSED = {
    # Debian/Ubuntu
    "apt":      "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y && DEBIAN_FRONTEND=noninteractive apt-get autoclean -y",

    # RHEL/CentOS/Fedora
    "yum":      "yum autoremove -y",
    "dnf":      "dnf autoremove -y",

    # SUSE/openSUSE
    # Remove packages flagged as "unneeded" (best-effort; no exact apt autoremove equivalent)
    "zypper":   r"""zypper packages --unneeded | awk -F'|' '/^i/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' | xargs -r zypper --non-interactive rm --clean-deps || true""",

    # Arch
    "pacman":   r"""orphans="$(pacman -Qtdq 2>/dev/null || true)"; [ -n "$orphans" ] && pacman -Rns --noconfirm $orphans || true""",

    # Gentoo
    "emerge":   "PAGER=cat emerge --depclean --ask=n",

    # Alpine
    "apk":      "apk autoremove",

    # FreeBSD
    "pkg":      "pkg autoremove -y",

    # macOS (Homebrew)
    "brew":     "brew autoremove && brew cleanup",

    # Snap
    # Remove disabled (old) revisions
    "snap":     r"""LANG=C snap list --all | awk '/disabled/{print $1, $3}' | while read -r snapname revision; do snap remove "$snapname" --revision="$revision"; done""",

    # Flatpak
    "flatpak":  "flatpak uninstall --unused -y --noninteractive",

    # Slackware
    # Removes packages not in the official Slackware set
    "slackpkg": "slackpkg -batch=on -default_answer=y clean-system",
}

PACKAGE_MANAGER_VALIDATE_INSTALLED = {
    # Debian/Ubuntu
    "apt":      "dpkg --verify",

    # RHEL/CentOS/Fedora
    "yum":      "rpm -Va",
    "dnf":      "rpm -Va",

    # SUSE/openSUSE
    "zypper":   "rpm -Va",

    # Arch
    "pacman":   "pacman -Qkk",

    # Gentoo
    "emerge":   "qcheck",

    # Alpine
    "apk":      "apk verify -a",

    # FreeBSD
    "pkg":      "pkg check -a -s",

    # macOS (Homebrew)
    "brew":     "brew doctor",

    # Snap
    # Best-effort: verify snapshot data integrity for all snaps (not a per-file package verify)
    "snap":     r"""id="$(snap save | awk 'NR==2{print $1}')"; [ -n "$id" ] && snap check-snapshot "$id" """,

    # Flatpak
    "flatpak":  "flatpak repair --system -y --noninteractive || flatpak repair --user -y --noninteractive",

    # Slackware
    # Best-effort: re-download + reinstall (signature-checked) official packages
    "slackpkg": r"""slackpkg -batch=on -default_answer=y reinstall \*""",
}

class PackageInstallerModule(HardeningModule):
    """Install useful packages for CCDC scenarios"""

    def __init__(self, connection, server_info, os_family):
        super().__init__(connection, server_info, os_family)

        self.package_manager =  None
        for pm in server_info.package_managers:
            if pm not in PACKAGE_MANAGER_INSTALL_CMD:
                print(f"WARNING: Unsupported package manager: {self.package_manager!r}")
            else:
                self.package_manager = pm
                print(f"Info: Using the package manager {self.package_manager}")
                break
        
        if not self.package_manager:
            print(f'ERROR: None of the detected package managers {server_info.package_managers} is supported!')


    def get_name(self) -> str:
        return "package_installer"
    
    def get_commands(self) -> List[HardeningCommand]:
        if not self.package_manager:        # if a valid package manager is not found return
            return []

        packages_to_install = self._get_linux_package_mappings(self.package_manager)    # get the dict [common-name: package_manager-specific-name]
        install_cmd_template = PACKAGE_MANAGER_INSTALL_CMD[self.package_manager]        # get the package manager command to install packages
        
        commands: list[HardeningCommand] = []

        package_install_commands: list[str] = []

        for friendly_name in packages_to_install:
            package_install_commands.append(install_cmd_template.format(packages_to_install[friendly_name]))
        
        command_str = "\n".join(package_install_commands)

        # update existing packages
        commands.append(HardeningCommand(
            command=PACKAGE_MANAGER_UPDATE_CMD.get(self.package_manager, 'false'),
            description="Updating and upgrading all the packages",
            requires_sudo=True
        ))

        # install packages
        commands.append(HardeningCommand(
            command=command_str,
            description="install all required packages",
            requires_sudo=True
        ))

        # remove unused
        commands.append(HardeningCommand(
            command=PACKAGE_MANAGER_REMOVE_UNUSED.get(self.package_manager,"false"),
            description="removing unused packages",
            requires_sudo=True
        ))

        # verify installed
        commands.append(HardeningCommand(
            command=PACKAGE_MANAGER_VALIDATE_INSTALLED.get(self.package_manager,"false"),
            description="Verify installed packages",
            requires_sudo=True
        ))

        return commands

    def _get_linux_package_mappings(self, package_manager) -> Dict[str, Dict[str, str]]:
        """
        Map your generic package names (the keys) to the package name used by each
        package manager/distro ecosystem (the values).

        Notes:
        - snap/flatpak are app-centric; many low-level admin tools are not consistently
            available. For snap I mapped the ones I could confirm; the rest fall back to
            the generic name (you may want to validate availability at runtime).
        - pkg here is aligned to FreeBSD ports/pkgng naming where it differs.
        - brew is aligned to Homebrew; some formulae are Linux-only (Homebrew shows bottles).
        """
        all_generic = [
            # security
            "tcpdump", "ss", "rkhunter", "fail2ban", "aide",
            # monitoring
            "rsyslog", "auditd",
            # networking
            "curl",
            # system
            "vim", "nano", "less", "tree", "file", "which",
            "psmisc", "procps", "util-linux", "coreutils",
            # forensics
            "strace", "strings",
            # development
            "python3",
        ]

        def identity_map(overrides: Dict[str, str]) -> Dict[str, str]:
            m = {k: k for k in all_generic}
            m.update(overrides)
            return m

        package_mappings = {
            # Debian/Ubuntu
            "apt": identity_map({
                "ss": "iproute2",
                "which": "debianutils",
                "strings": "binutils",
                # auditd is already "auditd" on Debian/Ubuntu
            }),

            # RHEL/CentOS (yum, esp. 7.x)
            "yum": identity_map({
                "ss": "iproute",
                "auditd": "audit",
                "procps": "procps-ng",
                "vim": "vim-enhanced",
                "strings": "binutils",
            }),

            # RHEL/CentOS 8+/Fedora (dnf)
            "dnf": identity_map({
                "ss": "iproute",
                "auditd": "audit",
                "procps": "procps-ng",
                "vim": "vim-enhanced",
                "strings": "binutils",
            }),

            # openSUSE/SLES
            "zypper": identity_map({
                "ss": "iproute2",
                "auditd": "audit",
                "strings": "binutils",
            }),

            # Arch/Manjaro
            "pacman": identity_map({
                "ss": "iproute2",
                "auditd": "audit",
                "procps": "procps-ng",
                "python3": "python",
                "strings": "binutils",
            }),

            # Gentoo (category/package atoms)
            "emerge": identity_map({
                "tcpdump":  "net-analyzer/tcpdump",
                "ss":       "sys-apps/iproute2",
                "rkhunter": "app-forensics/rkhunter",
                "fail2ban": "net-analyzer/fail2ban",
                "aide":     "app-forensics/aide",

                "rsyslog":  "app-admin/rsyslog",
                "auditd":   "sys-process/audit",

                "curl":     "net-misc/curl",

                "vim":      "app-editors/vim",
                "nano":     "app-editors/nano",
                "less":     "sys-apps/less",
                "tree":     "app-text/tree",
                "file":     "sys-apps/file",
                "which":    "sys-apps/which",
                "psmisc":   "sys-process/psmisc",
                "procps":   "sys-process/procps",
                "util-linux":"sys-apps/util-linux",
                "coreutils":"sys-apps/coreutils",

                "strace":   "dev-debug/strace",
                "strings":  "sys-devel/binutils",

                "python3":  "dev-lang/python",
            }),

            # Alpine (apk)
            "apk": identity_map({
                "ss": "iproute2-ss",
                "auditd": "audit",
                "strings": "binutils",
            }),

            # FreeBSD (pkgng) — best-effort equivalents
            "pkg": identity_map({
                # many are available as ports; a few are base-system on FreeBSD
                # (you may choose to skip installing those).
                "fail2ban": "py311-fail2ban",  # commonly used on FreeBSD 14.x
                "strings": "binutils",
                "ss": "sockstat",              # closest built-in equivalent (no iproute2)
                "auditd": "auditd",            # base-system service on FreeBSD
                "python3": "python3",
            }),

            # Homebrew (brew) — best-effort (some formulae are Linux-only)
            "brew": identity_map({
                "ss": "iproute2mac",
                "procps": "procps",
                "python3": "python",
                "strings": "binutils",
            }),

            # Snap — only a few of these have well-known snaps; others vary by publisher.
            "snap": identity_map({
                "tcpdump": "tcpdump",
                "curl": "curl",
                "coreutils": "rust-coreutils",
                "strace": "strace-static",
                # leave the rest as identity (may or may not exist in the Snap Store)
            }),

            # Flatpak — generally not used for these low-level CLI/admin tools.
            # Keep identity for completeness; you may want to treat this manager as "unsupported"
            # for this package set and fall back to the distro manager.
            "flatpak": identity_map({}),

            # Slackware (slackpkg)
            "slackpkg": identity_map({
                "ss": "iproute2",
                "procps": "procps-ng",
                "auditd": "audit",     # often via SlackBuilds; not always in the base set
                "strings": "binutils",
            }),
        }

        return package_mappings.get(package_manager, {})

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