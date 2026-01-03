# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CCDC Hardening Deployment Framework - An automated SSH-based system hardening tool for the Collegiate Cyber Defense Competition. It orchestrates discovery, lockdown, and hardening of Linux/BSD systems in parallel via Fabric.

## Commands

```bash
# Activate environment (required first)
source activate.sh

# Primary workflow - runs full hardening pipeline on all hosts
fab harden

# Discovery only (no changes)
fab discover-all
fab discover --host=192.168.1.10 --user=root --password=pass

# Test a specific module
fab test-module --module=ssh_hardening --live
# Available: user_hardening, ssh_hardening, firewall_hardening, package_installer, logging_setup

# Run a custom script on all hosts
fab run-script --file=scripts/all/my-script.sh

# List available hardening modules
fab list-modules

# SSH recovery/reset
fab reset-ssh

# Setup test environments
fab setup-test-env
```

## Architecture

```
fabfile.py              # Entry point - imports and exposes all tasks
tasks/                  # Fabric task definitions
  discovery.py          # System profiling commands
  hardening.py          # Main hardening orchestration
  tools.py              # Script deployment utilities
  maintenance.py        # Recovery operations
  testing.py            # Test environment setup
utilities/
  models.py             # Data classes: ServerInfo, UserInfo, OSInfo, etc.
  discovery.py          # SystemDiscovery class - OS/user/service detection
  deployment.py         # HardeningOrchestrator and HardeningDeployer
  utils.py              # Config loading, host parsing, password generation
  actions.py            # UserManager for cross-platform user operations
  modules/              # Hardening modules (each inherits HardeningModule)
    base.py             # Abstract base: HardeningModule, CommandAction, PythonAction
    user_hardening.py   # Password rotation, sudoers, user creation
    ssh_hardening.py    # sshd_config hardening, honeypot traps, Dead Man's Switch
    firewall_hardening.py  # Multi-backend firewall (firewalld/iptables/nftables/pf/ipfw)
    package_installer.py   # Cross-distro package management
    logging_setup.py    # rsyslog/auditd/journald configuration
scripts/all/            # Bash scripts deployed to remote hosts
  lockdown.sh           # Immediate firewall lockdown + panic button
  pre-hardening-snapshot.sh  # System state capture
```

## Configuration Files

- **hosts.txt**: Target inventory - `IP:User:Password[:Port][:FriendlyName]`
- **users.json**: User definitions with `regular_users`, `super_users`, `do_not_change_users`
  - Empty password = auto-generate; `__PER_HOST__` = unique per host
- **config.yaml**: Global settings (timeouts, trusted IPs, default scripts)
- **keys/root-key.pub**: SSH key injected for root persistence

## Module Development

All hardening modules in `utilities/modules/` inherit from `HardeningModule` and implement:
- `get_name()`: Unique identifier
- `get_commands()`: Returns list of `CommandAction` or `PythonAction` objects
- `is_applicable()`: OS compatibility check

Key patterns:
- Use `CommandAction` with `check_command` for idempotency
- Include `rollback_command` for safety-critical operations
- Dead Man's Switch: auto-revert on connection failure (see ssh_hardening, firewall_hardening)

## OS Support

Supports 13 OS families via `OSFamily` enum in `utilities/discovery.py`:
- Debian, Ubuntu, RHEL, CentOS, Fedora, Rocky, AlmaLinux
- SUSE, Arch, Alpine
- FreeBSD, OpenBSD, macOS

## Output Locations

- **Reports**: `reports/<host>/<timestamp>.md`
- **Logs**: `logs/harden/<host>/<timestamp>.log`
- **Passwords**: `logs/user-hardening/<host>/passwords_<timestamp>.txt`
