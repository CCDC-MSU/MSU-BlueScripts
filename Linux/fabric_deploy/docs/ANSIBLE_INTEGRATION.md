# Ansible Integration Guide

**Hybrid Ansible/Fabric Architecture for Cross-Distribution Package Management**

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [How It Works](#how-it-works)
5. [Integration with Hardening Pipeline](#integration-with-hardening-pipeline)
6. [Configuration Files](#configuration-files)
7. [Workflow Details](#workflow-details)
8. [Testing](#testing)
9. [Troubleshooting](#troubleshooting)

---

## Overview

### The Problem
Different Linux distributions use different package managers and package names:
- **Debian/Ubuntu**: `apt` → `auditd`, `rsyslog`
- **RHEL/CentOS/Fedora**: `dnf`/`yum` → `audit`, `rsyslog`
- **Arch**: `pacman` → `audit`, `rsyslog` (not in default repos)
- **Alpine**: `apk` → `audit`, `rsyslog`
- **openSUSE**: `zypper` → `audit`, `rsyslog`

Managing these differences in pure Fabric/Python SSH code would require extensive conditional logic and error handling.

### The Solution: Hybrid Approach
We use **Ansible for package installation only**, and **Fabric for everything else**:

- ✅ **Ansible handles**: Cross-distro package installation (rsyslog, auditd, logrotate)
- ✅ **Fabric handles**: System discovery, configuration deployment, service management, all other hardening

This keeps the "click and go" workflow intact while solving the cross-platform package management problem elegantly.

### Supported Distributions
The hybrid system has been tested and works on:
- Alpine Linux 3.21+
- Arch Linux (latest)
- Debian 13 (Trixie)
- CentOS Stream 10
- Fedora 43
- Rocky Linux 9+
- openSUSE Tumbleweed
- Slackware 15+
- Gentoo (latest)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Control Node (Your Machine)              │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Fabric Orchestrator (Python/Paramiko)              │   │
│  │  - System discovery                                  │   │
│  │  - User management                                   │   │
│  │  - Configuration deployment                          │   │
│  │  - Service management                                │   │
│  └──────────────────┬───────────────────────────────────┘   │
│                     │                                        │
│                     │ Calls when needed                      │
│                     ↓                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Ansible Engine                                      │   │
│  │  - Package installation (cross-distro)               │   │
│  │  - Handles package name differences                  │   │
│  └──────────────────┬───────────────────────────────────┘   │
│                     │                                        │
└─────────────────────┼────────────────────────────────────────┘
                      │
                      │ SSH Connection
                      ↓
         ┌────────────────────────────┐
         │   Remote Hosts (Targets)   │
         │  - Package installation    │
         │  - Configuration           │
         │  - Service management      │
         └────────────────────────────┘
```

### Component Breakdown

**1. Fabric Layer** (`utilities/`, `tasks/`, `fabfile.py`)
   - Primary orchestration engine
   - Handles SSH connections via Paramiko
   - Executes discovery, configuration, and most hardening steps

**2. Ansible Layer** (`ansible/`)
   - Secondary execution engine (invoked as subprocess from Fabric)
   - **Only used for package installation**
   - Automatically handles distro-specific package names and managers

**3. Configuration Sync** (`ansible/generate_configs.py`)
   - Auto-generates Ansible inventory from `hosts.txt`
   - Syncs configuration templates from `configs/` directory
   - Runs before every Ansible operation to ensure consistency

**4. Module Integration** (`utilities/modules/logging_setup.py`)
   - Hardening modules can call `_install_packages_via_ansible()`
   - Seamlessly integrates Ansible into Fabric workflow
   - Falls back gracefully if Ansible fails

---

## Requirements

### Control Node Requirements (Your Machine)

**Required:**
1. **Python 3.8+** (for Fabric and uv)
2. **uv** (Python package manager) - Install: `curl -LsSf https://astral.sh/uv/install.sh | sh`
3. **Ansible 2.14+** - Install: `pip install ansible` or `apt install ansible`
4. **SSH connectivity** to all target hosts

**Included in uv environment:**
- fabric
- paramiko
- pyyaml
- invoke

### Target Host Requirements

**Nothing extra!** The Ansible integration handles everything:
- No Python installation required on targets (Ansible uses raw commands when needed)
- No Ansible installation required on targets
- Only standard SSH access needed

### Verify Installation

Check if Ansible is installed:
```bash
ansible --version
```

Expected output:
```
ansible [core 2.16.3]
  config file = None
  configured module search path = [...]
  ansible python module location = /usr/lib/python3/dist-packages/ansible
  ansible collection location = ...
  executable location = /usr/bin/ansible
  python version = 3.12.7
```

If not installed:
```bash
# Debian/Ubuntu
sudo apt install ansible

# RHEL/CentOS/Fedora
sudo dnf install ansible

# macOS
brew install ansible

# Python pip (any OS)
pip install ansible
```

---

## How It Works

### Step-by-Step Flow

Let's trace what happens when you run `fab harden`:

**1. Fabric Discovery Phase** (Pure Fabric)
```
fab harden
  └─> HardeningOrchestrator.run()
      └─> SystemDiscovery.discover()
          - Detects OS family, version, package manager
          - Inventories users, groups, services
          - Stores results in ServerInfo object
```

**2. Module Execution Phase** (Hybrid)
```
  └─> HardeningDeployer.deploy()
      └─> Step 13: logging_setup module
          ├─> _install_packages_via_ansible()  ← ANSIBLE CALL
          │   ├─> Syncs configs (generate_configs.py)
          │   │   - Converts hosts.txt → ansible/inventory/hosts.yaml
          │   │   - Copies configs/ → ansible/roles/*/templates/
          │   └─> Runs: ansible-playbook install_logging_packages.yaml
          │       - Detects distro automatically
          │       - Installs rsyslog, auditd, logrotate
          │       - Handles missing packages gracefully
          ├─> _configure_rsyslog()              ← FABRIC COMMANDS
          │   - Deploys /etc/rsyslog.d/ccdc-security.conf
          │   - Sets permissions
          │   - Restarts service
          ├─> _configure_journald()             ← FABRIC COMMANDS
          └─> _configure_auditd()               ← FABRIC COMMANDS
```

**3. Ansible Subprocess Details**
```python
# In utilities/modules/logging_setup.py:

def _install_packages_via_ansible(self, conn, server_info):
    # 1. Sync inventory and configs
    subprocess.run(['python3', 'generate_configs.py'], cwd='ansible/')

    # 2. Look up Ansible hostname for this IP
    friendly_name = self._get_ansible_hostname_for_ip(server_info.host)

    # 3. Run Ansible playbook
    result = subprocess.run([
        'ansible-playbook',
        'playbooks/install_logging_packages.yaml',
        '--limit', friendly_name,  # Only target this host
        '-v'
    ], cwd='ansible/', timeout=300)

    # 4. Return HardeningResult
    return HardeningResult(success=True, ...)
```

**4. Ansible Playbook Execution** (ansible/playbooks/install_logging_packages.yaml)
```yaml
- name: Install logging packages
  hosts: all
  become: yes
  tasks:
    # Debian/Ubuntu
    - block:
        - apt:
            name: [rsyslog, auditd, logrotate]
            state: present
      when: ansible_os_family == 'Debian'

    # RHEL/CentOS/Fedora
    - block:
        - dnf:
            name: [rsyslog, audit, logrotate]  # Note: 'audit' not 'auditd'
            state: present
      when: ansible_os_family == 'RedHat'

    # ... (9 distro families total)
```

---

## Integration with Hardening Pipeline

### Where Ansible Fits in the 14-Step Pipeline

From `docs/workflow_guide.md`, step 13 is "Logging Setup". Here's what happens:

```
Pipeline Step 13: Logging Setup
├─ [Ansible] Install packages (rsyslog, auditd, logrotate)
│   Duration: ~5-15 seconds per host
│   Handles: Cross-distro package differences
│
├─ [Fabric] Backup existing configs
├─ [Fabric] Deploy /etc/rsyslog.d/ccdc-security.conf
├─ [Fabric] Create log files (/var/log/auth.log, etc.)
├─ [Fabric] Set restrictive permissions (chmod 640)
├─ [Fabric] Restart rsyslog service
├─ [Fabric] Configure systemd-journald
├─ [Fabric] Deploy /etc/audit/rules.d/ccdc.rules
├─ [Fabric] Load audit rules (auditctl -R)
├─ [Fabric] Restart auditd service
├─ [Fabric] Configure logrotate
└─ [Fabric] Enable bash history timestamps
```

### Full Pipeline Context

```
1.  Discovery                 [Fabric only]
2.  Snapshot                  [Fabric only]
3.  User Hardening (Round 1)  [Fabric only]
4.  Firewall Setup            [Fabric only]
5.  Lockdown Script           [Fabric only]
6.  SSH Hardening             [Fabric only]
7.  Script Uploads            [Fabric only]
8.  Local Fixes               [Fabric only]
9.  Reboot                    [Fabric only]
10. User Hardening (Round 2)  [Fabric only]
11. Allow Internet            [Fabric only]
12. Install & Update          [Could use Ansible - currently Fabric]
13. Logging Setup             [Hybrid: Ansible + Fabric] ← YOU ARE HERE
14. Final Snapshot            [Fabric only]
```

### Why Only Logging Setup Uses Ansible (For Now)?

**Current State:**
- Only `logging_setup` module uses Ansible integration
- Works perfectly for its use case (rsyslog, auditd, logrotate)

**Future Expansion Potential:**
The pattern is reusable. Other modules *could* use Ansible for package installation:
- `firewall_hardening` - Install iptables, firewalld, ufw, nftables
- `package_installer` - Full package management via Ansible
- Custom security tools installation

To add Ansible to another module:
1. Create playbook in `ansible/playbooks/`
2. Add `_install_packages_via_ansible()` to module
3. Test with `fab test-module --module=your_module --live`

---

## Configuration Files

### Auto-Generated Files (DO NOT EDIT MANUALLY)

These files are **regenerated automatically** from source files:

| Generated File | Source File | Regeneration Trigger |
|----------------|-------------|---------------------|
| `ansible/inventory/hosts.yaml` | `hosts.txt` | Every Ansible call |
| `ansible/group_vars/all.yml` | `users.json` | Every Ansible call |
| `ansible/roles/*/templates/*.j2` | `configs/rsyslog.conf`, etc. | Every Ansible call |

**How regeneration works:**
```python
# In utilities/modules/logging_setup.py, before every Ansible call:
subprocess.run(['python3', 'generate_configs.py'], cwd='ansible/')
```

**Example: hosts.txt → inventory/hosts.yaml**

`hosts.txt`:
```
10.0.0.3:root:alpine123::alpine
10.0.0.8:root:arch456::arch
```

Auto-generates `ansible/inventory/hosts.yaml`:
```yaml
all:
  children:
    linux_servers:
      hosts:
        alpine:
          ansible_host: 10.0.0.3
          ansible_user: root
          ansible_password: alpine123
          ansible_port: 22
        arch:
          ansible_host: 10.0.0.8
          ansible_user: root
          ansible_password: arch456
          ansible_port: 22
```

### Manual Configuration Files (Safe to Edit)

These files are created **once** and can be manually edited:

| File | Purpose | Edit Frequency |
|------|---------|----------------|
| `ansible/ansible.cfg` | Ansible settings | Rarely |
| `ansible/playbooks/*.yaml` | Installation playbooks | When adding packages |
| `ansible/roles/*/tasks/*.yaml` | Distro-specific tasks | When modifying logic |
| `hosts.txt` | Host inventory | **Every competition** |
| `users.json` | User definitions | **Every competition** |
| `configs/rsyslog.conf` | Rsyslog template | Occasionally |
| `configs/audit.rules` | Auditd template | Occasionally |

### Source Configuration Files

Templates used by Fabric and synced to Ansible:

- `configs/rsyslog.conf` - Rsyslog logging rules
- `configs/journald.conf` - Systemd journal settings
- `configs/audit.rules` - Auditd monitoring rules
- `configs/logrotate-security` - Log rotation settings

**When you edit these:**
1. Changes apply to **both** Fabric and Ansible operations
2. Auto-synced to `ansible/roles/*/templates/` before Ansible runs
3. Deployed to targets by Fabric after package installation

---

## Workflow Details

### Complete Workflow for Logging Setup

```bash
# 1. Update source files (before competition)
vim hosts.txt        # Add your targets
vim users.json       # Define your team users
vim configs/rsyslog.conf  # Customize logging rules (optional)

# 2. Run hardening (during competition)
uv run fab harden    # Runs full 14-step pipeline
```

**What happens internally (Step 13 - Logging Setup):**

```
For each host in hosts.txt (parallel execution):
  ┌─────────────────────────────────────────────┐
  │ 1. Fabric Discovery (already done in step 1)│
  │    - OS: Arch Linux                         │
  │    - Family: archlinux                      │
  │    - Package manager: pacman                │
  └─────────────────────────────────────────────┘
                    ↓
  ┌─────────────────────────────────────────────┐
  │ 2. Ansible Package Installation             │
  │    a. Sync configs:                         │
  │       hosts.txt → inventory/hosts.yaml      │
  │       users.json → group_vars/all.yml       │
  │       configs/* → roles/*/templates/*       │
  │                                             │
  │    b. Run playbook:                         │
  │       ansible-playbook install_logging...   │
  │       --limit arch                          │
  │                                             │
  │    c. Ansible detects: ansible_os_family    │
  │       = "Archlinux"                         │
  │                                             │
  │    d. Installs: rsyslog, audit (if available)│
  │       Falls back gracefully if missing      │
  └─────────────────────────────────────────────┘
                    ↓
  ┌─────────────────────────────────────────────┐
  │ 3. Fabric Configuration Deployment          │
  │    - Backup /etc/rsyslog.conf (if exists)   │
  │    - Deploy /etc/rsyslog.d/ccdc-security.conf│
  │    - Create log files (auth.log, ssh.log)   │
  │    - Set permissions (chmod 640)            │
  │    - Restart rsyslog                        │
  │    - Configure journald                     │
  │    - Deploy audit rules                     │
  │    - Restart auditd                         │
  └─────────────────────────────────────────────┘
                    ↓
  ┌─────────────────────────────────────────────┐
  │ 4. Result Logging                           │
  │    - Success/failure for each action        │
  │    - Saved to: logs/test-module/arch/*.log  │
  └─────────────────────────────────────────────┘
```

### Manual Ansible Operations (Optional)

You can also run Ansible tasks directly:

```bash
# Test connectivity
uv run fab ansible-ping

# Get system facts
uv run fab ansible-facts

# Run any playbook
uv run fab ansible-run --playbook=install_logging_packages.yaml

# Run ad-hoc command
uv run fab ansible-shell --command="uptime"

# Sync configs manually
uv run fab ansible-sync
```

---

## Testing

### Test the Ansible Integration

**Option 1: Test logging_setup module only**
```bash
# Dry run (safe - no changes)
uv run fab test-module --module=logging_setup

# Live run (actual installation and configuration)
uv run fab test-module --module=logging_setup --live
```

**Option 2: Test Ansible connectivity**
```bash
# Ping all hosts
uv run fab ansible-ping

# Expected output:
# ✓ alpine | SUCCESS
# ✓ arch | SUCCESS
# ✓ debian | SUCCESS
# ...
```

**Option 3: Test full pipeline**
```bash
# Run complete hardening on all hosts
uv run fab harden
```

### Verify Installation

Check logs for Ansible execution:

```bash
# View latest test log for a specific host
cat logs/test-module/arch/$(ls -t logs/test-module/arch/ | head -1)

# Look for these lines:
# "Installing logging packages via Ansible on arch (limit: arch)..."
# "Ansible package installation completed for arch"
# "✓ SUCCESS - Install logging packages via Ansible"
```

### Expected Results

**Successful Ansible Installation:**
```
2026-01-06 00:51:06 - INFO - Installing logging packages via Ansible on arch (limit: arch)...
2026-01-06 00:51:26 - INFO - Ansible package installation completed for arch
2026-01-06 00:51:26 - INFO -   ✓ Success

Summary: 17 commands
  ✓ Successful: 9
  • Already Applied: 8
  ✗ Failed: 0
```

**Common Success Indicators:**
- "Ansible package installation completed for {host}"
- "Packages installed successfully"
- Summary shows 0 failures

---

## Troubleshooting

### Issue: "ansible-playbook: command not found"

**Cause:** Ansible not installed on control node

**Fix:**
```bash
# Install Ansible
pip install ansible

# Or on Debian/Ubuntu
sudo apt install ansible

# Verify
ansible --version
```

---

### Issue: "Could not match supplied host pattern, ignoring: 10.0.0.X"

**Cause:** Ansible inventory uses friendly names, but IP was passed

**Status:** ✅ **Already fixed** in current version

**How it's fixed:**
- `_get_ansible_hostname_for_ip()` looks up hostname from inventory
- Playbooks are called with `--limit {friendly_name}` not IP

**If you still see this:**
1. Ensure `hosts.txt` has friendly names in 5th column
2. Check `ansible/inventory/hosts.yaml` was generated
3. Run `uv run fab ansible-sync` to regenerate

---

### Issue: Ansible package installation fails but shows success

**Cause:** Package not available in distro repos (e.g., rsyslog on Arch)

**Expected Behavior:** This is **intentional**
- Playbook uses `block/rescue` pattern
- Falls back gracefully if package missing
- Logs show: "rsyslog not in repos - will use journald"
- Module marks as success and continues

**Verification:**
```bash
# SSH to target
ssh root@10.0.0.8

# Check if rsyslog installed
command -v rsyslogd
# If not found, check journald
journalctl --version
```

---

### Issue: "Command executed but verification failed" for rsyslog backup

**Cause:** `/etc/rsyslog.conf` doesn't exist on some distros (Arch, Alpine)

**Status:** ✅ **Already fixed** in current version

**How it's fixed:**
```python
# Check command now handles both cases:
check_command="test ! -f /etc/rsyslog.conf -o -f /etc/rsyslog.conf.backup.* 2>/dev/null && echo exists"
# Succeeds if: rsyslog.conf doesn't exist OR backup exists
```

---

### Issue: "which: command not found" on Arch Linux

**Cause:** Arch doesn't include `which` by default

**Status:** ✅ **Already fixed** in current version

**How it's fixed:**
```python
# Changed from:
command="which auditctl >/dev/null && ..."
# To POSIX-compliant:
command="command -v auditctl >/dev/null && ..."
```

---

### Issue: Slow Ansible execution (>30 seconds per host)

**Causes:**
1. DNS lookups for hostnames
2. Gathering facts (unnecessary for package install)
3. Network latency

**Fix:** Already optimized in playbooks:
```yaml
- name: Install logging packages
  hosts: all
  gather_facts: yes  # Required to detect ansible_os_family
  become: yes
```

**Further optimization (if needed):**
```yaml
  strategy: free  # Don't wait for all hosts (parallel)
```

---

### Issue: Ansible can't connect to host

**Symptoms:**
```
UNREACHABLE! => {"changed": false, "msg": "Failed to connect to host"}
```

**Debug steps:**
1. Verify SSH connectivity manually:
   ```bash
   ssh root@10.0.0.8
   ```

2. Check `hosts.txt` credentials:
   ```bash
   cat hosts.txt | grep 10.0.0.8
   # Verify password is correct
   ```

3. Check generated inventory:
   ```bash
   cat ansible/inventory/hosts.yaml
   # Verify ansible_host, ansible_user, ansible_password
   ```

4. Test Ansible directly:
   ```bash
   cd ansible
   ansible all -m ping
   ```

---

### Issue: Module-specific Ansible integration not working

**If you're adding Ansible to a new module:**

1. **Copy the pattern from logging_setup.py:**
   ```python
   from pathlib import Path
   ANSIBLE_DIR = Path(__file__).parent.parent.parent / "ansible"

   def _get_ansible_hostname_for_ip(self, ip: str) -> str:
       # ... (copy implementation from logging_setup.py)

   def _install_packages_via_ansible(self, conn, server_info) -> HardeningResult:
       # 1. Sync configs
       subprocess.run(['python3', 'generate_configs.py'], cwd=str(ANSIBLE_DIR))

       # 2. Get hostname
       friendly_name = self._get_ansible_hostname_for_ip(server_info.host)

       # 3. Run playbook
       result = subprocess.run([
           'ansible-playbook',
           'playbooks/your_playbook.yaml',
           '--limit', friendly_name
       ], cwd=str(ANSIBLE_DIR), timeout=300)

       # 4. Return result
   ```

2. **Create your playbook:**
   ```bash
   cp ansible/playbooks/install_logging_packages.yaml \
      ansible/playbooks/your_module.yaml
   # Edit to install your packages
   ```

3. **Test:**
   ```bash
   uv run fab test-module --module=your_module --live
   ```

---

### Debug Mode

Enable verbose Ansible output:

```python
# In utilities/modules/logging_setup.py:
result = subprocess.run([
    'ansible-playbook',
    'playbooks/install_logging_packages.yaml',
    '--limit', friendly_name,
    '-vvv'  # Very verbose (add more 'v' for more detail)
], ...)
```

Or run Ansible manually:
```bash
cd ansible
ansible-playbook playbooks/install_logging_packages.yaml --limit arch -vvv
```

---

## Summary

### Key Takeaways

1. **Hybrid is Best**: Ansible for package installation, Fabric for everything else
2. **Auto-Generated Configs**: Inventory is always synced from `hosts.txt`
3. **Transparent Integration**: Modules call Ansible as a subprocess - no pipeline changes needed
4. **Graceful Degradation**: Missing packages don't fail the entire hardening
5. **Zero Target Dependencies**: Targets only need SSH - no Python/Ansible required

### Quick Reference Commands

```bash
# Pre-competition setup
vim hosts.txt
vim users.json

# Run hardening
uv run fab harden

# Test specific module
uv run fab test-module --module=logging_setup --live

# Ansible utilities
uv run fab ansible-ping
uv run fab ansible-sync
uv run fab ansible-facts

# View logs
ls -lt logs/test-module/arch/
cat logs/harden/{friendly_name}/latest.log
```

### When to Use Ansible vs Fabric

| Task | Tool | Reason |
|------|------|--------|
| Package installation | Ansible | Cross-distro abstraction |
| File deployment | Fabric | Direct control, simpler |
| Service restart | Fabric | Distro-agnostic commands |
| User management | Fabric | Complex conditional logic |
| Configuration editing | Fabric | Precise control |
| Multi-package install | Ansible | Handles dependencies |

---

**For more information:**
- Main workflow guide: `docs/workflow_guide.md`
- Logging module details: `docs/README_logging_setup.md`
- Ansible official docs: https://docs.ansible.com/
