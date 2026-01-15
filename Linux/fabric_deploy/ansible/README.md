# Ansible Integration Directory

This directory contains the Ansible integration components for the CCDC Hardening Framework.

## Overview

Ansible is used **exclusively for cross-distribution package installation** to abstract away differences in package managers and package names across Linux distributions.

**Fabric handles everything else**: discovery, configuration, service management, user management.

See `../docs/ANSIBLE_INTEGRATION.md` for complete documentation.

---

## Directory Structure

```
ansible/
├── ansible.cfg                    # Ansible configuration
├── generate_configs.py            # Auto-generates inventory and templates
├── inventory/                     # Inventory files (AUTO-GENERATED)
│   └── hosts.yaml                 # Generated from ../hosts.txt
├── group_vars/                    # Group variables (AUTO-GENERATED)
│   └── all.yml                    # Generated from ../users.json
├── playbooks/                     # Ansible playbooks
│   ├── bootstrap.yaml             # Python installation (if needed)
│   ├── logging_setup.yaml         # Full logging setup (reference)
│   └── install_logging_packages.yaml  # Package installation only (USED)
├── roles/                         # Ansible roles
│   └── logging_setup/             # Logging setup role
│       ├── tasks/
│       │   ├── main.yaml          # Entry point
│       │   ├── debian.yaml        # Debian-specific tasks
│       │   ├── redhat.yaml        # RHEL-specific tasks
│       │   ├── arch.yaml          # Arch-specific tasks
│       │   ├── alpine.yaml        # Alpine-specific tasks
│       │   └── ...                # Other distros
│       └── templates/             # Config templates (AUTO-SYNCED)
│           ├── rsyslog-ccdc.conf.j2    # From ../configs/rsyslog.conf
│           ├── journald-ccdc.conf.j2   # From ../configs/journald.conf
│           └── audit-ccdc.rules.j2     # From ../configs/audit.rules
└── run_playbook.sh                # Helper script for manual testing
```

---

## Auto-Generated Files (DO NOT EDIT)

These files are regenerated automatically before every Ansible operation:

### `inventory/hosts.yaml`

**Source**: `../hosts.txt`

**Regenerated**: Before every Ansible playbook execution

**Format Conversion**:
```
# hosts.txt format:
10.0.0.3:root:password123:22:alpine

# Generates hosts.yaml:
all:
  children:
    linux_servers:
      hosts:
        alpine:
          ansible_host: 10.0.0.3
          ansible_user: root
          ansible_password: password123
          ansible_port: 22
```

### `group_vars/all.yml`

**Source**: `../users.json`

**Regenerated**: Before every Ansible operation

**Contains**:
- User lists (regular_users, super_users, do_not_change_users)
- Configuration templates (synced from ../configs/)

### `roles/*/templates/*.j2`

**Source**: `../configs/*.conf` and `../configs/*.rules`

**Regenerated**: Before every Ansible operation

**Mapping**:
- `../configs/rsyslog.conf` → `roles/logging_setup/templates/rsyslog-ccdc.conf.j2`
- `../configs/journald.conf` → `roles/logging_setup/templates/journald-ccdc.conf.j2`
- `../configs/audit.rules` → `roles/logging_setup/templates/audit-ccdc.rules.j2`

---

## Manual Configuration Files

These files can be edited as needed:

### `ansible.cfg`

Ansible configuration settings:
```ini
[defaults]
inventory = inventory/hosts.yaml
roles_path = roles
host_key_checking = False
timeout = 30
```

### `playbooks/*.yaml`

Playbook definitions. Currently used:
- **`install_logging_packages.yaml`**: Installs rsyslog, auditd, logrotate across all distros

Example distro-specific block:
```yaml
# RHEL/CentOS/Fedora
- block:
    - dnf:
        name: [rsyslog, audit, logrotate]  # Note: 'audit' not 'auditd'
        state: present
  when: ansible_os_family == 'RedHat'
```

### `roles/logging_setup/tasks/*.yaml`

Distro-specific task files. Each handles package installation for a specific OS family:
- `debian.yaml` - Debian/Ubuntu
- `redhat.yaml` - RHEL/CentOS/Fedora/Rocky
- `arch.yaml` - Arch Linux
- `alpine.yaml` - Alpine Linux
- `suse.yaml` - openSUSE/SLES
- etc.

---

## How It Works

### Automatic Sync Process

Every time Fabric calls an Ansible playbook, it first regenerates configs:

```python
# In utilities/modules/logging_setup.py:
def _install_packages_via_ansible(self, conn, server_info):
    # 1. Regenerate all configs from source files
    subprocess.run(['python3', 'generate_configs.py'], cwd='ansible/')

    # 2. Run Ansible playbook
    subprocess.run([
        'ansible-playbook',
        'playbooks/install_logging_packages.yaml',
        '--limit', hostname
    ], cwd='ansible/')
```

### Config Generation Script

`generate_configs.py` performs three operations:

1. **Generate inventory** from `../hosts.txt`
2. **Generate group vars** from `../users.json`
3. **Sync templates** from `../configs/` to `roles/*/templates/`

Run manually if needed:
```bash
cd ansible
python3 generate_configs.py
```

---

## Usage Examples

### Run Playbook Directly

```bash
cd ansible

# Test connectivity
ansible all -m ping

# Run package installation playbook
ansible-playbook playbooks/install_logging_packages.yaml

# Run on specific host
ansible-playbook playbooks/install_logging_packages.yaml --limit alpine

# Verbose mode
ansible-playbook playbooks/install_logging_packages.yaml -vvv
```

### Via Fabric Tasks

```bash
cd ..  # Back to fabric_deploy/

# Ping all hosts
uv run fab ansible-ping

# Sync configs manually
uv run fab ansible-sync

# Run specific playbook
uv run fab ansible-run --playbook=install_logging_packages.yaml

# Run ad-hoc command
uv run fab ansible-shell --command="uptime"
```

### Test Logging Setup

```bash
cd ..  # Back to fabric_deploy/

# Dry run (no changes)
uv run fab test-module --module=logging_setup

# Live run (actual installation)
uv run fab test-module --module=logging_setup --live
```

---

## Adding a New Playbook

To add Ansible integration to another module:

### 1. Create Playbook

```bash
cd playbooks
cp install_logging_packages.yaml install_security_tools.yaml
vim install_security_tools.yaml
```

### 2. Define Packages per Distro

```yaml
- name: Install security tools across distros
  hosts: all
  become: yes
  gather_facts: yes
  tasks:
    # Debian/Ubuntu
    - block:
        - apt:
            name: [fail2ban, aide, tripwire]
            state: present
      when: ansible_os_family == 'Debian'

    # RHEL/CentOS/Fedora
    - block:
        - dnf:
            name: [fail2ban, aide, tripwire]
            state: present
      when: ansible_os_family == 'RedHat'

    # ... other distros
```

### 3. Create Module Integration

In `utilities/modules/your_module.py`:
```python
from pathlib import Path
ANSIBLE_DIR = Path(__file__).parent.parent.parent / "ansible"

def _install_packages_via_ansible(self, conn, server_info):
    # Copy implementation from logging_setup.py
    # Change playbook name to 'install_security_tools.yaml'
```

### 4. Test

```bash
uv run fab test-module --module=your_module --live
```

---

## Supported Distributions

The playbooks handle these OS families automatically:

| OS Family | Package Manager | Example Distros |
|-----------|----------------|-----------------|
| Debian | apt | Debian, Ubuntu |
| RedHat | dnf/yum | RHEL, CentOS, Fedora, Rocky |
| Archlinux | pacman | Arch Linux, Manjaro |
| Alpine | apk | Alpine Linux |
| Suse | zypper | openSUSE, SLES |
| Gentoo | emerge | Gentoo |
| Slackware | slackpkg | Slackware |

### Package Name Differences

Ansible abstracts these differences:

| Package | Debian | RHEL | Arch | Alpine |
|---------|--------|------|------|--------|
| Auditd | auditd | audit | audit | audit |
| Rsyslog | rsyslog | rsyslog | rsyslog (AUR) | rsyslog |
| Logrotate | logrotate | logrotate | logrotate | logrotate |

---

## Troubleshooting

### Inventory not generated

```bash
# Manually regenerate
cd ansible
python3 generate_configs.py

# Verify
cat inventory/hosts.yaml
```

### Playbook fails with "host pattern not found"

**Cause**: Hostname mismatch between inventory and --limit parameter

**Fix**: Ensure `hosts.txt` has friendly names:
```
10.0.0.3:root:pass:22:alpine    # ← 5th field is hostname
```

### Package not available in repos

**Expected behavior**: Playbooks use block/rescue to handle gracefully

Example from `playbooks/install_logging_packages.yaml`:
```yaml
- block:
    - pacman:
        name: rsyslog
        state: present
  rescue:
    - debug:
        msg: "rsyslog not in Arch repos - will use journald"
  when: ansible_os_family == 'Archlinux'
```

### Ansible too slow

Playbooks are already optimized:
- `gather_facts: yes` only when needed (for ansible_os_family)
- Parallel execution across hosts
- Minimal task set

For further optimization, edit `ansible.cfg`:
```ini
[defaults]
forks = 20           # Increase parallelism
timeout = 60         # Longer timeout for slow networks
```

---

## Key Design Decisions

### Why Ansible for Packages Only?

1. **Cross-distro abstraction**: Ansible modules handle package name differences
2. **Block/rescue pattern**: Graceful fallback when packages unavailable
3. **Community modules**: Uses well-tested community.general collection
4. **No target dependencies**: Ansible handles Python bootstrap automatically

### Why Fabric for Configuration?

1. **Direct SSH control**: Precise command execution and output parsing
2. **Complex logic**: Conditional configurations based on discovery
3. **Error handling**: Custom HardeningResult objects with rollback support
4. **Integration**: Seamless integration with existing pipeline

### Why Auto-Generate Inventory?

1. **Single source of truth**: `hosts.txt` is the only file to maintain
2. **Always in sync**: No manual inventory updates needed
3. **Format flexibility**: Can add/remove hosts without touching YAML
4. **Competition workflow**: Update one file, everything else follows

---

## Files Modified During Execution

**None.** All Ansible operations are read-only regarding the ansible/ directory itself:
- Playbooks are executed but not modified
- Inventory is regenerated (not edited)
- Templates are synced (overwritten from source)

**Files modified on target hosts**:
- `/etc/rsyslog.d/ccdc-security.conf`
- `/etc/audit/rules.d/ccdc.rules`
- `/etc/systemd/journald.conf.d/ccdc.conf`
- Log files in `/var/log/`

---

## Version Requirements

- **Ansible Core**: 2.14+ (tested with 2.16.3)
- **Python**: 3.8+ (for running generate_configs.py)
- **Community Collections**: Installed automatically

Install collections if needed:
```bash
ansible-galaxy collection install community.general
```

---

## Related Documentation

- **Complete Ansible Integration Guide**: `../docs/ANSIBLE_INTEGRATION.md`
- **Requirements and Setup**: `../docs/REQUIREMENTS.md`
- **Logging Module Details**: `../docs/README_logging_setup.md`
- **Main Workflow Guide**: `../docs/workflow_guide.md`

---

**Quick Reference Commands**:
```bash
# Regenerate configs
python3 generate_configs.py

# Test connectivity
ansible all -m ping

# Run playbook
ansible-playbook playbooks/install_logging_packages.yaml

# Check inventory
cat inventory/hosts.yaml

# View Ansible config
cat ansible.cfg
```
