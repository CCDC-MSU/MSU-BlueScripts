#!/usr/bin/env python3
"""
Generate Ansible configuration from fabric_deploy sources.

This script synchronizes:
1. Inventory (hosts.yaml) from hosts.txt
2. Config templates from configs/ directory
3. User definitions from users.json

Run this before any Ansible playbook to ensure configs are in sync.
"""

import sys
import os
import yaml
import json
import shutil
from pathlib import Path
from datetime import datetime

# Paths
SCRIPT_DIR = Path(__file__).parent
BASE_DIR = SCRIPT_DIR.parent
HOSTS_FILE = BASE_DIR / 'hosts.txt'
USERS_FILE = BASE_DIR / 'users.json'
CONFIGS_DIR = BASE_DIR / 'configs'
KEYS_DIR = BASE_DIR / 'keys'

# Output paths
INVENTORY_DIR = SCRIPT_DIR / 'inventory'
GROUP_VARS_DIR = SCRIPT_DIR / 'group_vars'
PYTHON_STATE_FILE = SCRIPT_DIR / 'python_bootstrap_state.json'

# Mapping of friendly names to OS families
OS_FAMILY_MAP = {
    'rocky': 'redhat',
    'centos': 'redhat',
    'fedora': 'redhat',
    'rhel': 'redhat',
    'alma': 'redhat',
    'debian': 'debian',
    'ubuntu': 'debian',
    'alpine': 'alpine',
    'arch': 'arch',
    'opensuse': 'suse',
    'suse': 'suse',
    'slackware': 'slackware',
    'gentoo': 'gentoo',
    'freebsd': 'bsd',
    'openbsd': 'bsd',
}


def parse_hosts_file() -> list:
    """Parse hosts.txt and return list of host dicts"""
    if not HOSTS_FILE.exists():
        print(f"Error: hosts file not found: {HOSTS_FILE}", file=sys.stderr)
        return []

    hosts = []
    with open(HOSTS_FILE, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(':')
            if len(parts) < 3:
                print(f"Warning: Skipping invalid line {line_num}: {line}", file=sys.stderr)
                continue

            host = parts[0]
            user = parts[1]
            auth = parts[2]

            is_key = (auth.endswith('.private') or auth.endswith('.pub') or
                     auth.startswith('/') or auth.startswith('~') or
                     auth.startswith('keys/') or auth.endswith('.pem'))

            port = 22
            name = None

            if len(parts) >= 4:
                fourth = parts[3]
                if fourth.isdigit():
                    port = int(fourth)
                    if len(parts) >= 5:
                        name = parts[4]
                else:
                    name = fourth

            if not name:
                name = host.replace('.', '_')

            os_family = 'unknown'
            for key, family in OS_FAMILY_MAP.items():
                if key in name.lower():
                    os_family = family
                    break

            host_info = {
                'name': name,
                'host': host,
                'user': user,
                'port': port,
                'os_family': os_family,
            }

            if is_key:
                host_info['key_file'] = auth
            else:
                host_info['password'] = auth

            hosts.append(host_info)

    return hosts


def load_python_bootstrap_state() -> dict:
    """Load Python bootstrap installation state"""
    if PYTHON_STATE_FILE.exists():
        try:
            with open(PYTHON_STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load Python bootstrap state: {e}")
    return {}


def generate_inventory(hosts: list) -> dict:
    """Generate Ansible inventory structure"""
    # Load Python bootstrap state to determine which hosts have Python 3.12
    python_state = load_python_bootstrap_state()

    inventory = {
        'all': {
            'children': {
                'linux': {
                    'children': {
                        'redhat': {'hosts': {}},
                        'debian': {'hosts': {}},
                        'alpine': {'hosts': {}},
                        'arch': {'hosts': {}},
                        'suse': {'hosts': {}},
                        'slackware': {'hosts': {}},
                        'gentoo': {'hosts': {}},
                    }
                },
                'bsd': {'hosts': {}},
            },
            # No global ansible_python_interpreter - set per-host based on bootstrap state
        }
    }

    for h in hosts:
        host_vars = {
            'ansible_host': h['host'],
            'ansible_user': h['user'],
            'ansible_port': h['port'],
        }

        if 'key_file' in h:
            key_path = h['key_file']
            if not key_path.startswith('/'):
                key_path = str((BASE_DIR / key_path).resolve())
            host_vars['ansible_private_key_file'] = key_path
        else:
            host_vars['ansible_password'] = h['password']
            host_vars['ansible_ssh_pass'] = h['password']

        # Set ansible_python_interpreter only if Python 3.12 was successfully installed
        host_ip = h['host']
        if host_ip in python_state and python_state[host_ip].get('success'):
            python_path = python_state[host_ip].get('python_path', '/root/python/bin/python3.12')
            host_vars['ansible_python_interpreter'] = python_path
        # Otherwise, omit it and let Ansible auto-discover Python

        family = h['os_family']
        name = h['name']

        if family == 'bsd':
            inventory['all']['children']['bsd']['hosts'][name] = host_vars
        elif family in inventory['all']['children']['linux']['children']:
            inventory['all']['children']['linux']['children'][family]['hosts'][name] = host_vars
        else:
            if 'unknown' not in inventory['all']['children']['linux']['children']:
                inventory['all']['children']['linux']['children']['unknown'] = {'hosts': {}}
            inventory['all']['children']['linux']['children']['unknown']['hosts'][name] = host_vars

    # Clean up empty groups
    for group_name in list(inventory['all']['children']['linux']['children'].keys()):
        if not inventory['all']['children']['linux']['children'][group_name]['hosts']:
            del inventory['all']['children']['linux']['children'][group_name]

    if not inventory['all']['children']['bsd']['hosts']:
        del inventory['all']['children']['bsd']

    return inventory


def sync_config_templates():
    """Sync config files from configs/ to Ansible templates"""
    if not CONFIGS_DIR.exists():
        print(f"Warning: configs directory not found: {CONFIGS_DIR}")
        return

    # Mapping of config files to their Ansible template destinations
    config_mappings = {
        'rsyslog.conf': 'roles/logging_setup/templates/rsyslog-ccdc.conf.j2',
        'journald.conf': 'roles/logging_setup/templates/journald-ccdc.conf.j2',
        'audit.rules': 'roles/logging_setup/templates/audit-ccdc.rules.j2',
        'logrotate.conf': 'roles/logging_setup/templates/logrotate-ccdc.conf.j2',
        'bsd_syslog.conf': 'roles/logging_setup/templates/bsd-syslog.conf.j2',
        'bsd_newsyslog.conf': 'roles/logging_setup/templates/bsd-newsyslog.conf.j2',
    }

    synced = []
    for src_name, dest_path in config_mappings.items():
        src_file = CONFIGS_DIR / src_name
        dest_file = SCRIPT_DIR / dest_path

        if src_file.exists():
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            # Read source
            with open(src_file, 'r') as f:
                content = f.read()

            # Add Ansible header
            header = f"# Auto-generated from {src_name}\n# Last synced: {datetime.now().isoformat()}\n# Managed by Ansible - do not edit manually\n\n"

            # Write with header
            with open(dest_file, 'w') as f:
                f.write(header + content)

            synced.append(src_name)

    return synced


def load_users_config() -> dict:
    """Load users.json and generate group_vars"""
    if not USERS_FILE.exists():
        print(f"Warning: users.json not found: {USERS_FILE}")
        return {}

    with open(USERS_FILE, 'r') as f:
        users = json.load(f)

    return users


def generate_group_vars(users_config: dict):
    """Generate group_vars/all.yaml from users.json"""
    GROUP_VARS_DIR.mkdir(parents=True, exist_ok=True)

    # Create all.yaml with user configuration
    all_vars = {
        'ccdc_regular_users': users_config.get('regular_users', []),
        'ccdc_super_users': users_config.get('super_users', []),
        'ccdc_do_not_change_users': users_config.get('do_not_change_users', []),
    }

    # Add root key path if exists
    root_key = KEYS_DIR / 'root-key.pub'
    if root_key.exists():
        all_vars['ccdc_root_public_key'] = str(root_key.resolve())

    with open(GROUP_VARS_DIR / 'all.yaml', 'w') as f:
        f.write(f"# Auto-generated from users.json\n")
        f.write(f"# Last synced: {datetime.now().isoformat()}\n")
        f.write("---\n")
        yaml.dump(all_vars, f, default_flow_style=False)


def main():
    print("=" * 60)
    print("CCDC Ansible Config Generator")
    print("=" * 60)

    # 1. Generate inventory
    print("\n[1/4] Generating inventory from hosts.txt...")
    hosts = parse_hosts_file()
    if hosts:
        inventory = generate_inventory(hosts)
        INVENTORY_DIR.mkdir(parents=True, exist_ok=True)
        with open(INVENTORY_DIR / 'hosts.yaml', 'w') as f:
            yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)
        print(f"  - Generated inventory with {len(hosts)} hosts")

        # Print groups
        linux_groups = inventory['all']['children'].get('linux', {}).get('children', {})
        for group, data in linux_groups.items():
            count = len(data.get('hosts', {}))
            if count:
                print(f"    - {group}: {count} hosts")

        # Print Python bootstrap status
        python_state = load_python_bootstrap_state()
        if python_state:
            print(f"\n  Python Bootstrap Status:")
            successful = [ip for ip, data in python_state.items() if data.get('success')]
            failed = [ip for ip, data in python_state.items() if not data.get('success')]
            print(f"    - Python 3.12 installed: {len(successful)} hosts")
            if successful:
                for ip in successful[:3]:  # Show first 3
                    print(f"      ✓ {ip}")
                if len(successful) > 3:
                    print(f"      ... and {len(successful) - 3} more")
            if failed:
                print(f"    - Auto-discovery fallback: {len(failed)} hosts")
                for ip in failed:
                    print(f"      ○ {ip} (will use system Python)")
        else:
            print(f"\n  Python Bootstrap Status: Not run yet")
            print(f"    - Run 'uv run fab test-module --module=python_bootstrap --live' first")
            print(f"    - Or it will run during 'uv run fab harden'")
    else:
        print("  - No hosts found!")

    # 2. Sync config templates
    print("\n[2/4] Syncing config templates from configs/...")
    synced = sync_config_templates()
    if synced:
        for name in synced:
            print(f"  - Synced: {name}")
    else:
        print("  - No config files to sync")

    # 3. Load users config
    print("\n[3/4] Loading users.json...")
    users = load_users_config()
    if users:
        print(f"  - regular_users: {len(users.get('regular_users', []))}")
        print(f"  - super_users: {len(users.get('super_users', []))}")
        print(f"  - do_not_change_users: {len(users.get('do_not_change_users', []))}")

    # 4. Generate group vars
    print("\n[4/4] Generating group_vars...")
    generate_group_vars(users)
    print(f"  - Generated: group_vars/all.yaml")

    print("\n" + "=" * 60)
    print("Config generation complete!")
    print("=" * 60)

    # Print summary of what's auto-generated vs manual
    print("\nFile Status:")
    print("-" * 40)
    print("AUTO-GENERATED (regenerated on each run):")
    print("  - inventory/hosts.yaml      <- hosts.txt")
    print("  - group_vars/all.yaml       <- users.json")
    print("  - roles/*/templates/*.j2    <- configs/*")
    print("\nMANUAL (edit directly):")
    print("  - playbooks/*.yaml")
    print("  - roles/*/tasks/*.yaml")
    print("  - roles/*/handlers/*.yaml")
    print("  - roles/*/vars/*.yaml (distro-specific)")
    print("  - ansible.cfg")


if __name__ == '__main__':
    main()
