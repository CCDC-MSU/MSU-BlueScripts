#!/usr/bin/env python3
"""
Generate Ansible inventory from hosts.txt

This script reads the fabric_deploy hosts.txt format and generates
an Ansible inventory YAML file with proper host groupings.
"""

import sys
import os
import yaml
from pathlib import Path

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


def parse_hosts_file(hosts_file: str) -> list:
    """Parse hosts.txt and return list of host dicts"""
    hosts = []

    with open(hosts_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            parts = line.split(':')
            if len(parts) < 3:
                print(f"Warning: Skipping invalid line {line_num}: {line}", file=sys.stderr)
                continue

            host = parts[0]
            user = parts[1]
            auth = parts[2]  # Could be password or key path

            # Determine if auth is a key file or password
            is_key = auth.endswith('.private') or auth.endswith('.pub') or \
                     auth.startswith('/') or auth.startswith('~') or \
                     auth.startswith('keys/') or auth.endswith('.pem')

            port = 22
            name = None

            # Parse optional port and name
            if len(parts) >= 4:
                # Could be port or name
                fourth = parts[3]
                if fourth.isdigit():
                    port = int(fourth)
                    if len(parts) >= 5:
                        name = parts[4]
                else:
                    name = fourth

            # Generate name if not provided
            if not name:
                name = host.replace('.', '_')

            # Determine OS family from name
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


def generate_inventory(hosts: list, base_path: str) -> dict:
    """Generate Ansible inventory structure"""
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
            'vars': {
                'ansible_python_interpreter': 'auto_silent',
            }
        }
    }

    for h in hosts:
        host_vars = {
            'ansible_host': h['host'],
            'ansible_user': h['user'],
            'ansible_port': h['port'],
        }

        if 'key_file' in h:
            # Make key path absolute relative to ansible directory
            key_path = h['key_file']
            if not key_path.startswith('/'):
                key_path = os.path.join(base_path, '..', key_path)
            host_vars['ansible_private_key_file'] = os.path.abspath(key_path)
        else:
            host_vars['ansible_password'] = h['password']
            host_vars['ansible_ssh_pass'] = h['password']

        # Add to appropriate group
        family = h['os_family']
        name = h['name']

        if family == 'bsd':
            inventory['all']['children']['bsd']['hosts'][name] = host_vars
        elif family in inventory['all']['children']['linux']['children']:
            inventory['all']['children']['linux']['children'][family]['hosts'][name] = host_vars
        else:
            # Unknown, add to a generic group
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


def main():
    # Determine paths
    script_dir = Path(__file__).parent
    base_path = script_dir.parent
    hosts_file = base_path / 'hosts.txt'
    output_file = script_dir / 'inventory' / 'hosts.yaml'

    # Allow override via command line
    if len(sys.argv) > 1:
        hosts_file = Path(sys.argv[1])

    if not hosts_file.exists():
        print(f"Error: hosts file not found: {hosts_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading hosts from: {hosts_file}")
    hosts = parse_hosts_file(str(hosts_file))
    print(f"Found {len(hosts)} hosts")

    inventory = generate_inventory(hosts, str(script_dir))

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w') as f:
        yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)

    print(f"Inventory written to: {output_file}")

    # Print summary
    print("\nHost groups:")
    linux_groups = inventory['all']['children'].get('linux', {}).get('children', {})
    for group, data in linux_groups.items():
        host_count = len(data.get('hosts', {}))
        if host_count:
            print(f"  {group}: {host_count} hosts")

    bsd_hosts = inventory['all']['children'].get('bsd', {}).get('hosts', {})
    if bsd_hosts:
        print(f"  bsd: {len(bsd_hosts)} hosts")


if __name__ == '__main__':
    main()
