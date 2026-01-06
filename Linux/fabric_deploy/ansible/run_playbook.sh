#!/bin/bash
# Run Ansible playbooks from the ansible directory
# Usage: ./run_playbook.sh <playbook_name> [ansible-playbook options]
#
# Examples:
#   ./run_playbook.sh bootstrap
#   ./run_playbook.sh logging_setup
#   ./run_playbook.sh logging_setup --limit=debian
#   ./run_playbook.sh logging_setup --check  # dry run

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Regenerate inventory from hosts.txt
echo "Regenerating inventory from hosts.txt..."
python3 generate_inventory.py

if [ -z "$1" ]; then
    echo "Usage: $0 <playbook_name> [ansible-playbook options]"
    echo ""
    echo "Available playbooks:"
    ls -1 playbooks/*.yaml | xargs -n1 basename | sed 's/.yaml$//'
    exit 1
fi

PLAYBOOK="$1"
shift

# Add .yaml if not present
if [[ ! "$PLAYBOOK" == *.yaml ]]; then
    PLAYBOOK="${PLAYBOOK}.yaml"
fi

if [ ! -f "playbooks/$PLAYBOOK" ]; then
    echo "Error: Playbook 'playbooks/$PLAYBOOK' not found"
    echo ""
    echo "Available playbooks:"
    ls -1 playbooks/*.yaml | xargs -n1 basename | sed 's/.yaml$//'
    exit 1
fi

echo "Running playbook: $PLAYBOOK"
echo "================================"

ansible-playbook "playbooks/$PLAYBOOK" "$@"
