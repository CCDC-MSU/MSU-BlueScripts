#!/usr/bin/env python3
"""
CCDC Hardening Script Deployment Framework - Fabfile Entry Point
Refactored to assume tasks are located in the tasks/ directory.
"""

import logging
import os
import sys


try:
    from utilities.utils import setup_logging

    setup_logging()
except ImportError:
    pass
except Exception as e:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger(__name__).warning(f"Failed to setup logging: {e}")

# Import tasks from the tasks package
# This makes them available to fabric
from tasks.ansible import (
    ansible_bootstrap,
    ansible_facts,
    ansible_logging,
    ansible_ping,
    ansible_run,
    ansible_shell,
    ansible_sync,
    list_playbooks,
)
from tasks.discovery_tasks import discover, discover_all
from tasks.hardening import (
    apply_competition_firewall,
    deploy_scripts,
    harden,
    list_modules,
    test_all_modules,
    test_module,
)
from tasks.maintenance import reset_ssh
from tasks.testing import setup_test_env
from tasks.tools import run_script, upload_hardening_scripts

# Define __all__ to explicitely export tasks if needed (not strictly required by Fabric but good practice)
__all__ = [
    "discover",
    "discover_all",
    "harden",
    "deploy_scripts",
    "test_module",
    "list_modules",
    "test_all_modules",
    "apply_competition_firewall",
    "upload_hardening_scripts",
    "run_script",
    "reset_ssh",
    "setup_test_env",
    # Ansible integration
    "ansible_sync",
    "ansible_ping",
    "ansible_facts",
    "ansible_bootstrap",
    "ansible_logging",
    "ansible_run",
    "ansible_shell",
    "list_playbooks",
]
