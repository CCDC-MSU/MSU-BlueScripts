#!/usr/bin/env python3
"""
CCDC Hardening Script Deployment Framework - Fabfile Entry Point
Refactored to assume tasks are located in the tasks/ directory.
"""

import sys
import os
import logging

# Ensure the current directory is in the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import logging setup
try:
    from utilities.utils import setup_logging
    setup_logging()
except ImportError:
    pass
except Exception as e:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger(__name__).warning(f"Failed to setup logging: {e}")

# Import tasks from the tasks package
# This makes them available to fabric
from tasks.discovery import discover, discover_all
from tasks.hardening import harden, deploy_scripts, test_module, list_modules, test_all_modules
from tasks.tools import upload_tools, run_script
from tasks.maintenance import reset_ssh
from tasks.testing import setup_test_env

# Define __all__ to explicitely export tasks if needed (not strictly required by Fabric but good practice)
__all__ = [
    'discover',
    'discover_all',
    'harden',
    'deploy_scripts', 
    'test_module',
    'list_modules',
    'test_all_modules',
    'upload_tools',
    'run_script',
    'reset_ssh',
    'setup_test_env'
]
