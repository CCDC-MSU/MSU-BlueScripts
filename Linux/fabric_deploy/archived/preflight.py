"""
Pre-flight checks for hardening operations
"""

from fabric import task
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from .common import _get_console_logger, _configure_parallel_logging, _host_label, _host_log_handler
from utilities.models import ServerCredentials
from utilities.discovery import SystemDiscovery
from utilities.utils import parse_hosts_file
from utilities.operator_interaction import (
    prompt_operator_for_failures,
    wait_for_manual_fix,
    save_decisions,
    clear_decisions,
    OperatorDecision
)
from utilities.modules.python_bootstrap import PythonBootstrapModule
from fabric import Connection, Config
import paramiko

logger = logging.getLogger(__name__)


@task
def check_python_bootstrap_deps(c, hosts_file='hosts.txt'):
    """
    Pre-flight check for python_bootstrap dependencies across all hosts.
    Prompts operator for action if dependencies are missing.

    Run this before 'harden' to handle dependency issues interactively.
    """
    _configure_parallel_logging()
    console_logger = _get_console_logger()

    console_logger.info("=" * 80)
    console_logger.info("PYTHON BOOTSTRAP DEPENDENCY PRE-FLIGHT CHECK")
    console_logger.info("=" * 80)

    # Clear any previous decisions
    clear_decisions()

    # Parse hosts
    try:
        servers = parse_hosts_file(hosts_file)
    except Exception as e:
        console_logger.error(f"Error parsing hosts file: {e}")
        return

    if not servers:
        console_logger.error("No servers found in hosts file")
        return

    console_logger.info(f"Checking {len(servers)} hosts for Python bootstrap dependencies...")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _check_host_deps(server_creds):
        """Check dependencies for a single host"""
        host_id = _host_label(server_creds)

        with _host_log_handler("preflight", host_id, timestamp) as log_path:
            try:
                # Setup connection
                connect_kwargs = {
                    'allow_agent': False,
                    'look_for_keys': False,
                    'timeout': 30
                }

                if server_creds.password:
                    connect_kwargs['password'] = server_creds.password
                elif server_creds.key_file:
                    connect_kwargs['key_filename'] = [server_creds.key_file]

                config_overrides = {
                    'sudo': {'password': server_creds.password if server_creds.password else None},
                    'load_ssh_configs': False
                }

                fabric_config = Config(overrides=config_overrides)

                with Connection(server_creds.host, user=server_creds.user,
                               port=server_creds.port, config=fabric_config,
                               connect_kwargs=connect_kwargs) as conn:

                    conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # Quick discovery to get OS info
                    logger.info(f"Discovering system info for {server_creds.host}")
                    discovery = SystemDiscovery(conn, server_creds)
                    server_info = discovery.discover_system()

                    if not server_info.discovery_successful:
                        logger.error(f"Discovery failed for {server_creds.host}")
                        return {
                            'host': server_creds.host,
                            'hostname': server_creds.display_name,
                            'status': 'discovery_failed',
                            'missing_deps': []
                        }

                    # Check if module is applicable
                    os_family = discovery.os_family
                    if os_family in ['freebsd', 'openbsd', 'netbsd']:
                        logger.info(f"Python bootstrap not applicable for {os_family}")
                        return {
                            'host': server_creds.host,
                            'hostname': server_info.hostname or server_creds.display_name,
                            'status': 'not_applicable',
                            'missing_deps': []
                        }

                    # Run dependency check using the module's verification function
                    logger.info(f"Checking dependencies for {server_creds.host}")
                    module = PythonBootstrapModule(conn, server_info, os_family)

                    # Call the dependency verification method directly
                    result = module._verify_uv_dependencies(conn, server_info)

                    if result.success:
                        logger.info(f"✓ All dependencies present on {server_creds.host}")
                        return {
                            'host': server_creds.host,
                            'hostname': server_info.hostname or server_creds.display_name,
                            'status': 'ok',
                            'missing_deps': []
                        }
                    else:
                        # Parse missing dependencies from error message
                        error_msg = result.error or ""
                        missing = []
                        if "Missing required utilities:" in error_msg:
                            deps_str = error_msg.split("Missing required utilities:")[1].split(".")[0].strip()
                            missing = [d.strip() for d in deps_str.split(',')]

                        logger.warning(f"✗ Missing dependencies on {server_creds.host}: {missing}")
                        return {
                            'host': server_creds.host,
                            'hostname': server_info.hostname or server_creds.display_name,
                            'status': 'missing_deps',
                            'missing_deps': missing
                        }

            except Exception as e:
                logger.error(f"Failed to check {server_creds.host}: {e}")
                return {
                    'host': server_creds.host,
                    'hostname': server_creds.display_name,
                    'status': 'check_failed',
                    'missing_deps': [],
                    'error': str(e)
                }

    # Check all hosts in parallel
    results = []
    max_workers = min(16, len(servers))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_check_host_deps, server) for server in servers]

        for future in as_completed(futures):
            results.append(future.result())

    # Categorize results
    ok_hosts = [r for r in results if r['status'] == 'ok']
    not_applicable = [r for r in results if r['status'] == 'not_applicable']
    failures = [r for r in results if r['status'] == 'missing_deps']
    check_failed = [r for r in results if r['status'] in ['check_failed', 'discovery_failed']]

    # Display summary
    console_logger.info("\n" + "=" * 80)
    console_logger.info("DEPENDENCY CHECK RESULTS")
    console_logger.info("=" * 80)
    console_logger.info(f"✓ Ready for Python 3.12: {len(ok_hosts)} hosts")
    if not_applicable:
        console_logger.info(f"○ Not applicable (BSD): {len(not_applicable)} hosts")
    if check_failed:
        console_logger.warning(f"⚠ Check failed: {len(check_failed)} hosts")
    if failures:
        console_logger.warning(f"✗ Missing dependencies: {len(failures)} hosts")

    # If no failures, we're good to go
    if not failures:
        console_logger.info("\n✓ All hosts ready for Python bootstrap!")
        return

    # Prepare failure data for operator
    failure_data = [
        {
            'ip': f['host'],
            'hostname': f['hostname'],
            'missing_deps': f['missing_deps']
        }
        for f in failures
    ]

    # Prompt operator for decisions
    decisions = prompt_operator_for_failures(failure_data)

    # Check if operator chose to abort
    if any(d == OperatorDecision.ABORT for d in decisions.values()):
        console_logger.error("\n⚠  Hardening aborted by operator")
        save_decisions(decisions)
        return

    # Separate hosts by decision
    hosts_to_retry = [f for f in failure_data if decisions.get(f['ip']) == OperatorDecision.RETRY_AFTER_MANUAL_FIX]
    hosts_to_skip = [f for f in failure_data if decisions.get(f['ip']) == OperatorDecision.SKIP_USE_AUTO_DISCOVERY]

    console_logger.info(f"\nDecisions summary:")
    console_logger.info(f"  Retry after manual fix: {len(hosts_to_retry)}")
    console_logger.info(f"  Skip (use auto-discovery): {len(hosts_to_skip)}")

    # If operator chose to fix manually, wait and re-verify
    if hosts_to_retry:
        wait_for_manual_fix(hosts_to_retry)

        # Re-verify dependencies for hosts that should be fixed
        console_logger.info("Re-verifying dependencies after manual installation...")

        retry_servers = [s for s in servers if s.host in [h['ip'] for h in hosts_to_retry]]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            retry_futures = [executor.submit(_check_host_deps, server) for server in retry_servers]
            retry_results = [future.result() for future in as_completed(retry_futures)]

        # Check retry results
        still_failing = [r for r in retry_results if r['status'] == 'missing_deps']

        if still_failing:
            console_logger.warning(f"\n⚠ {len(still_failing)} host(s) still missing dependencies:")
            for r in still_failing:
                console_logger.warning(f"  {r['hostname']} ({r['host']}): {', '.join(r['missing_deps'])}")

            console_logger.warning("\nThese hosts will fall back to Ansible auto-discovery.")
            # Update decisions to skip these hosts
            for r in still_failing:
                decisions[r['host']] = OperatorDecision.SKIP_USE_AUTO_DISCOVERY
        else:
            console_logger.info(f"\n✓ All {len(hosts_to_retry)} host(s) now have required dependencies!")
            # Update decisions to allow retry
            for r in retry_results:
                if r['status'] == 'ok':
                    # Remove from decisions (no special handling needed)
                    if r['host'] in decisions:
                        del decisions[r['host']]

    # Save final decisions
    save_decisions(decisions)

    console_logger.info("\n" + "=" * 80)
    console_logger.info("PRE-FLIGHT CHECK COMPLETE")
    console_logger.info("=" * 80)
    console_logger.info("You can now run: uv run fab harden")
    console_logger.info("Python bootstrap will use the saved operator decisions.")
