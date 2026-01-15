from fabric import task, Connection, Config
import logging
import os
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko

from utilities.utils import load_config, parse_hosts_file, is_connection_reset
from utilities.discovery import SystemDiscovery
from utilities.deployment import HardeningOrchestrator

from .common import (
    _configure_parallel_logging,
    _get_console_logger,
    _host_label,
    _host_log_handler
)
from .tools import _upload_tools_internal

logger = logging.getLogger(__name__)

# Load configuration with error handling
try:
    CONFIG = load_config()
except Exception as e:
    logger.warning(f"Could not load config: {e}")
    CONFIG = {}


@task
def harden(c, hosts_file='hosts.txt', dry_run=False, modules=None, 
           scripts=None, script_categories=None, priority_only=False):
    """
    Apply hardening configurations to discovered hosts
    
    Args:
        hosts_file: Path to hosts file
        dry_run: If True, only show what would be done
        modules: Comma-separated list of modules to run (e.g. 'user_hardening,ssh')
        scripts: Comma-separated list of scripts (e.g. 'check-go-binaries.sh') or 'ALL'
                 If not provided, runs default_scripts from config
        script_categories (list/str): Optional list of categories for bash scripts
        priority_only (bool): If True, only run scripts with PRIORITY=10 or less
    """
    _configure_parallel_logging()
    console_logger = _get_console_logger()

    console_logger.info("=" * 60)
    console_logger.info("CCDC HARDENING STARTING (PARALLEL)")
    console_logger.info("=" * 60)

    if dry_run:
        console_logger.info("DRY RUN MODE - No changes will be made")

    start_time = datetime.now()

    # Check if hosts file exists
    if not os.path.exists(hosts_file):
        console_logger.error(f"Hosts file not found: {hosts_file}")
        return

    # Parse hosts file
    try:
        servers = parse_hosts_file(hosts_file)
    except Exception as e:
        console_logger.error(f"Error parsing hosts file: {e}")
        return

    if not servers:
        console_logger.error("No servers found in hosts file")
        return

    # Parse modules if provided
    module_list = None
    if modules:
        # Check if modules is already a list (passed from another task) or string
        if isinstance(modules, list):
             module_list = modules
        else:
             module_list = [m.strip() for m in modules.split(',')]
        console_logger.info(f"Applying modules: {module_list}")

    # Resolve scripts to run
    script_paths = []
    
    # Load config for defaults
    try:
        config = load_config()
    except Exception:
        config = {}

    if scripts:
        if isinstance(scripts, str) and scripts.upper() == 'ALL':
            scripts_dir = Path(__file__).parent.parent / "scripts/all"
            script_paths = [f"all/{s.name}" for s in scripts_dir.glob("*.sh")]
            console_logger.info(f"Scripts mode: ALL ({len(script_paths)} scripts)")
        elif isinstance(scripts, str):
            requested = [s.strip() for s in scripts.split(',')]
            resolved = []
            for r in requested:
                if '/' in r:
                    resolved.append(r)
                else:
                    resolved.append(f"all/{r}")
            script_paths = resolved
            console_logger.info(f"Scripts mode: Custom ({len(script_paths)} scripts)")
        else:
             # Assume list passed
             script_paths = scripts
    else:
        # Use defaults
        script_paths = config.get('default_scripts', [])
        console_logger.info(f"Scripts mode: Default ({len(script_paths)} scripts)")

    console_logger.info(f"Found {len(servers)} servers to harden")
    console_logger.info("Logs: logs/harden/<host>/<timestamp>.log")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _harden_host(server_creds):
        host_id = _host_label(server_creds)
        with _host_log_handler("harden", host_id, timestamp) as log_path:
            
            # Helper to run hardening logic given a valid connection
            def perform_hardening(conn, is_fallback=False):
                # First discover the system
                # If fallback, we might want to update creds or just assume root access implies sudo capability
                discovery = SystemDiscovery(conn, server_creds)
                server_info = discovery.discover_system()
                server_info._discovery = discovery

                if not server_info.discovery_successful:
                    logger.error(f"Discovery failed for {server_creds.host}, skipping hardening")
                    return {
                        'host': server_creds.host,
                        'status': 'discovery-failed',
                        'log_file': str(log_path)
                    }

                # Then deploy hardening
                orchestrator = HardeningOrchestrator(conn, server_info, script_paths=script_paths)
                result = orchestrator.deploy(dry_run=dry_run, modules=module_list)
                
                # Tools upload
                _upload_tools_internal(conn)

                logger.info(f"Hardening completed for {server_creds.host}")
                report_file = result.get('report_file', 'N/A')
                logger.info(f"Report generated: {report_file}")
                logger.info(f"Summary:\n{result['summary']}")

                results = result.get('results', {})
                failed_actions = any(
                    not action.success for module_results in results.values() for action in module_results
                )
                
                status_extra = " (fallback)" if is_fallback else ""
                status = f"dry-run{status_extra}" if dry_run else f"ok{status_extra}"
                
                if failed_actions:
                    status = f"failed{status_extra}"
                    logger.error(f"Hardening had failures for {server_creds.host}")

                return {
                    'host': server_creds.host,
                    'status': status,
                    'log_file': str(log_path),
                    'report_file': report_file
                }

            # Setup connection parameters
            logger.info(f"Starting hardening on {server_creds.host}")
            connect_kwargs = {
                'allow_agent': False,
                'look_for_keys': False,
                'timeout': 90
            }
            config_overrides = {
                'sudo': {'password': None},
                'load_ssh_configs': False,
                'load_system_host_keys': False
            }

            if server_creds.key_file:
                connect_kwargs['key_filename'] = server_creds.key_file
                logger.info(f"Using SSH key: {server_creds.key_file}")
            elif server_creds.password:
                connect_kwargs['password'] = server_creds.password
                config_overrides['sudo']['password'] = server_creds.password
                logger.info("Using password authentication")

            if server_creds.port != 22:
                connect_kwargs['port'] = server_creds.port

            fabric_config = Config(overrides=config_overrides)
            
            # Password retry with exponential backoff: 0s, 2s, 4s delays
            PASSWORD_RETRY_DELAYS = [0, 2, 4]
            
            # Helper to attempt a single connection
            def _try_connection(host, user, config, kwargs, label=""):
                with Connection(host, user=user, config=config, connect_kwargs=kwargs) as conn:
                    conn.run("true", hide=True, timeout=10)
                    if conn.transport:
                        conn.transport.set_keepalive(10)
                    return conn, perform_hardening(conn, is_fallback=bool(label))
            
            last_error = None
            
            # Phase 1: Try password auth with retries (if password provided and no key)
            if server_creds.password and not server_creds.key_file:
                for attempt, delay in enumerate(PASSWORD_RETRY_DELAYS, 1):
                    if delay > 0:
                        logger.info(f"Waiting {delay}s before password retry...")
                        import time
                        time.sleep(delay)

                    try:
                        logger.info(f"Password attempt {attempt}/{len(PASSWORD_RETRY_DELAYS)} for {server_creds.host}...")
                        with Connection(server_creds.host, user=server_creds.user,
                                       config=fabric_config, connect_kwargs=connect_kwargs) as conn:
                            # Ignore host key changes - critical for fault tolerance
                            conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            conn.run("true", hide=True, timeout=10)
                            if conn.transport:
                                conn.transport.set_keepalive(10)
                            logger.info(f"Password auth succeeded on attempt {attempt}")
                            return perform_hardening(conn)
                    except Exception as e:
                        last_error = e
                        logger.warning(f"Password attempt {attempt} failed: {e}")
                
                logger.warning(f"All {len(PASSWORD_RETRY_DELAYS)} password attempts failed, trying SSH key fallback...")
            
            # Phase 2: Try key from hosts.txt (if specified)
            elif server_creds.key_file:
                try:
                    logger.info(f"Attempting connection with specified key: {server_creds.key_file}")
                    with Connection(server_creds.host, user=server_creds.user,
                                   config=fabric_config, connect_kwargs=connect_kwargs) as conn:
                        # Ignore host key changes - critical for fault tolerance
                        conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        conn.run("true", hide=True, timeout=10)
                        if conn.transport:
                            conn.transport.set_keepalive(10)
                        return perform_hardening(conn)
                except Exception as e:
                    last_error = e
                    logger.warning(f"Key auth with {server_creds.key_file} failed: {e}")
            
            # Phase 3: Fallback to recovery key
            try:
                logger.info(f"Attempting fallback to RECOVERY KEY for {server_creds.host}...")
                
                # Resolve key path relative to this file
                # tasks/hardening.py -> ../keys/test-root-key.private
                fallback_key = os.path.abspath(os.path.join(os.path.dirname(__file__), "../keys/test-root-key.private"))
                
                if not os.path.exists(fallback_key):
                    logger.error(f"Recovery key not found at {fallback_key}")
                    if last_error:
                        raise last_error
                    raise FileNotFoundError(f"No valid auth method and recovery key missing: {fallback_key}")

                fallback_kwargs = {
                    'allow_agent': False,
                    'look_for_keys': False,
                    'timeout': 90,
                    'key_filename': [fallback_key]
                }
                if server_creds.port != 22:
                    fallback_kwargs['port'] = server_creds.port
                
                # For root fallback, we don't need sudo password
                fallback_config = Config(overrides={'load_ssh_configs': False, 'load_system_host_keys': False})

                with Connection(server_creds.host, user='root',
                               config=fallback_config, connect_kwargs=fallback_kwargs) as conn:
                    # Ignore host key changes - critical for fault tolerance
                    conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    conn.run("true", hide=True, timeout=10)
                    if conn.transport:
                        conn.transport.set_keepalive(10)
                    logger.info(f"RECOVERY KEY SUCCESS: Connected as root!")
                    return perform_hardening(conn, is_fallback=True)

            except Exception as fallback_e:
                logger.error(f"Recovery key connection failed: {fallback_e}")
                
                # Determine primary error to report
                primary_error = last_error if last_error else fallback_e
                if is_connection_reset(primary_error):
                    logger.error(f"Hardening failed for {server_creds.host}: Connection reset by peer")
                else:
                    logger.error(f"Hardening failed for {server_creds.host}: {primary_error}")
                
                return {
                    'host': server_creds.host,
                    'status': f'error: {primary_error} (recovery key also failed: {fallback_e})',
                    'log_file': str(log_path)
                }

    results = []
    max_workers = min(16, len(servers)) if servers else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for server_creds in servers:
            console_logger.info(f"Starting hardening on {server_creds.host}")
            futures.append(executor.submit(_harden_host, server_creds))

        for future in as_completed(futures):
            results.append(future.result())

    successful_hardenings = sum(1 for r in results if r['status'] == 'ok')
    failed_hardenings = sum(1 for r in results if r['status'] not in ['ok', 'dry-run'])
    dry_runs = sum(1 for r in results if r['status'] == 'dry-run')

    # End summary
    end_time = datetime.now()
    duration = end_time - start_time

    console_logger.info("=" * 60)
    console_logger.info("CCDC HARDENING COMPLETED")
    console_logger.info("=" * 60)
    console_logger.info(f"Total time: {duration}")
    if len(servers) > 0:
        console_logger.info(
            f"Hardening success rate: {successful_hardenings}/{len(servers)} ({(successful_hardenings/len(servers)*100):.1f}%)"
        )
    if dry_runs > 0:
        console_logger.info(f"Dry runs: {dry_runs}")
    if failed_hardenings > 0:
        failed_hosts = [r['host'] for r in results if r['status'] not in ['ok', 'dry-run']]
        console_logger.error(f"Hardening failed for: {', '.join(failed_hosts)}")

    return successful_hardenings, failed_hardenings


@task
def deploy_scripts(c, hosts_file='hosts.txt', dry_run=False, categories=None, priority_only=False):
    """Deploy only bash scripts to discovered hosts"""
    console_logger = _get_console_logger()
    console_logger.info("=" * 60)
    console_logger.info("CCDC BASH SCRIPT DEPLOYMENT STARTING")
    console_logger.info("=" * 60)
    
    script_categories = categories
    
    console_logger.info("Deploying shell scripts only")
    if categories:
        console_logger.info(f"Script categories: {categories}")

    return harden(c, hosts_file=hosts_file, dry_run=dry_run,
                  modules='shell_scripts', script_categories=script_categories,
                  priority_only=priority_only)


@task
def test_module(c, module, live=False):
    """Test individual hardening module across all hosts"""
    try:
        from test_modules import ModuleTester
    except ImportError:
         logger.error("Could not import ModuleTester. Ensure test_modules.py is in path.")
         return False

    _configure_parallel_logging()
    console_logger = _get_console_logger()

    console_logger.info("=" * 60)
    console_logger.info(f"TESTING MODULE: {module} (PARALLEL)")
    console_logger.info("=" * 60)

    # Parse hosts file
    try:
        servers = parse_hosts_file('hosts.txt')
    except Exception as e:
        console_logger.error(f"Error parsing hosts file: {e}")
        return False

    if not servers:
        console_logger.error("No servers found in hosts file")
        return False

    console_logger.info(f"Found {len(servers)} servers to test")
    console_logger.info("Logs: logs/test-module/<host>/<timestamp>.log")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dry_run = not live

    def _test_host(server_creds, host_index):
        host_id = _host_label(server_creds)
        with _host_log_handler("test-module", host_id, timestamp) as log_path:
            try:
                logger.info(f"Starting module test on {server_creds.host}")
                tester = ModuleTester(CONFIG)
                success = tester.test_module(module, host_index, dry_run)
                if not success:
                    logger.error(f"Module test failed for {server_creds.host}")
                return {
                    'host': server_creds.host,
                    'success': success,
                    'log_file': str(log_path)
                }
            except Exception as e:
                err_str = str(e)
                if is_connection_reset(e):
                    logger.error(f"Module test failed for {server_creds.host}: Connection reset by peer")
                else:
                    logger.error(f"Module test failed for {server_creds.host}: {e}")
                return {
                    'host': server_creds.host,
                    'success': False,
                    'log_file': str(log_path)
                }

    results = []
    max_workers = min(16, len(servers)) if servers else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for index, server_creds in enumerate(servers):
            console_logger.info(f"Starting module test on {server_creds.host}")
            futures.append(executor.submit(_test_host, server_creds, index))

        for future in as_completed(futures):
            results.append(future.result())

    successful = sum(1 for r in results if r['success'])
    failed = len(results) - successful

    console_logger.info("=" * 60)
    console_logger.info("MODULE TEST SUMMARY")
    console_logger.info("=" * 60)
    console_logger.info(f"Success rate: {successful}/{len(results)} ({(successful/len(results)*100):.1f}%)")
    if failed > 0:
        failed_hosts = [r['host'] for r in results if not r['success']]
        console_logger.error(f"Module test failed for: {', '.join(failed_hosts)}")

    return failed == 0


@task
def list_modules(c):
    """List all available hardening modules"""
    try:
        from test_modules import ModuleTester
    except ImportError:
         print("Could not import ModuleTester")
         return
    
    try:
        tester = ModuleTester(CONFIG)
        tester.list_modules()
    except Exception as e:
        logger.error(f"Failed to list modules: {e}")


@task
def test_all_modules(c, host_index=0, live=False):
    """Test all available hardening modules"""
    try:
        from test_modules import ModuleTester
    except ImportError:
         print("Could not import ModuleTester")
         return
    
    try:
        tester = ModuleTester(CONFIG)
        dry_run = not live
        
        logger.info("=" * 60)
        logger.info("TESTING ALL MODULES")
        logger.info("=" * 60)
        
        results = {}
        for module_name in tester.available_modules.keys():
            logger.info(f"\n--- Testing {module_name} ---")
            success = tester.test_module(module_name, host_index, dry_run)
            results[module_name] = success
            
        # Summary
        logger.info("\n" + "=" * 60)
        logger.info("ALL MODULES TEST SUMMARY")
        logger.info("=" * 60)
        
        successful = sum(1 for success in results.values() if success)
        total = len(results)
        
        for module_name, success in results.items():
            status = "✓" if success else "✗"
            logger.info(f"{status} {module_name}")
            
        logger.info(f"\nSuccess rate: {successful}/{total} ({(successful/total*100):.1f}%)")
        
        return results
        
    except Exception as e:
        logger.error(f"All modules test failed: {e}")
        return False
