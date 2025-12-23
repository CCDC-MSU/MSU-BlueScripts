#!/usr/bin/env python3
"""
CCDC Hardening Script Deployment Framework - Fixed for Windows
Fabric-based automation for rapid deployment of security hardening scripts
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import getpass
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from fabric import Connection, Config
from invoke import task

# Import modular components with error handling
try:
    from utilities.models import ServerCredentials, ServerInfo
    from utilities.discovery import SystemDiscovery
    from utilities.deployment import HardeningDeployer
    from utilities.utils import load_config, parse_hosts_file, save_discovery_summary, setup_logging
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the fabric_deploy directory")
    sys.exit(1)

# Setup logging
try:
    setup_logging()
except:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

# Load configuration with error handling
try:
    CONFIG = load_config()
except Exception as e:
    logger.warning(f"Could not load config: {e}")
    CONFIG = {}


class _ThreadFilter(logging.Filter):
    def __init__(self, thread_id):
        super().__init__()
        self.thread_id = thread_id

    def filter(self, record):
        return record.thread == self.thread_id


def _get_console_logger():
    console_logger = logging.getLogger("console")
    if not console_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        console_logger.addHandler(handler)
        console_logger.setLevel(logging.INFO)
        console_logger.propagate = False
    return console_logger


def _configure_parallel_logging():
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root.addHandler(console_handler)

    logging.getLogger('paramiko').setLevel(logging.WARNING)
    logging.getLogger('fabric').setLevel(logging.WARNING)
    logging.getLogger('invoke').setLevel(logging.WARNING)


def _host_label(server_creds):
    label = server_creds.host.replace(":", "_").replace("/", "_").replace(" ", "_")
    if getattr(server_creds, 'port', 22) != 22:
        label = f"{label}_{server_creds.port}"
    return label


@contextmanager
def _host_log_handler(task_name, host_label, timestamp):
    log_dir = Path("logs") / task_name / host_label
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{timestamp}.log"

    handler = logging.FileHandler(log_path)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    handler.addFilter(_ThreadFilter(threading.get_ident()))

    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield log_path
    finally:
        root.removeHandler(handler)
        handler.close()


@task
def discover(c, host, user=None, key_file=None, password=None):
    """Discover system information on target host"""
    # Use config defaults if not provided
    if user is None:
        user = CONFIG.get('connection', {}).get('user', 'root')
    if password is None and key_file is None:
        password = CONFIG.get('connection', {}).get('password')
    
    # Handle authentication
    connect_kwargs = {'allow_agent':False,'look_for_keys':False }
    config_overrides = {
        'sudo': {'password': None},
        'load_ssh_configs': False  # Disable SSH config loading to avoid parse errors
    }
    
    if key_file:
        connect_kwargs['key_filename'] = key_file
        logger.info(f"Using SSH key authentication: {key_file}")
    elif password:
        connect_kwargs['password'] = password
        config_overrides['sudo']['password'] = password
        logger.info("Using password authentication")
    else:
        # Prompt for password if neither key nor password provided
        password = getpass.getpass(f"Enter password for {user}@{host}: ")
        connect_kwargs['password'] = password
        config_overrides['sudo']['password'] = password
        logger.info("Using prompted password authentication")
    
    config = Config(overrides=config_overrides)
    
    try:
        with Connection(host, user=user, config=config, connect_kwargs=connect_kwargs) as conn:
            credentials = ServerCredentials(host=host, user=user, password=password, key_file=key_file)
            discovery = SystemDiscovery(conn, credentials)
            server_info = discovery.discover_system()
            
            # Save discovery results
            output_file = f"discovery_{host.replace('.', '_')}.json"
            save_discovery_summary(server_info, output_file)
            
            return server_info
    except Exception as e:
        logger.error(f"Connection failed to {host}: {e}")
        return None


@task
def discover_all(c, hosts_file='hosts.txt'):
    """Automated discovery pipeline - discovers all hosts"""
    _configure_parallel_logging()
    console_logger = _get_console_logger()

    console_logger.info("=" * 60)
    console_logger.info("CCDC DISCOVERY PIPELINE STARTING (PARALLEL)")
    console_logger.info("=" * 60)

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
        console_logger.error("No servers found in hosts file or file not found")
        return

    console_logger.info(f"Found {len(servers)} servers to process")
    console_logger.info("Logs: logs/discover-all/<host>/<timestamp>.log")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _discover_host(server_creds):
        host_id = _host_label(server_creds)
        with _host_log_handler("discover-all", host_id, timestamp) as log_path:
            try:
                logger.info(f"Starting discovery on {server_creds.host}")
                # Set up connection
                connect_kwargs = {
                    'allow_agent': False,
                    'look_for_keys': False
                }
                config_overrides = {
                    'sudo': {'password': None},
                    'load_ssh_configs': False  # Disable SSH config loading
                }

                if server_creds.key_file:
                    connect_kwargs['key_filename'] = server_creds.key_file
                    logger.info(f"Using SSH key: {server_creds.key_file}")
                elif server_creds.password:
                    connect_kwargs['password'] = server_creds.password
                    config_overrides['sudo']['password'] = server_creds.password
                    logger.info("Using password authentication")

                # Add port if specified
                if server_creds.port != 22:
                    connect_kwargs['port'] = server_creds.port

                config = Config(overrides=config_overrides)

                # Run discovery
                with Connection(server_creds.host, user=server_creds.user,
                              config=config, connect_kwargs=connect_kwargs) as conn:
                    discovery = SystemDiscovery(conn, server_creds)
                    server_info = discovery.discover_system()

                    # Store discovery instance for OS family access
                    server_info._discovery = discovery

                    if server_info.discovery_successful:
                        logger.info(f"Discovery successful for {server_creds.host}")
                        logger.info(f"OS: {server_info.os.distro} {server_info.os.version}")
                        logger.info(f"Users: {server_info.regular_usernames}")
                        logger.info(f"Services: {len(server_info.services)} running")
                        logger.info(f"Security tools: {[k for k, v in server_info.security_tools.items() if v]}")
                    else:
                        logger.error(f"Discovery failed for {server_creds.host}")
                        for error in server_info.discovery_errors:
                            logger.error(f"Error: {error}")

                return {
                    'host': server_creds.host,
                    'success': server_info.discovery_successful,
                    'server_info': server_info,
                    'log_file': str(log_path)
                }

            except Exception as e:
                logger.error(f"Discovery failed for {server_creds.host}: {e}")
                server_info = ServerInfo(hostname=server_creds.host, credentials=server_creds)
                server_info.discovery_successful = False
                server_info.discovery_errors.append(str(e))
                return {
                    'host': server_creds.host,
                    'success': False,
                    'server_info': server_info,
                    'log_file': str(log_path)
                }

    discovered_servers = []
    results = []
    max_workers = min(16, len(servers)) if servers else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for server_creds in servers:
            console_logger.info(f"Starting discovery on {server_creds.host}")
            futures.append(executor.submit(_discover_host, server_creds))

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            discovered_servers.append(result['server_info'])

    successful_discoveries = sum(1 for r in results if r['success'])
    failed_discoveries = len(results) - successful_discoveries

    end_time = datetime.now()
    duration = end_time - start_time

    console_logger.info("=" * 60)
    console_logger.info("CCDC DISCOVERY PIPELINE COMPLETED")
    console_logger.info("=" * 60)
    console_logger.info(f"Total time: {duration}")
    if len(servers) > 0:
        console_logger.info(
            f"Discovery success rate: {successful_discoveries}/{len(servers)} ({(successful_discoveries/len(servers)*100):.1f}%)"
        )
    if failed_discoveries > 0:
        failed_hosts = [r['host'] for r in results if not r['success']]
        console_logger.error(f"Discovery failed for: {', '.join(failed_hosts)}")

    if len(servers) > 0 and successful_discoveries > 0:
        console_logger.info("Discovery complete. Use 'fab harden' to apply hardening configurations.")

    return discovered_servers


@task
def harden(c, hosts_file='hosts.txt', dry_run=False, modules=None, 
           script_categories=None, priority_only=False):
    """Apply hardening configurations to discovered hosts"""
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
    if modules:
        modules = [m.strip() for m in modules.split(',')]
        console_logger.info(f"Applying modules: {modules}")

    # Parse script categories if provided
    if script_categories:
        script_categories = [c.strip() for c in script_categories.split(',')]
        console_logger.info(f"Script categories: {script_categories}")

    if priority_only:
        console_logger.info("Priority scripts only: enabled")

    console_logger.info(f"Found {len(servers)} servers to harden")
    console_logger.info("Logs: logs/harden/<host>/<timestamp>.log")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _harden_host(server_creds):
        host_id = _host_label(server_creds)
        with _host_log_handler("harden", host_id, timestamp) as log_path:
            try:
                logger.info(f"Starting hardening on {server_creds.host}")
                # Set up connection
                connect_kwargs = {
                    'allow_agent': False,
                    'look_for_keys': False
                }
                config_overrides = {
                    'sudo': {'password': None},
                    'load_ssh_configs': False
                }

                if server_creds.key_file:
                    connect_kwargs['key_filename'] = server_creds.key_file
                    logger.info(f"Using SSH key: {server_creds.key_file}")
                elif server_creds.password:
                    connect_kwargs['password'] = server_creds.password
                    config_overrides['sudo']['password'] = server_creds.password
                    logger.info("Using password authentication")

                # Add port if specified
                if server_creds.port != 22:
                    connect_kwargs['port'] = server_creds.port

                config = Config(overrides=config_overrides)

                # Run discovery and hardening
                with Connection(server_creds.host, user=server_creds.user,
                              config=config, connect_kwargs=connect_kwargs) as conn:

                    # First discover the system
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
                    deployer = HardeningDeployer(conn, server_info)
                    result = deployer.deploy_hardening(
                        dry_run=dry_run,
                        modules=modules,
                        script_categories=script_categories,
                        priority_only=priority_only
                    )

                    logger.info(f"Hardening completed for {server_creds.host}")
                    logger.info(f"Summary:\n{result['summary']}")

                    results = result.get('results', {})
                    failed_actions = any(
                        not action.success for module_results in results.values() for action in module_results
                    )
                    status = "dry-run" if dry_run else "ok"
                    if failed_actions:
                        status = "failed"
                        logger.error(f"Hardening had failures for {server_creds.host}")

                    return {
                        'host': server_creds.host,
                        'status': status,
                        'log_file': str(log_path)
                    }

            except Exception as e:
                logger.error(f"Hardening failed for {server_creds.host}: {e}")
                return {
                    'host': server_creds.host,
                    'status': f'error: {e}',
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
    logger.info("=" * 60)
    logger.info("CCDC BASH SCRIPT DEPLOYMENT STARTING")
    logger.info("=" * 60)
    
    # Convert parameters and call main deployment with bash_scripts module only
    script_categories = categories
    modules = ['bash_scripts']
    
    logger.info("Deploying bash scripts only")
    if categories:
        logger.info(f"Script categories: {categories}")
    
    return harden(c, hosts_file=hosts_file, dry_run=dry_run,
                  modules='bash_scripts', script_categories=script_categories,
                  priority_only=priority_only)


@task
def run_script(c, file, hosts_file='hosts.txt', sudo=True, timeout=300, output_dir='script_outputs', shell='bash', dry_run=False):
    """Upload and run a local script on all targets"""
    script_path = Path(file).expanduser()
    if not script_path.is_file():
        logger.error(f"Script file not found: {script_path}")
        return

    try:
        script_content = script_path.read_text()
    except Exception as e:
        logger.error(f"Failed to read script file {script_path}: {e}")
        return

    # Check if hosts file exists
    if not os.path.exists(hosts_file):
        logger.error(f"Hosts file not found: {hosts_file}")
        return

    # Parse hosts file
    try:
        servers = parse_hosts_file(hosts_file)
    except Exception as e:
        logger.error(f"Error parsing hosts file: {e}")
        return

    if not servers:
        logger.error("No servers found in hosts file")
        return

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    script_dir_name = script_path.name.replace(" ", "_")
    script_output_dir = output_dir_path / script_dir_name
    script_output_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Running {script_path.name} on {len(servers)} hosts (parallel)")
    if dry_run:
        logger.info("DRY RUN MODE - No changes will be made")
    logger.info(f"Per-host logs: {script_output_dir}")

    start_time = datetime.now()
    remote_dir = "/tmp/ccdc_scripts"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    def _run_on_host(server_creds):
        host_label = server_creds.host.replace(":", "_").replace("/", "_")
        output_file = script_output_dir / f"{host_label}_{timestamp}.log"
        logger.info(f"Running {script_path.name} on {server_creds.host}")

        try:
            # Set up connection
            connect_kwargs = {
                'allow_agent': False,
                'look_for_keys': False
            }
            config_overrides = {
                'sudo': {'password': None},
                'load_ssh_configs': False
            }

            if server_creds.key_file:
                connect_kwargs['key_filename'] = server_creds.key_file
                logger.debug(f"Using SSH key: {server_creds.key_file}")
            elif server_creds.password:
                connect_kwargs['password'] = server_creds.password
                config_overrides['sudo']['password'] = server_creds.password
                logger.debug("Using password authentication")

            if server_creds.port != 22:
                connect_kwargs['port'] = server_creds.port

            config = Config(overrides=config_overrides)

            def _run_remote(conn, command, use_sudo=False):
                if use_sudo and conn.user != 'root':
                    command = f"sudo {command}"
                return conn.run(command, hide=True, warn=True)

            with Connection(server_creds.host, user=server_creds.user,
                            config=config, connect_kwargs=connect_kwargs) as conn:
                if dry_run:
                    _write_runbash_output(
                        output_file,
                        server_creds,
                        script_path,
                        [],
                        None,
                        error_message="DRY RUN - not executed"
                    )
                    return {
                        'host': server_creds.host,
                        'exit_code': None,
                        'status': 'dry-run',
                        'output_file': str(output_file)
                    }

                steps = []

                # Create staging directory
                create_result = _run_remote(conn, f"mkdir -p {remote_dir} && chmod 755 {remote_dir}")
                steps.append(("create staging dir", create_result))
                if not create_result.ok:
                    logger.error(f"{server_creds.host}: failed to create staging dir")
                    _write_runbash_output(output_file, server_creds, script_path, steps, None)
                    return {
                        'host': server_creds.host,
                        'exit_code': create_result.exited,
                        'status': 'failed-create-dir',
                        'output_file': str(output_file)
                    }

                # Upload script via heredoc
                remote_script = f"{remote_dir}/{script_path.name}"
                marker = f"CCDC_SCRIPT_EOF_{int(time.time())}"
                upload_cmd = f"cat > {remote_script} << '{marker}'\n{script_content}\n{marker}"
                upload_result = _run_remote(conn, upload_cmd)
                steps.append(("upload script", upload_result))
                if not upload_result.ok:
                    logger.error(f"{server_creds.host}: failed to upload script")
                    _write_runbash_output(output_file, server_creds, script_path, steps, None)
                    return {
                        'host': server_creds.host,
                        'exit_code': upload_result.exited,
                        'status': 'failed-upload',
                        'output_file': str(output_file)
                    }

                # Execute script
                exec_cmd = f"{shell} {remote_script}"
                if timeout and int(timeout) > 0:
                    exec_cmd = f"timeout {int(timeout)} {exec_cmd}"
                exec_result = _run_remote(conn, exec_cmd, use_sudo=sudo)
                steps.append(("execute script", exec_result))

                # Cleanup
                cleanup_result = _run_remote(conn, f"rm -f {remote_script}")
                steps.append(("cleanup script", cleanup_result))

                _write_runbash_output(output_file, server_creds, script_path, steps, exec_result)

                if not exec_result.ok:
                    logger.error(f"{server_creds.host}: script failed with exit {exec_result.exited}")

                status = "ok" if exec_result.ok else "failed"
                return {
                    'host': server_creds.host,
                    'exit_code': exec_result.exited,
                    'status': status,
                    'output_file': str(output_file)
                }

        except Exception as e:
            logger.error(f"{server_creds.host}: {e}")
            _write_runbash_output(
                output_file,
                server_creds,
                script_path,
                [],
                None,
                error_message=str(e)
            )
            return {
                'host': server_creds.host,
                'exit_code': None,
                'status': f'error: {e}',
                'output_file': str(output_file)
            }

    summary = []
    max_workers = min(32, len(servers)) if servers else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_run_on_host, server): server for server in servers}
        for future in as_completed(future_map):
            summary.append(future.result())

    logger.info("Summary:")
    for item in sorted(summary, key=lambda x: x['host']):
        if item['exit_code'] is None:
            logger.info(f"{item['host']}: {item['status']}")
        else:
            logger.info(f"{item['host']}: {item['exit_code']}")

    end_time = datetime.now()
    duration = end_time - start_time
    successful_runs = sum(1 for r in summary if r['status'] == 'ok')
    failed_runs = sum(1 for r in summary if r['status'] not in ['ok', 'dry-run'])
    dry_runs = sum(1 for r in summary if r['status'] == 'dry-run')
    logger.info(f"Completed in {duration} | ok={successful_runs} failed={failed_runs} dry-run={dry_runs}")

    return summary


def _write_runbash_output(output_file, server_creds, script_path, steps, exec_result, error_message=None):
    """Write per-host script output to a local file."""
    try:
        with open(output_file, 'w') as f:
            f.write(f"Host: {server_creds.host}\n")
            f.write(f"User: {server_creds.user}\n")
            f.write(f"Script: {script_path}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write("\n")
            if error_message:
                f.write(f"Error: {error_message}\n\n")

            for name, result in steps:
                f.write(f"[{name}]\n")
                if result is None:
                    f.write("No result\n\n")
                    continue
                f.write(f"Exit code: {result.exited}\n")
                if result.stdout:
                    f.write("STDOUT:\n")
                    f.write(result.stdout)
                    f.write("\n")
                if result.stderr:
                    f.write("STDERR:\n")
                    f.write(result.stderr)
                    f.write("\n")
                f.write("\n")

            if exec_result is not None:
                f.write("Final exit code: ")
                f.write(str(exec_result.exited))
                f.write("\n")
    except Exception as e:
        logger.error(f"Failed to write output file {output_file}: {e}")


@task 
def test_connection(c, host, user=None, password=None):
    """Test basic SSH connection to a host"""
    if user is None:
        user = CONFIG.get('connection', {}).get('user', 'root')
    if password is None:
        password = CONFIG.get('connection', {}).get('password')
    
    if not password:
        password = getpass.getpass(f"Enter password for {user}@{host}: ")
    
    try:
        config = Config(overrides={'load_ssh_configs': False})
        with Connection(host, user=user, password=password, config=config) as conn:
            result = conn.run('echo "Connection successful!"', hide=True)
            logger.info(f"✓ Successfully connected to {host} as {user}")
            logger.info(f"Response: {result.stdout.strip()}")
            return True
    except Exception as e:
        logger.error(f"✗ Connection failed to {host}: {e}")
        return False


@task
def test_module(c, module, live=False):
    """Test individual hardening module across all hosts"""
    from test_modules import ModuleTester

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
    from test_modules import ModuleTester
    
    try:
        tester = ModuleTester(CONFIG)
        tester.list_modules()
    except Exception as e:
        logger.error(f"Failed to list modules: {e}")


@task
def test_all_modules(c, host_index=0, live=False):
    """Test all available hardening modules"""
    from test_modules import ModuleTester
    
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
