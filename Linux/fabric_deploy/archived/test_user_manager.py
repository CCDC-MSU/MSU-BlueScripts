#!/usr/bin/env python3
"""
Integration test for UserManager actions.
Creates a sudo user, verifies SSH + sudo access, removes sudo,
then removes the user and verifies SSH access is gone.
Runs in parallel across hosts from hosts.txt by default.
"""

import argparse
import logging
import os
import shlex
import sys
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
import secrets

from fabric import Connection, Config

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utilities.actions import UserManager
from utilities.discovery import SystemDiscovery
from utilities.utils import generate_password, load_config, parse_hosts_file, setup_logging


logger = logging.getLogger(__name__)


def _sh_quote(value: str) -> str:
    return shlex.quote(value)


def _wrap_script(shell: str, script: str) -> str:
    return f"{shell} -c {_sh_quote(script)}"


class _ThreadFilter(logging.Filter):
    def __init__(self, thread_id: int):
        super().__init__()
        self.thread_id = thread_id

    def filter(self, record: logging.LogRecord) -> bool:
        return record.thread == self.thread_id


def _get_console_logger() -> logging.Logger:
    console_logger = logging.getLogger("console")
    if not console_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        console_logger.addHandler(handler)
        console_logger.setLevel(logging.INFO)
        console_logger.propagate = False
    return console_logger


def _configure_parallel_logging(verbose: bool = False) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root.addHandler(console_handler)

    logging.getLogger('paramiko').setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger('fabric').setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger('invoke').setLevel(logging.DEBUG if verbose else logging.WARNING)


def _host_label(server_creds) -> str:
    label = server_creds.host.replace(":", "_").replace("/", "_").replace(" ", "_")
    if getattr(server_creds, 'port', 22) != 22:
        label = f"{label}_{server_creds.port}"
    return label


@contextmanager
def _host_log_handler(task_name: str, host_label: str, timestamp: str):
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


class UserManagerTester:
    def __init__(self, config: dict):
        self.config = config

    def _connect_to_host(self, server_creds) -> Connection:
        connect_kwargs = {'allow_agent': False, 'look_for_keys': False}
        config_overrides = {
            'sudo': {'password': None},
            'load_ssh_configs': False
        }

        if server_creds.key_file:
            connect_kwargs['key_filename'] = server_creds.key_file
            logger.info("Using SSH key: %s", server_creds.key_file)
        elif server_creds.password:
            connect_kwargs['password'] = server_creds.password
            config_overrides['sudo']['password'] = server_creds.password
            logger.info("Using password authentication")

        if server_creds.port != 22:
            connect_kwargs['port'] = server_creds.port

        config = Config(overrides=config_overrides)
        return Connection(
            server_creds.host,
            user=server_creds.user,
            config=config,
            connect_kwargs=connect_kwargs
        )

    def _connect_as_user(self, host: str, port: int, username: str, password: str) -> Connection:
        connect_kwargs = {
            'allow_agent': False,
            'look_for_keys': False,
            'password': password
        }
        if port != 22:
            connect_kwargs['port'] = port
        config = Config(overrides={'load_ssh_configs': False})
        return Connection(host, user=username, config=config, connect_kwargs=connect_kwargs)

    def _run_privileged(self, conn: Connection, command: str, dry_run: bool) -> bool:
        logger.debug(command)
        if dry_run:
            logger.info("[DRY RUN] %s", command)
            return True

        if conn.user == "root":
            result = conn.run(command, hide=True, warn=True, timeout=60)
        else:
            result = conn.sudo(command, hide=True, warn=True, timeout=60)

        if not result.ok:
            logger.error("Command failed: %s", result.stderr or result.stdout)
        logger.debug(result)
        return result.ok

    def _run_scripts(self, conn: Connection, shell: str, scripts, dry_run: bool) -> bool:
        if isinstance(scripts, (list, tuple)):
            script_list = list(scripts)
        else:
            script_list = [scripts]

        for script in script_list:
            if not self._run_privileged(conn, _wrap_script(shell, script), dry_run):
                return False
        return True

    def _remote_user_exists(self, conn: Connection, username: str) -> bool:
        result = conn.run(f"id -u {_sh_quote(username)}", hide=True, warn=True, timeout=10)
        return result.ok

    def _ssh_login_ok(self, host: str, port: int, username: str, password: str) -> bool:
        try:
            with self._connect_as_user(host, port, username, password) as test_conn:
                result = test_conn.run("id -u", hide=True, warn=True, timeout=10)
                return result.ok
        except Exception:
            return False

    def _sudo_access_ok(self, host: str, port: int, username: str, password: str) -> bool:
        try:
            with self._connect_as_user(host, port, username, password) as test_conn:
                sudo_cmd = (
                    f"printf '%s\\n' {_sh_quote(password)} | "
                    "sudo -S -p '' -k id -u"
                )
                result = test_conn.run(sudo_cmd, hide=True, warn=True, timeout=10)
                return result.ok and result.stdout.strip() == "0"
        except Exception:
            return False

    def _generate_username(self, conn: Connection) -> str:
        for _ in range(5):
            suffix = secrets.randbelow(900000) + 100000
            candidate = f"umtest{suffix}"
            if not self._remote_user_exists(conn, candidate):
                return candidate
        raise RuntimeError("Unable to find a free test username")

    def _generate_password(self) -> str:
        return generate_password()

    def run(self, host_index: Optional[int], username: str, password: str,
            hosts_file: str, dry_run: bool, verbose: bool) -> bool:
        try:
            servers = parse_hosts_file(hosts_file)
        except Exception as e:
            logger.error("Error parsing hosts file: %s", e)
            return False

        if not servers:
            logger.error("No servers found in hosts file")
            return False

        _configure_parallel_logging(verbose=verbose)
        console_logger = _get_console_logger()

        target_servers = servers
        if host_index is not None:
            if host_index >= len(servers):
                logger.error("Host index %d out of range (0-%d)", host_index, len(servers) - 1)
                return False
            target_servers = [servers[host_index]]

        if not target_servers:
            logger.error("No servers selected for testing")
            return False

        console_logger.info("=" * 60)
        console_logger.info("USERMANAGER TEST STARTING (PARALLEL)")
        console_logger.info("=" * 60)
        console_logger.info("Logs: logs/test-user-manager/<host>/<timestamp>.log")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        shared_username = username
        if not shared_username:
            first_host = target_servers[0]
            console_logger.info("Generating shared test username using %s", first_host.host)
            with self._connect_to_host(first_host) as conn:
                shared_username = self._generate_username(conn)
            console_logger.info("Shared test username: %s", shared_username)

        def _run_on_host(server_creds) -> bool:
            host_label = _host_label(server_creds)
            with _host_log_handler("test-user-manager", host_label, timestamp) as log_path:
                logger.info("Starting UserManager test for %s", host_label)
                logger.info("Per-host log file: %s", log_path)
                with self._connect_to_host(server_creds) as conn:
                    logger.info("Performing system discovery...")
                    discovery = SystemDiscovery(conn, server_creds)
                    server_info = discovery.discover_system()
                    if not server_info.discovery_successful:
                        logger.error("System discovery failed")
                        return False

                    user_manager = UserManager(
                        server_info.available_commands,
                        server_info.groups,
                        server_info.sudoers_info
                    )

                    local_username = shared_username
                    local_password = password

                    if self._remote_user_exists(conn, local_username):
                        logger.error("[%s] User %s already exists. Pick another username.", host_label, local_username)
                        return False

                    if not local_password:
                        local_password = self._generate_password()

                    host = server_creds.host
                    port = getattr(server_creds, "port", 22)
                    shell = server_info.default_shell or "/bin/sh"

                    logger.info("Test user: %s", local_username)
                    logger.info("Password set: %s", "yes" if local_password else "no")

                    # Ensure sudo binary exists for verification.
                    sudo_check = conn.run("command -v sudo >/dev/null 2>&1", warn=True, hide=True)
                    if not sudo_check.ok:
                        logger.error("sudo command not found on target; cannot verify sudo access.")
                        return False

                    logger.info("Step 1: add sudo user and verify SSH + sudo access")
                    add_scripts = user_manager.add_sudo_user(local_username, local_password)
                    if not self._run_scripts(conn, shell, add_scripts, dry_run):
                        return False

                    if not dry_run:
                        if not self._ssh_login_ok(host, port, local_username, local_password):
                            logger.error("SSH login failed for new user")
                            return False
                        if not self._sudo_access_ok(host, port, local_username, local_password):
                            logger.error("Sudo access verification failed for new user")
                            return False

                    logger.info("Step 2: remove sudo and verify sudo access is removed")
                    remove_sudo_script = user_manager.remove_user_from_sudoers(local_username)
                    if not self._run_privileged(conn, _wrap_script(shell, remove_sudo_script), dry_run):
                        return False

                    if not dry_run:
                        if not self._ssh_login_ok(host, port, local_username, local_password):
                            logger.error("SSH login failed after sudo removal")
                            return False
                        if self._sudo_access_ok(host, port, local_username, local_password):
                            logger.error("Sudo access still available after removal")
                            return False

                    logger.info("Step 3: kill user processes before removal")
                    kill_script = user_manager.kill_user_processes(local_username)
                    if not self._run_privileged(conn, _wrap_script(shell, kill_script), dry_run):
                        return False

                    logger.info("Step 4: remove user and verify SSH access is gone")
                    if not dry_run:
                        logger.info("Waiting 2 seconds before user removal")
                        time.sleep(2)
                    remove_user_script = user_manager.remove_user(local_username)
                    if not self._run_privileged(conn, _wrap_script(shell, remove_user_script), dry_run):
                        return False

                    if dry_run:
                        logger.info("Dry run complete for %s", host_label)
                        return True

                logger.info("Waiting 2 seconds before SSH removal verification")
                time.sleep(2)
                if self._ssh_login_ok(host, port, local_username, local_password):
                    logger.error("SSH access still works after user removal")
                    return False

                logger.info("UserManager test completed successfully")
                return True

        results = []
        max_workers = min(16, len(target_servers)) if target_servers else 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_run_on_host, server): server for server in target_servers}
            for future in as_completed(futures):
                server_creds = futures[future]
                try:
                    ok = future.result()
                except Exception as exc:
                    logger.error("[%s] Test crashed: %s", server_creds.host, exc)
                    ok = False
                results.append({'host': server_creds.host, 'success': ok})

        success_count = sum(1 for result in results if result['success'])
        failed_hosts = [result['host'] for result in results if not result['success']]
        console_logger.info("=" * 60)
        console_logger.info("USERMANAGER TEST COMPLETED")
        console_logger.info("=" * 60)
        console_logger.info("Summary: %d/%d hosts succeeded", success_count, len(results))
        if failed_hosts:
            console_logger.error("Failures: %s", ", ".join(failed_hosts))
        return success_count == len(results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Test UserManager actions against a host")
    parser.add_argument('--host-index', '-i', type=int, default=None,
                        help='Optional host index from hosts.txt (default: all hosts)')
    parser.add_argument('--hosts-file', default='hosts.txt', help='Hosts file to use')
    parser.add_argument('--username', help='Username to create (random if omitted)')
    parser.add_argument('--password', help='Password to set (random if omitted)')
    parser.add_argument('--live', action='store_true', help='Run live (default is dry-run)')
    parser.add_argument('--config', default='config.yaml', help='Configuration file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger('fabric').setLevel(logging.DEBUG)
        logging.getLogger('paramiko').setLevel(logging.INFO)
        logging.getLogger('invoke').setLevel(logging.INFO)

    try:
        config = load_config(args.config)
    except Exception as e:
        logger.error("Could not load config: %s", e)
        sys.exit(1)

    tester = UserManagerTester(config)
    dry_run = not args.live

    if dry_run:
        logger.info("Running in dry-run mode; no changes will be made.")

    ok = tester.run(
        host_index=args.host_index,
        username=args.username,
        password=args.password,
        hosts_file=args.hosts_file,
        dry_run=dry_run,
        verbose=args.verbose
    )

    if not ok:
        sys.exit(1)


if __name__ == '__main__':
    setup_logging()
    main()
