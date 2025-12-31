from fabric import task, Connection, Config
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import tarfile
from io import BytesIO

from utilities.utils import load_config, parse_hosts_file, is_connection_reset
from .common import (
    _configure_parallel_logging,
    _get_console_logger,
    _host_label,
    _host_log_handler
)

logger = logging.getLogger(__name__)

# Load configuration with error handling
try:
    CONFIG = load_config()
except Exception as e:
    logger.warning(f"Could not load config: {e}")
    CONFIG = {}


def _upload_tools_internal(conn):
    """Internal helper to sync tools dir"""
    local_tools_path = Path(__file__).parent.parent / "tools"
    
    if not local_tools_path.exists():
        logger.warning(f"No local 'tools' directory found to upload at {local_tools_path}")
        return

    remote_tools_path = "/root/tools"
    
    logger.info("Uploading tools...")
    conn.sudo(f"mkdir -p {remote_tools_path}")
    
    # Create tar in memory
    fh = BytesIO()
    with tarfile.open(fileobj=fh, mode='w:gz') as tar:
        tar.add(local_tools_path, arcname='.')
    tar_data = fh.getvalue()
    
    # Upload tar
    tmp_tar = "/tmp/ccdc_tools.tar.gz"
    conn.put(BytesIO(tar_data), tmp_tar)
    
    # Extract
    conn.sudo(f"tar -xzf {tmp_tar} -C {remote_tools_path}")
    conn.sudo(f"rm {tmp_tar}")
    logger.info(f"Tools uploaded to {remote_tools_path}")


@task
def upload_tools(c, hosts_file='hosts.txt'):
    """Upload tools directory to remote servers"""
    _configure_parallel_logging()
    console_logger = _get_console_logger()
    
    servers = parse_hosts_file(hosts_file)
    if not servers:
        return
        
    def _upload_host(server_creds):
        host_id = _host_label(server_creds)
        with _host_log_handler("tools", host_id) as log_path:
             try:
                # Set up connection (similar boiler plate)
                connect_kwargs = {'allow_agent': False, 'look_for_keys': False}
                config_overrides = {'sudo': {'password': None}}
                if server_creds.key_file:
                    connect_kwargs['key_filename'] = server_creds.key_file
                elif server_creds.password:
                    connect_kwargs['password'] = server_creds.password
                    config_overrides['sudo']['password'] = server_creds.password
                
                # Check for port
                if server_creds.port != 22:
                    connect_kwargs['port'] = server_creds.port
                
                fabric_config = Config(overrides=config_overrides)
                
                with Connection(server_creds.host, user=server_creds.user,
                               config=fabric_config, connect_kwargs=connect_kwargs) as conn:
                    _upload_tools_internal(conn)
                    return {'host': server_creds.host, 'status': 'ok'}
             except Exception as e:
                 if is_connection_reset(e):
                     logger.error(f"Tools upload failed for {server_creds.host}: Connection reset by peer")
                 else:
                     logger.error(f"Tools upload failed: {e}")
                 return {'host': server_creds.host, 'status': 'failed'}

    with ThreadPoolExecutor(max_workers=len(servers)) as executor:
        list(executor.map(_upload_host, servers))


def _write_runbash_output(output_file, server_creds, script_path, steps, exec_result, error_message=None):
    """Write per-host script output to a local file."""
    try:
        with open(output_file, 'w') as f:
            host_header = f"{server_creds.display_name} ({server_creds.host})" if server_creds.friendly_name else server_creds.host
            f.write(f"Host: {host_header}\n")
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
        host_label = _host_label(server_creds)
        output_file = script_output_dir / f"{host_label}_{timestamp}.log"
        logger.info(f"Running {script_path.name} on {server_creds.display_name}")

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
                    logger.error(f"{server_creds.display_name}: failed to create staging dir")
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
                    logger.error(f"{server_creds.display_name}: failed to upload script")
                    _write_runbash_output(output_file, server_creds, script_path, steps, None)
                    return {
                        'host': server_creds.host,
                        'exit_code': upload_result.exited,
                        'status': 'failed-upload',
                        'output_file': str(output_file)
                    }

                # Execute script with nohup to persist even if SSH connection dies
                # Running in foreground (no &) so we wait for completion and get exit code
                # If SSH dies, nohup ensures the script continues running
                exec_cmd = f"{shell} {remote_script}"
                if timeout and int(timeout) > 0:
                    exec_cmd = f"timeout {int(timeout)} {exec_cmd}"
                
                # Wrap with nohup - output goes to both remote log and our capture
                remote_log_dir = "/root/hardening-logs"
                # Create remote log directory if it doesn't exist
                _run_remote(conn, f"mkdir -p {remote_log_dir}")
                
                remote_log = f"{remote_log_dir}/{script_path.name}-{timestamp}.log"
                # Use tee to write to both log file and stdout so we can capture it
                nohup_cmd = f"nohup {exec_cmd} 2>&1 | tee {remote_log}"
                
                logger.info(f"{server_creds.display_name}: executing script with nohup (remote log: {remote_log})")
                
                # Execute with nohup - this will wait for completion unless SSH dies
                exec_result = _run_remote(conn, nohup_cmd, use_sudo=sudo)
                steps.append(("execute script (nohup)", exec_result))
                
                # If we get here, either the script completed or SSH died
                if exec_result.ok:
                    logger.info(f"{server_creds.display_name}: script completed successfully (exit code: {exec_result.exited})")
                else:
                    logger.warning(f"{server_creds.display_name}: script exited with code {exec_result.exited}, check remote log: {remote_log}")

                # Cleanup the script file (keep the log for reference)
                cleanup_result = _run_remote(conn, f"rm -f {remote_script}")
                steps.append(("cleanup script", cleanup_result))

                _write_runbash_output(output_file, server_creds, script_path, steps, exec_result)

                # Determine status based on exit code
                if not exec_result.ok:
                    logger.error(f"{server_creds.display_name}: script failed with exit code {exec_result.exited}")
                    status = "failed"
                else:
                    status = "ok"

                return {
                    'host': server_creds.host,
                    'exit_code': exec_result.exited,
                    'status': status,
                    'output_file': str(output_file),
                    'remote_log': remote_log
                }

        except Exception as e:
            if is_connection_reset(e):
                logger.error(f"{server_creds.display_name}: Connection reset by peer (Firewall/Hostile Action)")
            else:
                logger.error(f"{server_creds.display_name}: {e}")
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
        display = next((s.display_name for s in servers if s.host == item['host']), item['host'])
        
        # Display exit code and status
        if item['exit_code'] is None:
            status_str = item['status']
        else:
            status_str = f"exit {item['exit_code']} ({item['status']})"
        
        # Add remote log location for reference
        if item.get('remote_log'):
            status_str += f" - log: {item['remote_log']}"
        
        logger.info(f"{display}: {status_str}")

    end_time = datetime.now()
    duration = end_time - start_time
    successful_runs = sum(1 for r in summary if r['status'] == 'ok')
    failed_runs = sum(1 for r in summary if r['status'] not in ['ok', 'dry-run'])
    dry_runs = sum(1 for r in summary if r['status'] == 'dry-run')
    logger.info(f"Completed in {duration} | ok={successful_runs} failed={failed_runs} dry-run={dry_runs}")

    return summary
