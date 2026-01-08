"""
Ansible Integration Tasks

Provides Fabric tasks to run Ansible playbooks and manage the Ansible-based
deployment workflow.
"""

import logging
import os
import subprocess

from invoke import task

logger = logging.getLogger(__name__)

# Get the base directory (where fabfile.py lives)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANSIBLE_DIR = os.path.join(BASE_DIR, "ansible")


def _run_ansible_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Run an ansible command from the ansible directory"""
    env = os.environ.copy()
    env["ANSIBLE_CONFIG"] = os.path.join(ANSIBLE_DIR, "ansible.cfg")

    result = subprocess.run(cmd, cwd=ANSIBLE_DIR, env=env, capture_output=False)

    if check and result.returncode != 0:
        raise RuntimeError(f"Ansible command failed with exit code {result.returncode}")

    return result


def _sync_configs():
    """Regenerate all Ansible configs from source files"""
    subprocess.run(
        ["python3", "generate_configs.py"], cwd=ANSIBLE_DIR, capture_output=True
    )


@task
def ansible_sync(c):
    """Sync all Ansible configs from source files (hosts.txt, users.json, configs/)"""
    logger.info("Syncing Ansible configs from source files...")
    _sync_configs()
    logger.info("Config sync completed")


@task
def ansible_ping(c):
    """Test Ansible connectivity to all hosts"""
    logger.info("Testing Ansible connectivity to all hosts...")
    _sync_configs()
    _run_ansible_command(["ansible", "all", "-m", "ping"], check=False)


@task
def ansible_facts(c, host="all"):
    """Gather and display facts from hosts"""
    logger.info(f"Gathering facts from {host}...")
    _sync_configs()
    _run_ansible_command(
        [
            "ansible",
            host,
            "-m",
            "setup",
            "-a",
            "filter=ansible_distribution,ansible_distribution_version,ansible_os_family",
        ],
        check=False,
    )


@task
def ansible_bootstrap(c, limit=None):
    """Run the bootstrap playbook to ensure Python is installed"""
    logger.info("Running Ansible bootstrap playbook...")
    _sync_configs()

    cmd = ["ansible-playbook", "playbooks/bootstrap.yaml"]
    if limit:
        cmd.extend(["--limit", limit])

    _run_ansible_command(cmd, check=False)


@task
def ansible_logging(c, limit=None, check=False):
    """Run the logging_setup Ansible playbook

    Args:
        limit: Limit to specific hosts (e.g., 'debian', 'redhat')
        check: Run in check mode (dry run)
    """
    logger.info("Running logging_setup Ansible playbook...")
    _sync_configs()

    cmd = ["ansible-playbook", "playbooks/logging_setup.yaml"]
    if limit:
        cmd.extend(["--limit", limit])
    if check:
        cmd.append("--check")

    _run_ansible_command(cmd, check=False)


@task
def ansible_run(c, playbook, limit=None, check=False, verbose=False):
    """Run any Ansible playbook by name

    Args:
        playbook: Name of the playbook (without .yaml extension)
        limit: Limit to specific hosts
        check: Run in check mode (dry run)
        verbose: Enable verbose output

    Example:
        fab ansible-run --playbook=logging_setup --limit=debian --check
    """
    _sync_configs()

    playbook_path = f"playbooks/{playbook}"
    if not playbook_path.endswith(".yaml"):
        playbook_path += ".yaml"

    full_path = os.path.join(ANSIBLE_DIR, playbook_path)
    if not os.path.exists(full_path):
        logger.error(f"Playbook not found: {playbook_path}")
        logger.info("Available playbooks:")
        playbooks_dir = os.path.join(ANSIBLE_DIR, "playbooks")
        for f in os.listdir(playbooks_dir):
            if f.endswith(".yaml"):
                logger.info(f"  - {f.replace('.yaml', '')}")
        return

    logger.info(f"Running Ansible playbook: {playbook}")

    cmd = ["ansible-playbook", playbook_path]
    if limit:
        cmd.extend(["--limit", limit])
    if check:
        cmd.append("--check")
    if verbose:
        cmd.append("-v")

    _run_ansible_command(cmd, check=False)


@task
def ansible_shell(c, host, command):
    """Run a shell command on hosts via Ansible

    Args:
        host: Target host(s) - can be hostname, group, or 'all'
        command: Shell command to run

    Example:
        fab ansible-shell --host=debian --command="cat /etc/os-release"
    """
    _sync_configs()
    logger.info(f"Running command on {host}: {command}")
    _run_ansible_command(["ansible", host, "-m", "shell", "-a", command], check=False)


@task
def list_playbooks(c):
    """List available Ansible playbooks"""
    playbooks_dir = os.path.join(ANSIBLE_DIR, "playbooks")

    print("\nAvailable Ansible playbooks:")
    print("=" * 40)

    for f in sorted(os.listdir(playbooks_dir)):
        if f.endswith(".yaml"):
            name = f.replace(".yaml", "")
            print(f"  {name}")

    print("\nUsage:")
    print("  fab ansible-run --playbook=<name>")
    print("  fab ansible-run --playbook=<name> --limit=debian --check")
