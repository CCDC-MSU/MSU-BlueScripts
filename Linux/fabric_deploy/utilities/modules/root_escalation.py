"""
Root Escalation Module for CCDC Framework.

When hosts.txt specifies a non-root user with sudo access, this module:
1. Unlocks the root account
2. Sets a new root password
3. Injects SSH key into root's authorized_keys
4. Creates a new connection as root
5. Returns the new root connection for use by subsequent operations

This enables the rest of the hardening pipeline to run as root without
needing sudo support throughout the codebase.
"""

import logging
import os
import time

import paramiko
from fabric import Config, Connection

from ..deployment import CriticalPipelineError
from ..models import ServerCredentials
from ..utils import generate_password

logger = logging.getLogger(__name__)

ROOT_KEY_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../keys/test-root-key.pub")
)
ROOT_KEY_PATH_PRIVATE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../keys/test-root-key.private")
)


def escalate_to_root(
    conn: Connection,
    server_creds: ServerCredentials,
    sudo_password: str | None = None,
) -> tuple[Connection, str]:
    """
    Escalate from a sudo-capable user to root.

    Args:
        conn: Active Fabric connection as a sudo-capable non-root user
        server_creds: Server credentials from hosts.txt
        sudo_password: Password for sudo (defaults to server_creds.password)

    Returns:
        Tuple of (new_root_connection, root_password)

    Raises:
        CriticalPipelineError: If escalation fails at any step
    """
    if conn.user == "root":
        logger.info("Already connected as root, skipping escalation")
        return conn, ""

    host = server_creds.host
    sudo_pass = sudo_password or server_creds.password

    if not sudo_pass:
        raise CriticalPipelineError(
            f"Cannot escalate to root on {host}: no sudo password available"
        )

    logger.info(f"Escalating to root on {host} from user {conn.user}")

    # Step 1: Generate new root password
    root_password = generate_password()
    logger.debug(f"Generated new root password: {root_password}")

    # Step 2: Read the SSH public key
    if not os.path.exists(ROOT_KEY_PATH):
        raise CriticalPipelineError(
            f"Root SSH key not found at {ROOT_KEY_PATH}. Cannot escalate."
        )

    try:
        with open(ROOT_KEY_PATH) as f:
            key_content = f.read().strip()
    except OSError as e:
        raise CriticalPipelineError(f"Failed to read root SSH key: {e}") from e

    if not key_content:
        raise CriticalPipelineError("Root SSH key file is empty")

    # Step 3: Execute escalation commands via sudo
    # All commands must use sudo since we're not root
    try:
        _unlock_root(conn, sudo_pass)
        _set_root_password(conn, sudo_pass, root_password)
        _inject_ssh_key(conn, sudo_pass, key_content)
    except Exception as e:
        raise CriticalPipelineError(
            f"Failed to prepare root access on {host}: {e}"
        ) from e

    # Step 4: Create new connection as root using SSH key
    root_conn = _create_root_connection(server_creds)

    # Step 5: Test the root connection
    if not _test_root_connection(root_conn):
        raise CriticalPipelineError(
            f"Failed to establish root connection on {host}. "
            f"Manual intervention required."
        )

    logger.info(f"Successfully escalated to root on {host}")
    return root_conn, root_password


def _run_sudo_command(conn: Connection, sudo_password: str, command: str) -> bool:
    """
    Run a command with sudo, handling password prompt.

    Uses conn.run() which automatically handles password prompting
    when the connection's config has sudo.password set.
    """
    # Temporarily ensure sudo password is set in connection config
    original_sudo_pass = conn.config.sudo.password
    conn.config.sudo.password = sudo_password

    try:
        result = conn.sudo(command, hide=True, warn=True)
        return result.ok
    except Exception as e:
        logger.error(f"sudo command failed: {e}")
        return False
    finally:
        conn.config.sudo.password = original_sudo_pass


def _unlock_root(conn: Connection, sudo_password: str) -> None:
    """Unlock the root account."""
    logger.info("Unlocking root account...")

    # Try different unlock methods based on OS
    # Linux: passwd -u root
    # BSD: pw unlock root
    # We try passwd first as it's more common

    # First check if root is locked
    # On Linux, a locked account has '!' or '!!' prefix in /etc/shadow
    check_result = conn.run(
        "sudo grep '^root:' /etc/shadow 2>/dev/null | grep -q '^root:[!*]'",
        hide=True,
        warn=True,
    )

    if check_result.ok:
        # Root is locked, unlock it
        unlock_commands = [
            "passwd -u root",  # Linux
            "pw unlock root",  # BSD
        ]

        for unlock_cmd in unlock_commands:
            if _run_sudo_command(conn, sudo_password, unlock_cmd):
                logger.info("Root account unlocked")
                return

        logger.warning("Could not unlock root with standard commands, proceeding anyway")
    else:
        logger.info("Root account appears to already be unlocked")


def _set_root_password(conn: Connection, sudo_password: str, new_password: str) -> None:
    """Set a new password for the root account."""
    logger.info("Setting new root password...")

    # Use chpasswd which reads from stdin
    # Format: username:password
    # Must use sh -c for pipeline with sudo
    cmd = f"sh -c 'echo \"root:{new_password}\" | chpasswd'"

    if not _run_sudo_command(conn, sudo_password, cmd):
        # Try alternative method for BSD
        # echo 'password' | pw usermod root -h 0
        cmd_bsd = f"sh -c 'echo \"{new_password}\" | pw usermod root -h 0'"
        if not _run_sudo_command(conn, sudo_password, cmd_bsd):
            raise RuntimeError("Failed to set root password with chpasswd or pw")

    logger.info(f"Root password set successfully: {new_password}")


def _inject_ssh_key(conn: Connection, sudo_password: str, key_content: str) -> None:
    """Inject SSH public key into root's authorized_keys."""
    logger.info("Injecting SSH key into root's authorized_keys...")

    # Create .ssh directory and set permissions, then append key
    # All in one sudo sh -c command to avoid multiple sudo calls
    cmd = (
        f"sh -c '"
        f"mkdir -p /root/.ssh && "
        f"chmod 700 /root/.ssh && "
        f"touch /root/.ssh/authorized_keys && "
        f"chmod 600 /root/.ssh/authorized_keys && "
        f"grep -qF \"{key_content}\" /root/.ssh/authorized_keys 2>/dev/null || "
        f"echo \"{key_content}\" >> /root/.ssh/authorized_keys"
        f"'"
    )

    if not _run_sudo_command(conn, sudo_password, cmd):
        raise RuntimeError("Failed to inject SSH key into root's authorized_keys")

    logger.info("SSH key injected successfully")


def _create_root_connection(server_creds: ServerCredentials) -> Connection:
    """Create a new connection as root using the SSH key."""
    logger.info("Creating root connection with SSH key...")

    if not os.path.exists(ROOT_KEY_PATH_PRIVATE):
        raise CriticalPipelineError(
            f"Root private key not found at {ROOT_KEY_PATH_PRIVATE}"
        )

    connect_kwargs = {
        "allow_agent": False,
        "look_for_keys": False,
        "timeout": 30,
        "key_filename": [ROOT_KEY_PATH_PRIVATE],
    }

    if server_creds.port != 22:
        connect_kwargs["port"] = server_creds.port

    fabric_config = Config(
        overrides={
            "load_ssh_configs": False,
            "load_system_host_keys": False,
        }
    )

    conn = Connection(
        server_creds.host,
        user="root",
        config=fabric_config,
        connect_kwargs=connect_kwargs,
    )

    # Auto-accept host keys
    conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    return conn


def _test_root_connection(conn: Connection, max_retries: int = 3) -> bool:
    """Test that the root connection works."""
    logger.info("Testing root connection...")

    for attempt in range(1, max_retries + 1):
        try:
            conn.open()
            result = conn.run("id -u", hide=True, timeout=10)
            if result.ok and result.stdout.strip() == "0":
                logger.info("Root connection verified (uid=0)")
                if conn.transport:
                    conn.transport.set_keepalive(10)
                return True
            else:
                logger.warning(f"Connection works but not root: uid={result.stdout.strip()}")
                return False
        except Exception as e:
            logger.warning(f"Root connection test attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                time.sleep(2)
                try:
                    conn.close()
                except Exception:
                    pass

    return False
