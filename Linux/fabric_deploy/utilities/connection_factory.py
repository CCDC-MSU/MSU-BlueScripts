"""
Connection Factory for CCDC Hardening Framework.

Provides centralized, consistent SSH connection creation across all task files.
Eliminates duplicate connection setup boilerplate in:
- tasks/hardening.py
- tasks/discovery_tasks.py
- tasks/maintenance.py
- tasks/tools.py
"""

import logging
import os
from dataclasses import dataclass

import paramiko
from fabric import Config, Connection

from .models import ServerCredentials

logger = logging.getLogger(__name__)

# Default SSH connection timeouts and settings
DEFAULT_TIMEOUT = 90
DEFAULT_KEEPALIVE = 10

# Recovery key path relative to the fabric_deploy directory
RECOVERY_KEY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "keys/test-root-key.private"
)


@dataclass
class ConnectionConfig:
    """Configuration for creating connections."""

    timeout: int = DEFAULT_TIMEOUT
    allow_agent: bool = False
    look_for_keys: bool = False
    load_ssh_configs: bool = False
    load_system_host_keys: bool = False
    ignore_host_key_changes: bool = True


def create_connect_kwargs(
    server_creds: ServerCredentials,
    config: ConnectionConfig | None = None,
) -> dict:
    """
    Create connect_kwargs dictionary for Fabric Connection.

    Args:
        server_creds: Server credentials from hosts.txt
        config: Optional connection configuration overrides

    Returns:
        dict suitable for Connection(connect_kwargs=...)
    """
    if config is None:
        config = ConnectionConfig()

    connect_kwargs = {
        "allow_agent": config.allow_agent,
        "look_for_keys": config.look_for_keys,
        "timeout": config.timeout,
    }

    if server_creds.key_file:
        connect_kwargs["key_filename"] = server_creds.key_file
    elif server_creds.password:
        connect_kwargs["password"] = server_creds.password

    if server_creds.port != 22:
        connect_kwargs["port"] = server_creds.port

    return connect_kwargs


def create_fabric_config(
    server_creds: ServerCredentials,
    config: ConnectionConfig | None = None,
) -> Config:
    """
    Create Fabric Config object with appropriate overrides.

    Args:
        server_creds: Server credentials from hosts.txt
        config: Optional connection configuration overrides

    Returns:
        Fabric Config object
    """
    if config is None:
        config = ConnectionConfig()

    overrides = {
        "sudo": {"password": None},
        "load_ssh_configs": config.load_ssh_configs,
        "load_system_host_keys": config.load_system_host_keys,
    }

    # Set sudo password if using password authentication
    if server_creds.password and not server_creds.key_file:
        overrides["sudo"]["password"] = server_creds.password

    return Config(overrides=overrides)


def create_connection(
    server_creds: ServerCredentials,
    config: ConnectionConfig | None = None,
    user_override: str | None = None,
) -> Connection:
    """
    Create a Fabric Connection with standardized settings.

    This is the PRIMARY factory method for creating connections.

    Args:
        server_creds: Server credentials from hosts.txt
        config: Optional connection configuration overrides
        user_override: Optional username override (e.g., 'root' for fallback)

    Returns:
        Fabric Connection object (not yet opened)

    Example:
        conn = create_connection(server_creds)
        with conn:
            conn.run("hostname")
    """
    if config is None:
        config = ConnectionConfig()

    connect_kwargs = create_connect_kwargs(server_creds, config)
    fabric_config = create_fabric_config(server_creds, config)

    user = user_override if user_override else server_creds.user

    conn = Connection(
        server_creds.host,
        user=user,
        config=fabric_config,
        connect_kwargs=connect_kwargs,
    )

    # Apply host key policy if configured
    if config.ignore_host_key_changes:
        conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    return conn


def create_recovery_connection(
    server_creds: ServerCredentials,
    recovery_key: str | None = None,
) -> Connection:
    """
    Create a fallback connection using the recovery SSH key.

    Used when primary authentication fails and we need to use the
    pre-injected root key for recovery access.

    Args:
        server_creds: Server credentials (only host/port used)
        recovery_key: Path to recovery key (defaults to keys/test-root-key.private)

    Returns:
        Fabric Connection configured for root access with recovery key

    Raises:
        FileNotFoundError: If recovery key doesn't exist
    """
    key_path = recovery_key or RECOVERY_KEY_PATH

    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Recovery key not found: {key_path}")

    connect_kwargs = {
        "allow_agent": False,
        "look_for_keys": False,
        "timeout": DEFAULT_TIMEOUT,
        "key_filename": [key_path],
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

    conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    return conn


def test_connection(conn: Connection, keepalive: int = DEFAULT_KEEPALIVE) -> bool:
    """
    Test that a connection is working and set keepalive.

    Args:
        conn: Fabric Connection to test
        keepalive: Keepalive interval in seconds

    Returns:
        True if connection is working, False otherwise
    """
    try:
        conn.run("true", hide=True, timeout=10)
        if conn.transport:
            conn.transport.set_keepalive(keepalive)
        return True
    except Exception as e:
        logger.warning(f"Connection test failed: {e}")
        return False
