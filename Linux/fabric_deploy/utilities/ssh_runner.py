"""
SSH command execution utilities for CCDC hardening framework.
Provides a unified interface for running commands on remote hosts via Fabric/SSH.

This consolidates the duplicate _run_command implementations from:
- utilities/discovery.py (SystemDiscovery._run_command)
- utilities/modules/base.py (HardeningModule._run_command)
"""

import logging
from dataclasses import dataclass

from fabric import Connection
from invoke.exceptions import UnexpectedExit

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result of a command execution"""

    success: bool
    output: str
    error: str | None = None
    command: str | None = None


# Error patterns that indicate failure even if exit code is 0
STDERR_ERROR_PATTERNS = [
    "Permission denied",
    "No such file or directory",
    "cannot access",
    "Operation not permitted",
    "command not found",
    "Access denied",
    "cannot create",
    "cannot remove",
    "cannot write",
    "Read-only file system",
    "Device or resource busy",
    "File exists",
    "Directory not empty",
    "Invalid argument",
    "Connection refused",
    "Connection timed out",
    "Network is unreachable",
    "Host is down",
]


def run_command(
    conn: Connection,
    command: str,
    *,
    use_sudo: bool = False,
    warn: bool = True,
    timeout: int = 300,
    check_stderr_errors: bool = False,
) -> CommandResult:
    """
    Run a command on a remote host via SSH.

    This is the unified command execution function used throughout the framework.

    Args:
        conn: Fabric Connection object
        command: Shell command to execute
        use_sudo: If True and not root, prepend sudo to command
        warn: If True, don't raise exception on non-zero exit (default True)
        timeout: Command timeout in seconds (default 300 for long-running scripts)
        check_stderr_errors: If True, check stderr for error patterns even on success

    Returns:
        CommandResult with success, output, error, and command fields

    Example:
        result = run_command(conn, "cat /etc/passwd", timeout=10)
        if result.success:
            print(result.output)
    """
    # Handle sudo if needed
    if use_sudo and conn.user != "root":
        command = f"sudo {command}"

    max_retries = 2
    retry_delay = 2.0

    for attempt in range(max_retries + 1):
        try:
            result = conn.run(command, hide=True, warn=warn, timeout=timeout)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else None

            command_success = result.ok

            # Optionally check for error patterns in stderr
            if command_success and check_stderr_errors and stderr:
                stderr_lower = stderr.lower()
                for pattern in STDERR_ERROR_PATTERNS:
                    if pattern.lower() in stderr_lower:
                        logger.warning(
                            f"Command appeared successful but stderr contains error: {pattern}"
                        )
                        command_success = False
                        break

            return CommandResult(
                success=command_success,
                output=stdout,
                error=stderr,
                command=command,
            )

        except UnexpectedExit as e:
            # Command ran but failed with non-zero exit code (and warn=False)
            return CommandResult(
                success=False,
                output="",
                error=str(e),
                command=command,
            )
        except (OSError, EOFError) as e:
            # Network/Connectivity errors
            if attempt < max_retries:
                logger.warning(
                    f"Command failed with network error (attempt {attempt + 1}/{max_retries + 1}): {e}. Reconnecting and retrying..."
                )
                try:
                    conn.close()
                    import time
                    time.sleep(retry_delay)
                    conn.open()
                except Exception as reconnect_error:
                    logger.warning(f"Reconnection attempt failed: {reconnect_error}")
                continue
            else:
                return CommandResult(
                    success=False,
                    output="",
                    error=f"Network error after {max_retries + 1} attempts: {str(e)}",
                    command=command,
                )
        except Exception as e:
            # Other unexpected errors
            return CommandResult(
                success=False,
                output="",
                error=f"Unexpected error: {str(e)}",
                command=command,
            )


def run_command_chain(
    conn: Connection,
    commands: list[str],
    *,
    warn: bool = True,
    timeout: int = 300,
) -> CommandResult | None:
    """
    Try a chain of commands until one succeeds.

    Useful for cross-platform compatibility when different systems have
    different commands for the same operation.

    Args:
        conn: Fabric Connection object
        commands: List of commands to try in order
        warn: If True, don't raise exception on non-zero exit
        timeout: Command timeout in seconds

    Returns:
        CommandResult from first successful command, or None if all fail

    Example:
        result = run_command_chain(conn, [
            "ip link show",
            "ifconfig -a",
        ])
    """
    for cmd in commands:
        result = run_command(conn, cmd, warn=warn, timeout=timeout)
        if result.success and result.output:
            return result
    return None
