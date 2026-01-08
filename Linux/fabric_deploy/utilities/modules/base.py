"""
Base classes for hardening modules.
"""

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field

from fabric import Connection

from ..discovery import OSFamily
from ..logging_context import log_context
from ..models import ServerInfo
from ..ssh_runner import CommandResult, run_command
from ..utils import retry_on_connection_failure

logger = logging.getLogger(__name__)



@dataclass
class CommandAction:
    """
    Represents a shell command hardening action.
    """

    command: str
    description: str
    check_command: str | None = field(default=None)
    requires_sudo: bool = field(default=True)
    os_families: list[OSFamily] | None = field(default=None)


@dataclass
class PythonAction:
    """
    Represents a Python function hardening action.
    """

    function: Callable
    description: str
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    check_function: Callable | None = field(default=None)
    requires_sudo: bool = field(default=True)
    os_families: list[OSFamily] | None = field(default=None)


@dataclass
class HardeningResult:
    """Result of a hardening operation"""

    success: bool
    command: str
    description: str
    output: str = ""
    error: str | None = None
    already_applied: bool = False


class HardeningModule(ABC):
    """Base class for hardening modules"""

    def __init__(self, connection: Connection, server_info: ServerInfo, os_family: str):
        self.conn = connection
        self.server_info = server_info
        self.os_family = os_family
        self.results: list[HardeningResult] = []

    @abstractmethod
    def get_name(self) -> str:
        """Get module name"""
        pass

    @abstractmethod
    def get_commands(self) -> list[CommandAction | PythonAction]:
        """Get list of hardening actions (commands or Python functions)"""
        pass

    def get_actions(self) -> list[CommandAction | PythonAction]:
        """
        Get list of hardening actions.
        """
        return self.get_commands()

    def is_applicable(self) -> bool:
        """Check if this module is applicable to the system"""
        return True

    @retry_on_connection_failure(max_retries=3, delay=2)
    def _run_command(self, command: str, use_sudo: bool = False) -> CommandResult:
        """
        Run a command with optional sudo.
        Delegates to shared ssh_runner.run_command() with stderr error checking.
        """
        return run_command(
            self.conn,
            command,
            use_sudo=use_sudo,
            check_stderr_errors=True,
        )

    def apply_action(self, action: CommandAction | PythonAction) -> HardeningResult:
        """
        Apply a single hardening action (command or Python function).
        """
        match action:
            case CommandAction():
                return self._apply_command_action(action)
            case PythonAction():
                return self._apply_python_action(action)
            case _:
                return HardeningResult(
                    success=False,
                    command=str(action),
                    description=getattr(action, "description", "Unknown"),
                    error=f"Unknown action type: {type(action).__name__}",
                )

    def _apply_command_action(self, hardening_cmd: CommandAction) -> HardeningResult:
        """Apply a single shell command action (internal implementation)."""
        # Check if command is applicable to this OS
        if hardening_cmd.os_families:
            try:
                current_family = OSFamily(self.os_family)
                if current_family not in hardening_cmd.os_families:
                    return HardeningResult(
                        success=True,
                        command=hardening_cmd.command,
                        description=hardening_cmd.description,
                        output="Skipped - not applicable to this OS",
                        already_applied=False,
                    )
            except ValueError:
                # If os_family is not a valid OSFamily enum, skip OS-specific commands
                if hardening_cmd.os_families:
                    return HardeningResult(
                        success=True,
                        command=hardening_cmd.command,
                        description=hardening_cmd.description,
                        output="Skipped - unknown OS family",
                        already_applied=False,
                    )

        # Check if already applied
        if hardening_cmd.check_command:
            check_result = self._run_command(
                hardening_cmd.check_command, use_sudo=hardening_cmd.requires_sudo
            )
            if check_result.success and check_result.output:
                return HardeningResult(
                    success=True,
                    command=hardening_cmd.command,
                    description=hardening_cmd.description,
                    output="Already applied",
                    already_applied=True,
                )

        # Apply the hardening command
        result = self._run_command(
            hardening_cmd.command, use_sudo=hardening_cmd.requires_sudo
        )

        # If command execution failed, return failure immediately
        if not result.success:
            return HardeningResult(
                success=False,
                command=hardening_cmd.command,
                description=hardening_cmd.description,
                output=result.output,
                error=result.error or "Command failed",
            )

        # If there's a check command, verify the action actually succeeded
        if hardening_cmd.check_command:
            verify_result = self._run_command(
                hardening_cmd.check_command, use_sudo=hardening_cmd.requires_sudo
            )

            # Only consider it successful if both the command ran AND the check passed
            if not verify_result.success or not verify_result.output:
                return HardeningResult(
                    success=False,
                    command=hardening_cmd.command,
                    description=hardening_cmd.description,
                    output=result.output,
                    error=f"Command executed but verification failed. Check command: {hardening_cmd.check_command}. Check output: {verify_result.output}. Check error: {verify_result.error}",
                )

        return HardeningResult(
            success=True,
            command=hardening_cmd.command,
            description=hardening_cmd.description,
            output=result.output,
            error=result.error,
        )

    def _apply_python_action(self, python_action: PythonAction) -> HardeningResult:
        """Apply a single Python function action (internal implementation)."""
        # Check if action is applicable to this OS
        if python_action.os_families:
            try:
                current_family = OSFamily(self.os_family)
                if current_family not in python_action.os_families:
                    return HardeningResult(
                        success=True,
                        command=f"python_function:{python_action.function.__name__}",
                        description=python_action.description,
                        output="Skipped - not applicable to this OS",
                        already_applied=False,
                    )
            except ValueError:
                # If os_family is not a valid OSFamily enum, skip OS-specific actions
                if python_action.os_families:
                    return HardeningResult(
                        success=True,
                        command=f"python_function:{python_action.function.__name__}",
                        description=python_action.description,
                        output="Skipped - unknown OS family",
                        already_applied=False,
                    )

        # Check if already applied using check_function
        if python_action.check_function:
            try:
                check_result = python_action.check_function(
                    self.conn,
                    self.server_info,
                    *python_action.args,
                    **python_action.kwargs,
                )
                if isinstance(check_result, bool) and check_result:
                    return HardeningResult(
                        success=True,
                        command=f"python_function:{python_action.function.__name__}",
                        description=python_action.description,
                        output="Already applied",
                        already_applied=True,
                    )
                elif isinstance(check_result, HardeningResult) and check_result.success:
                    check_result.already_applied = True
                    return check_result
            except Exception as e:
                logger.warning(f"Check function failed: {e}")

        # Execute the Python function
        try:
            result = python_action.function(
                self.conn, self.server_info, *python_action.args, **python_action.kwargs
            )

            # Handle different return types
            if isinstance(result, HardeningResult):
                return result
            elif isinstance(result, bool):
                return HardeningResult(
                    success=result,
                    command=f"python_function:{python_action.function.__name__}",
                    description=python_action.description,
                    output="Function executed successfully"
                    if result
                    else "Function failed",
                    error=None if result else "Function returned False",
                )
            elif isinstance(result, dict):
                # Allow functions to return a dict that gets converted to HardeningResult
                return HardeningResult(
                    success=result.get("success", True),
                    command=f"python_function:{python_action.function.__name__}",
                    description=python_action.description,
                    output=result.get("output", ""),
                    error=result.get("error", None),
                )
            else:
                # Treat any other return value as success with output
                return HardeningResult(
                    success=True,
                    command=f"python_function:{python_action.function.__name__}",
                    description=python_action.description,
                    output=str(result)
                    if result is not None
                    else "Function completed successfully",
                )

        except Exception as e:
            logger.error(f"Python action failed: {e}")
            return HardeningResult(
                success=False,
                command=f"python_function:{python_action.function.__name__}",
                description=python_action.description,
                output="",
                error=str(e),
            )

    def apply_all(self, dry_run: bool = False) -> list[HardeningResult]:
        """Apply all hardening actions (commands and Python functions)"""
        module_name = self.get_name()
        with log_context(module=module_name):
            if not self.is_applicable():
                logger.info(f"Module {module_name} is not applicable to this system")
                return []

            actions = self.get_actions()

            for action in actions:
                # Reduce verbosity for file operations
                log_lvl = logging.DEBUG if "Upload" in action.description or "executable" in action.description else logging.INFO

                if dry_run:
                    logger.log(log_lvl, f"[DRY RUN] {action.description}")
                    # Create appropriate command representation for dry run
                    if isinstance(action, CommandAction):
                        command_repr = action.command
                    elif isinstance(action, PythonAction):
                        command_repr = f"python_function:{action.function.__name__}"
                    else:
                        command_repr = str(action)

                    self.results.append(
                        HardeningResult(
                            success=True,
                            command=command_repr,
                            description=action.description,
                            output="DRY RUN - not executed",
                        )
                    )
                else:
                    result = self.apply_action(action)
                    self.results.append(result)

                    if result.success:
                        suffix = " (already applied)" if result.already_applied else ""
                        logger.log(log_lvl, f"{action.description} → ✓{suffix}")
                    else:
                        error_msg = result.error or "Unknown error"
                        logger.error(
                            f"{action.description} → ✗ {error_msg}"
                        )

            return self.results
