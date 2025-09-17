"""
Base classes for hardening modules
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any, Union
from fabric import Connection

from ..models import ServerInfo
from ..discovery import OSFamily, CommandResult

logger = logging.getLogger(__name__)


class HardeningAction(ABC):
    """Base class for hardening actions"""
    def __init__(self, description: str, requires_sudo: bool = True, os_families: Optional[List[OSFamily]] = None):
        self.description = description
        self.requires_sudo = requires_sudo
        self.os_families = os_families


@dataclass
class CommandAction(HardeningAction):
    """Represents a shell command hardening action"""
    command: str
    description: str
    check_command: Optional[str] = field(default=None)  # Command to check if already applied
    rollback_command: Optional[str] = field(default=None)  # Command to rollback if needed
    requires_sudo: bool = field(default=True)
    os_families: Optional[List[OSFamily]] = field(default=None)  # None means all
    
    def __post_init__(self):
        super().__init__(self.description, self.requires_sudo, self.os_families)


@dataclass 
class PythonAction(HardeningAction):
    """Represents a Python function hardening action"""
    function: Callable
    description: str
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    check_function: Optional[Callable] = field(default=None)  # Function to check if already applied
    requires_sudo: bool = field(default=True)
    os_families: Optional[List[OSFamily]] = field(default=None)  # None means all
    
    def __post_init__(self):
        super().__init__(self.description, self.requires_sudo, self.os_families)


# Backward compatibility alias
HardeningCommand = CommandAction


@dataclass
class HardeningResult:
    """Result of a hardening operation"""
    success: bool
    command: str
    description: str
    output: str = ""
    error: Optional[str] = None
    already_applied: bool = False


class HardeningModule(ABC):
    """Base class for hardening modules"""
    
    def __init__(self, connection: Connection, server_info: ServerInfo, os_family: str):
        self.conn = connection
        self.server_info = server_info
        self.os_family = os_family
        self.results: List[HardeningResult] = []
        
    @abstractmethod
    def get_name(self) -> str:
        """Get module name"""
        pass
    
    @abstractmethod
    def get_commands(self) -> List[Union[HardeningAction, HardeningCommand]]:
        """Get list of hardening actions (commands or Python functions)"""
        pass
    
    def get_actions(self) -> List[HardeningAction]:
        """Get list of hardening actions - preferred method over get_commands"""
        commands = self.get_commands()
        # Convert old HardeningCommand objects to CommandAction for compatibility
        actions = []
        for cmd in commands:
            if isinstance(cmd, HardeningAction):
                actions.append(cmd)
            else:
                # Assume it's the old HardeningCommand format, convert to CommandAction
                actions.append(CommandAction(
                    command=cmd.command,
                    description=cmd.description,
                    check_command=getattr(cmd, 'check_command', None),
                    rollback_command=getattr(cmd, 'rollback_command', None),
                    requires_sudo=cmd.requires_sudo,
                    os_families=cmd.os_families
                ))
        return actions
    
    def is_applicable(self) -> bool:
        """Check if this module is applicable to the system"""
        return True
    
    def _run_command(self, command: str, use_sudo: bool = False) -> CommandResult:
        """Run a command with optional sudo"""
        if use_sudo and self.conn.user != 'root':
            command = f'sudo {command}'
            
        try:
            result = self.conn.run(command, hide=True, warn=True)
            stderr_content = result.stderr.strip() if result.stderr else None
            
            # Check for error indicators in stderr even if exit code is 0
            command_success = result.ok
            if command_success and stderr_content:
                # List of error patterns that indicate failure even with exit code 0
                error_patterns = [
                    'Permission denied',
                    'No such file or directory',
                    'cannot access',
                    'Operation not permitted',
                    'command not found',
                    'Permission denied',
                    'Access denied',
                    'cannot create',
                    'cannot remove',
                    'cannot write',
                    'Read-only file system',
                    'Device or resource busy',
                    'File exists',
                    'Directory not empty',
                    'Invalid argument',
                    'Connection refused',
                    'Connection timed out',
                    'Network is unreachable',
                    'Host is down'
                ]
                
                # Check if stderr contains any error patterns
                stderr_lower = stderr_content.lower()
                for pattern in error_patterns:
                    if pattern.lower() in stderr_lower:
                        logger.warning(f"Command appeared successful but stderr contains error: {pattern}")
                        command_success = False
                        break
            
            return CommandResult(
                success=command_success,
                output=result.stdout.strip(),
                error=stderr_content,
                command=command
            )
        except Exception as e:
            return CommandResult(
                success=False,
                output="",
                error=str(e),
                command=command
            )
    
    def apply_action(self, action: HardeningAction) -> HardeningResult:
        """Apply a single hardening action (command or Python function)"""
        if isinstance(action, CommandAction):
            return self.apply_command(action)
        elif isinstance(action, PythonAction):
            return self.apply_python_action(action)
        else:
            return HardeningResult(
                success=False,
                command=str(action),
                description=action.description,
                error="Unknown action type"
            )
    
    def apply_command(self, hardening_cmd: CommandAction) -> HardeningResult:
        """Apply a single hardening command"""
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
                        already_applied=False
                    )
            except ValueError:
                # If os_family is not a valid OSFamily enum, skip OS-specific commands
                if hardening_cmd.os_families:
                    return HardeningResult(
                        success=True,
                        command=hardening_cmd.command,
                        description=hardening_cmd.description,
                        output="Skipped - unknown OS family",
                        already_applied=False
                    )
        
        # Check if already applied
        if hardening_cmd.check_command:
            check_result = self._run_command(
                hardening_cmd.check_command, 
                use_sudo=hardening_cmd.requires_sudo
            )
            if check_result.success and check_result.output:
                return HardeningResult(
                    success=True,
                    command=hardening_cmd.command,
                    description=hardening_cmd.description,
                    output="Already applied",
                    already_applied=True
                )
        
        # Apply the hardening command
        result = self._run_command(
            hardening_cmd.command,
            use_sudo=hardening_cmd.requires_sudo
        )
        
        # If command execution failed, return failure immediately
        if not result.success:
            return HardeningResult(
                success=False,
                command=hardening_cmd.command,
                description=hardening_cmd.description,
                output=result.output,
                error=result.error or "Command failed"
            )
        
        # If there's a check command, verify the action actually succeeded
        if hardening_cmd.check_command:
            verify_result = self._run_command(
                hardening_cmd.check_command,
                use_sudo=hardening_cmd.requires_sudo
            )
            
            # Only consider it successful if both the command ran AND the check passed
            if not verify_result.success or not verify_result.output:
                return HardeningResult(
                    success=False,
                    command=hardening_cmd.command,
                    description=hardening_cmd.description,
                    output=result.output,
                    error=f"Command executed but verification failed. Check command: {hardening_cmd.check_command}. Check output: {verify_result.output}. Check error: {verify_result.error}"
                )
        
        return HardeningResult(
            success=True,
            command=hardening_cmd.command,
            description=hardening_cmd.description,
            output=result.output,
            error=result.error
        )
    
    def apply_python_action(self, python_action: PythonAction) -> HardeningResult:
        """Apply a single Python function action"""
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
                        already_applied=False
                    )
            except ValueError:
                # If os_family is not a valid OSFamily enum, skip OS-specific actions
                if python_action.os_families:
                    return HardeningResult(
                        success=True,
                        command=f"python_function:{python_action.function.__name__}",
                        description=python_action.description,
                        output="Skipped - unknown OS family",
                        already_applied=False
                    )
        
        # Check if already applied using check_function
        if python_action.check_function:
            try:
                check_result = python_action.check_function(
                    self.conn, self.server_info, *python_action.args, **python_action.kwargs
                )
                if isinstance(check_result, bool) and check_result:
                    return HardeningResult(
                        success=True,
                        command=f"python_function:{python_action.function.__name__}",
                        description=python_action.description,
                        output="Already applied",
                        already_applied=True
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
                    output="Function executed successfully" if result else "Function failed",
                    error=None if result else "Function returned False"
                )
            elif isinstance(result, dict):
                # Allow functions to return a dict that gets converted to HardeningResult
                return HardeningResult(
                    success=result.get('success', True),
                    command=f"python_function:{python_action.function.__name__}",
                    description=python_action.description,
                    output=result.get('output', ''),
                    error=result.get('error', None)
                )
            else:
                # Treat any other return value as success with output
                return HardeningResult(
                    success=True,
                    command=f"python_function:{python_action.function.__name__}",
                    description=python_action.description,
                    output=str(result) if result is not None else "Function completed successfully"
                )
                
        except Exception as e:
            logger.error(f"Python action failed: {e}")
            return HardeningResult(
                success=False,
                command=f"python_function:{python_action.function.__name__}",
                description=python_action.description,
                output="",
                error=str(e)
            )
    
    def apply_all(self, dry_run: bool = False) -> List[HardeningResult]:
        """Apply all hardening actions (commands and Python functions)"""
        if not self.is_applicable():
            logger.info(f"Module {self.get_name()} is not applicable to this system")
            return []
        
        actions = self.get_actions()
        
        for action in actions:
            if dry_run:
                logger.info(f"[DRY RUN] Would execute: {action.description}")
                # Create appropriate command representation for dry run
                if isinstance(action, CommandAction):
                    command_repr = action.command
                elif isinstance(action, PythonAction):
                    command_repr = f"python_function:{action.function.__name__}"
                else:
                    command_repr = str(action)
                    
                self.results.append(HardeningResult(
                    success=True,
                    command=command_repr,
                    description=action.description,
                    output="DRY RUN - not executed"
                ))
            else:
                logger.info(f"Applying: {action.description}")
                result = self.apply_action(action)
                self.results.append(result)
                
                if result.success:
                    if result.already_applied:
                        logger.info(f"  ✓ Already applied")
                    else:
                        logger.info(f"  ✓ Success")
                else:
                    logger.error(f"  ✗ Failed: {result.error}")
        
        return self.results