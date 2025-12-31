#!/usr/bin/env python3
"""
Individual Module Testing Framework for CCDC Hardening Scripts
Allows testing individual hardening modules without full deployment
"""

import sys
import os
import logging
import importlib
from datetime import datetime
from fabric import Connection, Config
from tabulate import tabulate

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utilities.models import ServerCredentials, ServerInfo
from utilities.discovery import SystemDiscovery
from utilities.utils import load_config, parse_hosts_file, setup_logging
from utilities.modules.base import HardeningModule

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

class ModuleTester:
    """Test individual hardening modules"""
    
    def __init__(self, config):
        self.config = config
        self.available_modules = self._discover_modules()
        
    def _discover_modules(self):
        """Discover all available hardening modules"""
        modules = {}
        modules_path = os.path.join(os.path.dirname(__file__), 'utilities', 'modules')
        
        for file in os.listdir(modules_path):
            if file.endswith('.py') and file not in ['__init__.py', 'base.py']:
                module_name = file[:-3]  # Remove .py extension
                modules[module_name] = file
                
        return modules
    
    def list_modules(self):
        """List all available modules"""
        print("\nAvailable Hardening Modules:")
        print("=" * 40)
        for i, module_name in enumerate(self.available_modules.keys(), 1):
            print(f"{i:2d}. {module_name}")
        print()
        
    def _connect_to_host(self, server_creds):
        """Establish connection to host"""
        connect_kwargs = {'allow_agent':False,'look_for_keys':False }
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
        
        if server_creds.port != 22:
            connect_kwargs['port'] = server_creds.port
            
        config = Config(overrides=config_overrides)
        
        return Connection(
            server_creds.host, 
            user=server_creds.user,
            config=config,
            connect_kwargs=connect_kwargs
        )
    
    def _load_module_class(self, module_name):
        """Dynamically load a hardening module class"""
        try:
            # Import the module
            module_path = f'utilities.modules.{module_name}'
            module = importlib.import_module(module_path)
            
            # Find the hardening module class (should inherit from HardeningModule)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, HardeningModule) and 
                    attr != HardeningModule):
                    return attr
                    
            raise ValueError(f"No HardeningModule subclass found in {module_name}")
            
        except ImportError as e:
            raise ValueError(f"Could not import module {module_name}: {e}")
    
    def test_module(self, module_name, host_index=0, dry_run=True, verbose=False):
        """Test a specific module on a host"""
        # Configure verbose logging if requested
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            # Also set fabric logging to be more verbose
            logging.getLogger('fabric').setLevel(logging.DEBUG)
            logging.getLogger('paramiko').setLevel(logging.INFO)
            logger.info("Verbose logging enabled")
            
        if module_name not in self.available_modules:
            logger.error(f"Module '{module_name}' not found")
            return False
            
        # Parse hosts file
        try:
            servers = parse_hosts_file('hosts.txt')
        except Exception as e:
            logger.error(f"Error parsing hosts file: {e}")
            return False
            
        if not servers:
            logger.error("No servers found in hosts file")
            return False
            
        if host_index >= len(servers):
            logger.error(f"Host index {host_index} out of range (0-{len(servers)-1})")
            return False
            
        server_creds = servers[host_index]
        
        logger.info("=" * 60)
        logger.info(f"TESTING MODULE: {module_name}")
        logger.info(f"TARGET HOST: {server_creds.host}")
        logger.info(f"DRY RUN: {dry_run}")
        logger.info("=" * 60)
        
        start_time = datetime.now()
        
        try:
            with self._connect_to_host(server_creds) as conn:

                # Discover system inf0
                logger.info("Performing system discovery...")
                discovery = SystemDiscovery(conn, server_creds)
                server_info = discovery.discover_system()
                
                if not server_info.discovery_successful:
                    logger.error("System discovery failed")
                    return False
                
                logger.info(f"Discovery successful - OS: {server_info.os.distro} {server_info.os.version}")
                
                # Load and instantiate the module
                logger.info(f"Loading module: {module_name}")
                module_class = self._load_module_class(module_name)
                
                # Get OS family for module initialization
                os_family = discovery.os_family
                
                # Create module instance
                module_instance = module_class(conn, server_info, os_family)
                
                logger.info(f"Module loaded: {module_instance.get_name()}")
                
                # Check if module is applicable
                if not module_instance.is_applicable():
                    logger.warning("Module is not applicable to this system")
                    return True
                
                # Get actions that would be executed
                actions = module_instance.get_actions()
                
                logger.info(f"Found {len(actions)} actions to execute")
                
                # Display actions summary (write details to file to reduce noise)
                if actions:
                    from utilities.modules.base import CommandAction, PythonAction
                    # Write detailed actions to file
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    cmd_file = f"/tmp/{module_name}_actions_{server_creds.host}_{timestamp}.txt"
                    
                    with open(cmd_file, 'w') as f:
                        f.write(f"Actions for {module_name} module on {server_creds.host}\n")
                        f.write("=" * 60 + "\n\n")
                        for i, action in enumerate(actions, 1):
                            f.write(f"{i:2d}. {action.description}\n")
                            if isinstance(action, CommandAction):
                                f.write(f"    Type: Shell Command\n")
                                f.write(f"    Command: {action.command}\n")
                                if action.check_command:
                                    f.write(f"    Check: {action.check_command}\n")
                            elif isinstance(action, PythonAction):
                                f.write(f"    Type: Python Function\n")
                                f.write(f"    Function: {action.function.__name__}\n")
                                if action.args:
                                    f.write(f"    Args: {action.args}\n")
                                if action.kwargs:
                                    f.write(f"    Kwargs: {action.kwargs}\n")
                            f.write(f"    Sudo: {action.requires_sudo}\n")
                            if action.os_families:
                                f.write(f"    OS Families: {[f.value for f in action.os_families]}\n")
                            f.write("\n")
                    
                    logger.info(f"{len(actions)} actions ready - details written to: {cmd_file}")
                
                # Execute module
                logger.info(f"Executing module {'(DRY RUN)' if dry_run else '(LIVE)'}")
                if verbose:
                    logger.info("Starting detailed action execution...")
                results = self._apply_all_with_verbose_logging(module_instance, dry_run, verbose)
                
                # Display results
                self._display_results(results)
                
                end_time = datetime.now()
                duration = end_time - start_time
                
                logger.info("=" * 60)
                logger.info(f"MODULE TEST COMPLETED - Duration: {duration}")
                logger.info("=" * 60)
                
                return True
                
        except Exception as e:
            logger.error(f"Module test failed: {e}")
            return False
    
    def _apply_all_with_verbose_logging(self, module_instance, dry_run, verbose):
        """Apply all actions with detailed verbose logging and timeout handling"""
        import time
        from utilities.modules.base import CommandAction, PythonAction
        
        if not module_instance.is_applicable():
            logger.info(f"Module {module_instance.get_name()} is not applicable to this system")
            return []
        
        actions = module_instance.get_actions()
        results = []
        
        for i, action in enumerate(actions, 1):
            action_type = "CMD" if isinstance(action, CommandAction) else "PY" if isinstance(action, PythonAction) else "?"
            
            if verbose:
                logger.info(f"[{i}/{len(actions)}] [{action_type}] Starting: {action.description}")
                if isinstance(action, CommandAction):
                    logger.info(f"  COMMAND: {action.command}")
                elif isinstance(action, PythonAction):
                    logger.info(f"  FUNCTION: {action.function.__name__}")
            
            start_time = time.time()
            
            try:
                if dry_run:
                    if verbose:
                        logger.info(f"[{i}/{len(actions)}] [DRY RUN] Would execute: {action.description}")
                    
                    # Create appropriate command representation for dry run
                    if isinstance(action, CommandAction):
                        command_repr = action.command
                    elif isinstance(action, PythonAction):
                        command_repr = f"python_function:{action.function.__name__}"
                    else:
                        command_repr = str(action)
                        
                    from utilities.modules.base import HardeningResult
                    result = HardeningResult(
                        success=True,
                        command=command_repr,
                        description=action.description,
                        output="DRY RUN - not executed"
                    )
                else:
                    if verbose:
                        logger.info(f"[{i}/{len(actions)}] Applying: {action.description}")
                    
                    # Add timeout handling for live execution
                    result = self._apply_action_with_timeout(module_instance, action, timeout=300)
                
                execution_time = time.time() - start_time
                
                if verbose:
                    status = "SUCCESS" if result.success else "FAILED"
                    if result.already_applied:
                        status = "ALREADY_APPLIED"
                    logger.info(f"[{i}/{len(actions)}] [{status}] Completed in {execution_time:.2f}s")
                    
                    # Always show output and errors in verbose mode for better debugging
                    if result.output:
                        logger.info(f"  OUTPUT: {result.output}")
                    if result.error:
                        logger.warning(f"  ERROR: {result.error}")
                
                results.append(result)
                
                if result.success:
                    if result.already_applied:
                        logger.info(f"  ✓ Already applied")
                    else:
                        logger.info(f"  ✓ Success")
                else:
                    logger.error(f"  ✗ Failed: {result.error}")
                    if verbose:
                        logger.error(f"Full error details: {result.error}")
                        
            except Exception as e:
                execution_time = time.time() - start_time
                error_msg = str(e)
                logger.error(f"[{i}/{len(actions)}] EXCEPTION after {execution_time:.2f}s: {error_msg}")
                
                # Create a failed result
                if isinstance(action, CommandAction):
                    command_repr = action.command
                elif isinstance(action, PythonAction):
                    command_repr = f"python_function:{action.function.__name__}"
                else:
                    command_repr = str(action)
                    
                from utilities.modules.base import HardeningResult
                result = HardeningResult(
                    success=False,
                    command=command_repr,
                    description=action.description,
                    output="",
                    error=error_msg
                )
                results.append(result)
        
        return results
    
    def _apply_action_with_timeout(self, module_instance, action, timeout=300):
        """Apply an action with timeout handling"""
        import signal
        import time
        import threading
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Action timed out after {timeout} seconds")

        if threading.current_thread() is not threading.main_thread():
            # logger.warning("Timeout disabled (non-main thread)")
            return module_instance.apply_action(action)
        
        # Set up timeout for non-dry runs
        original_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        
        try:
            result = module_instance.apply_action(action)
            signal.alarm(0)  # Cancel the alarm
            return result
        except TimeoutError as e:
            logger.error(f"Action timed out: {action.description}")
            if isinstance(action, CommandAction):
                command_repr = action.command
            elif isinstance(action, PythonAction):
                command_repr = f"python_function:{action.function.__name__}"
            else:
                command_repr = str(action)
                
            from utilities.modules.base import HardeningResult
            return HardeningResult(
                success=False,
                command=command_repr,
                description=action.description,
                output="",
                error=str(e)
            )
        finally:
            signal.signal(signal.SIGALRM, original_handler)

    def _display_results(self, results):
        """Display module execution results in a table"""
        if not results:
            logger.info("No results to display")
            return
            
        # Prepare table data
        table_data = []
        success_count = 0
        already_applied_count = 0
        
        for result in results:
            status = "✓ SUCCESS" if result.success else "✗ FAILED"
            if result.success and result.already_applied:
                status = "• ALREADY APPLIED"
                already_applied_count += 1
            elif result.success:
                success_count += 1
                
            # Truncate long outputs
            output = result.output
            error = result.error or ""
            
            table_data.append([
                status,
                result.description[:40] + "..." if len(result.description) > 40 else result.description,
                output,
                error
            ])
        
        # Display table
        headers = ["Status", "Description", "Output", "Error"]
        table = tabulate(table_data, headers=headers, tablefmt="simple")
        
        # Summary
        total = len(results)
        failed_count = total - success_count - already_applied_count
        
        summary_lines = [
            "Execution Results:",
            "=" * 100,
            table,
            "",
            f"Summary: {total} commands",
            f"  ✓ Successful: {success_count}",
            f"  • Already Applied: {already_applied_count}",
            f"  ✗ Failed: {failed_count}",
        ]
        logger.info("\n".join(summary_lines))

def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test individual hardening modules")
    parser.add_argument('--list', '-l', action='store_true', help='List available modules')
    parser.add_argument('--module', '-m', help='Module name to test')
    parser.add_argument('--host-index', '-i', type=int, default=0, help='Host index from hosts.txt (default: 0)')
    parser.add_argument('--live', action='store_true', help='Run in live mode (default is dry-run)')
    parser.add_argument('--config', default='config.yaml', help='Configuration file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging output')
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logger.error(f"Could not load config: {e}")
        sys.exit(1)
    
    tester = ModuleTester(config)
    
    if args.list:
        tester.list_modules()
        return
    
    if not args.module:
        print("No module specified. Use --list to see available modules or --module <name> to test.")
        tester.list_modules()
        return
    
    # Test the module
    dry_run = not args.live
    success = tester.test_module(args.module, args.host_index, dry_run, verbose=args.verbose)
    
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()
