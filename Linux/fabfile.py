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
from datetime import datetime
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


@task
def discover(c, host, user=None, key_file=None, password=None):
    """Discover system information on target host"""
    # Use config defaults if not provided
    if user is None:
        user = CONFIG.get('connection', {}).get('user', 'root')
    if password is None and key_file is None:
        password = CONFIG.get('connection', {}).get('password')
    
    # Handle authentication
    connect_kwargs = {}
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
def harden(c, hosts_file='hosts.txt'):
    """Automated hardening pipeline - discovers and hardens all hosts"""
    logger.info("=" * 60)
    logger.info("CCDC AUTOMATED HARDENING PIPELINE STARTING")
    logger.info("=" * 60)
    
    start_time = datetime.now()
    
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
        logger.error("No servers found in hosts file or file not found")
        return
    
    logger.info(f"Found {len(servers)} servers to process")
    
    # Store all server info objects
    discovered_servers = []
    successful_discoveries = 0
    failed_discoveries = 0
    
    # Discovery phase
    logger.info("\n" + "=" * 40)
    logger.info("DISCOVERY PHASE")
    logger.info("=" * 40)
    
    for server_creds in servers:
        logger.info(f"\n--- Discovering {server_creds.host} ---")
        
        try:
            # Set up connection
            connect_kwargs = {}
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
                
                discovered_servers.append(server_info)
                
                if server_info.discovery_successful:
                    successful_discoveries += 1
                    logger.info(f"✓ Discovery successful for {server_creds.host}")
                else:
                    failed_discoveries += 1
                    logger.error(f"✗ Discovery failed for {server_creds.host}")
                    
        except Exception as e:
            failed_discoveries += 1
            logger.error(f"✗ Discovery failed for {server_creds.host}: {e}")
            # Create a minimal server info object to track the failure
            server_info = ServerInfo(hostname=server_creds.host, credentials=server_creds)
            server_info.discovery_successful = False
            server_info.discovery_errors.append(str(e))
            discovered_servers.append(server_info)
    
    # Summary of discovery phase
    logger.info("\n" + "=" * 40)
    logger.info("DISCOVERY PHASE SUMMARY")
    logger.info("=" * 40)
    logger.info(f"Total servers: {len(servers)}")
    logger.info(f"Successful discoveries: {successful_discoveries}")
    logger.info(f"Failed discoveries: {failed_discoveries}")
    
    # Print detailed summary for each server
    for server in discovered_servers:
        if server.discovery_successful:
            logger.info(f"\n{server.hostname}:")
            logger.info(f"  OS: {server.os.distro} {server.os.version}")
            logger.info(f"  Users: {server.regular_usernames}")
            logger.info(f"  Services: {len(server.services)} running")
            logger.info(f"  Security tools: {[k for k, v in server.security_tools.items() if v]}")
        else:
            logger.error(f"\n{server.hostname}: DISCOVERY FAILED")
            for error in server.discovery_errors:
                logger.error(f"  Error: {error}")
    
    # End time and summary
    end_time = datetime.now()
    duration = end_time - start_time
    
    logger.info("\n" + "=" * 60)
    logger.info("CCDC AUTOMATED HARDENING PIPELINE COMPLETED")
    logger.info("=" * 60)
    logger.info(f"Total time: {duration}")
    if len(servers) > 0:
        logger.info(f"Discovery success rate: {successful_discoveries}/{len(servers)} ({(successful_discoveries/len(servers)*100):.1f}%)")
    
    # Optional: Deploy hardening if requested
    if len(servers) > 0 and successful_discoveries > 0:
        logger.info(f"\nDiscovery complete. Use 'fab harden-deploy' to apply hardening configurations.")
    
    return discovered_servers


@task
def harden_deploy(c, hosts_file='hosts.txt', dry_run=False, modules=None, 
                 script_categories=None, priority_only=False):
    """Deploy hardening configurations to discovered hosts"""
    logger.info("=" * 60)
    logger.info("CCDC HARDENING DEPLOYMENT STARTING")
    logger.info("=" * 60)
    
    if dry_run:
        logger.info("DRY RUN MODE - No changes will be made")
    
    start_time = datetime.now()
    
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
    
    # Parse modules if provided
    if modules:
        modules = [m.strip() for m in modules.split(',')]
        logger.info(f"Applying modules: {modules}")
    
    # Parse script categories if provided
    if script_categories:
        script_categories = [c.strip() for c in script_categories.split(',')]
        logger.info(f"Script categories: {script_categories}")
    
    if priority_only:
        logger.info("Priority scripts only: enabled")
    
    logger.info(f"Found {len(servers)} servers to harden")
    
    successful_hardenings = 0
    failed_hardenings = 0
    
    # Hardening phase
    logger.info("\n" + "=" * 40)
    logger.info("HARDENING PHASE")
    logger.info("=" * 40)
    
    for server_creds in servers:
        logger.info(f"\n--- Hardening {server_creds.host} ---")
        
        try:
            # Set up connection
            connect_kwargs = {}
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
                    failed_hardenings += 1
                    continue
                
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
                
                successful_hardenings += 1
                    
        except Exception as e:
            failed_hardenings += 1
            logger.error(f"✗ Hardening failed for {server_creds.host}: {e}")
    
    # End summary
    end_time = datetime.now()
    duration = end_time - start_time
    
    logger.info("\n" + "=" * 60)
    logger.info("CCDC HARDENING DEPLOYMENT COMPLETED")
    logger.info("=" * 60)
    logger.info(f"Total time: {duration}")
    if len(servers) > 0:
        logger.info(f"Hardening success rate: {successful_hardenings}/{len(servers)} ({(successful_hardenings/len(servers)*100):.1f}%)")
    
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
    
    return harden_deploy(c, hosts_file=hosts_file, dry_run=dry_run, 
                        modules='bash_scripts', script_categories=script_categories, 
                        priority_only=priority_only)


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
def test_module(c, module, host_index=0, live=False):
    """Test individual hardening module"""
    from test_modules import ModuleTester
    
    try:
        tester = ModuleTester(CONFIG)
        dry_run = not live
        success = tester.test_module(module, host_index, dry_run)
        return success
    except Exception as e:
        logger.error(f"Module test failed: {e}")
        return False


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