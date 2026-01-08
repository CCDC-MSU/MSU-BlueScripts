"""
Hardening deployment functionality for CCDC framework
Handles deployment of hardening configurations using modular approach
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from fabric import Connection


from .operator_decision import OperatorDecisionManager
class CriticalPipelineError(Exception):
    """Raised when a critical failure requires pipeline abort and manual intervention"""
    pass

from .models import ServerInfo
from .modules import (
    HardeningModule, HardeningResult,
    AgentAccountModule,
    PythonBootstrapModule,
    LoggingHardeningModule,
    SSHHardeningModule,
    FirewallHardeningModule,
    MODE_STRICT,
    MODE_ALLOW_INTERNET,
    ShellScriptHardeningModule,
    UserHardeningModule,
)
from .reporting import ReportGenerator
from dataclasses import dataclass, field
import time


@dataclass
class PipelineStep:
    type: str  # 'module', 'script', 'action'
    target: str  # Module name, script path, or action name
    args: Dict = field(default_factory=dict)  # Optional arguments

# Define the default hardening pipeline
DEFAULT_PIPELINE = [
    # 1. Snapshot
    PipelineStep('script', 'scripts/all/pre-hardening-snapshot.sh'),

    # 2. Discovery (Ensure we have fresh facts)
    PipelineStep('action', 'discovery'),

    # 3. Archive SSH keys (before user_hardening adds root key)
    PipelineStep('script', 'scripts/all/archive_ssh_keys.sh'),

    # 4. User Hardening (Passwords and root key setup)
    PipelineStep('module', 'user_hardening'),

    # 5. Firewall (Strict Mode - Trusted IPs only)
    PipelineStep('module', 'firewall_hardening'),

    # 6. SSH Hardening
    PipelineStep('module', 'ssh_hardening'),

    # 7. Run any additional custom scripts
    PipelineStep('module', 'shell_scripts'),

    # 8. Reboot (Clean slate)
    PipelineStep('action', 'reboot'),

    # 9. Discovery (Refresh facts after reboot)
    PipelineStep('action', 'discovery'),

    # 10. User Hardening (Rotate again)
    PipelineStep('module', 'user_hardening'),

    # 11. Firewall (Allow Internet Mode - for package updates)
    PipelineStep('module', 'firewall_hardening_allow_internet'),

    # 12. Packages & Tools (DISABLED)
    # PipelineStep('module', 'package_installer'),

    # 13. Python Bootstrap (Install Python 3.12 for Ansible)
    PipelineStep('module', 'python_bootstrap'),

    # 14. Logging
    PipelineStep('module', 'logging_hardening'),

    # 15. Final Lockdown (Return to Strict Mode)
    PipelineStep('module', 'firewall_hardening'),

    # 16. Final Snapshot
    PipelineStep('script', 'scripts/all/pre-hardening-snapshot.sh'),
]

logger = logging.getLogger(__name__)


class HardeningOrchestrator:
    """Orchestrates the hardening process and deploys configurations"""

    def __init__(self, connection: Connection, server_info: ServerInfo,
                 script_paths: Optional[List[str]] = None,
                 pipeline: Optional[List[PipelineStep]] = None,
                 firewall_mode: str = MODE_STRICT):
        self.conn = connection
        self.server_info = server_info
        # Extract OS family from discovery
        discovery = getattr(server_info, '_discovery', None)
        self.os_family = getattr(discovery, 'os_family', 'unknown') if discovery else 'unknown'
        self.script_paths = script_paths
        self.firewall_mode = firewall_mode
        self.modules_map = self._initialize_modules_map()
        self.pipeline = pipeline or DEFAULT_PIPELINE
    
    def _initialize_modules_map(self) -> Dict[str, HardeningModule]:
        """Initialize all hardening modules and return map"""
        modules = [
            AgentAccountModule(self.conn, self.server_info, self.os_family),
            # PackageInstallerModule(self.conn, self.server_info, self.os_family),
            PythonBootstrapModule(self.conn, self.server_info, self.os_family),
            LoggingHardeningModule(self.conn, self.server_info, self.os_family),
            SSHHardeningModule(self.conn, self.server_info, self.os_family),
            # Strict mode firewall (default)
            FirewallHardeningModule(self.conn, self.server_info, self.os_family, mode=MODE_STRICT),
            UserHardeningModule(self.conn, self.server_info, self.os_family),
            ShellScriptHardeningModule(self.conn, self.server_info, self.os_family,
                                    script_paths=self.script_paths),
        ]
        modules_map = {m.get_name(): m for m in modules}
        
        # Add a second firewall instance for allow_internet mode with a distinct name
        firewall_allow_internet = FirewallHardeningModule(
            self.conn, self.server_info, self.os_family, mode=MODE_ALLOW_INTERNET
        )
        modules_map['firewall_hardening_allow_internet'] = firewall_allow_internet
        
        return modules_map
    
    def get_applicable_modules(self) -> List[HardeningModule]:
        """Get list of applicable modules for this system"""
        return [m for m in self.modules_map.values() if m.is_applicable()]
    
    def apply_module(self, module_name: str, dry_run: bool = False) -> List[HardeningResult]:
        """Apply a specific hardening module"""
        if module_name not in self.modules_map:
             raise ValueError(f"Module {module_name} not found")
        return self.modules_map[module_name].apply_all(dry_run=dry_run)
    
    def apply_all(self, dry_run: bool = False, 
                  modules: Optional[List[str]] = None) -> Dict[str, List[HardeningResult]]:
        """
        Apply all or selected hardening modules/steps
        
        Args:
            dry_run: If True, only show what would be done
            modules: List of module names to apply (None = use pipeline)
            
        Returns:
            Dictionary mapping step names to their results
        """
        results = {}
        
        # If specific modules requested, ignore pipeline and run them directly
        if modules:
            for mod_name in modules:
                if mod_name in self.modules_map:
                    logger.info(f"\nApplying module (selective): {mod_name}")
                    results[mod_name] = self.modules_map[mod_name].apply_all(dry_run=dry_run)
                else:
                    logger.warning(f"Module {mod_name} not found, skipping")
            return results
        
        # Otherwise execute pipeline
        for i, step in enumerate(self.pipeline):
            step_id = f"{i+1}_{step.type}_{Path(step.target).name}"
            logger.info(f"\n--- Pipeline Step {i+1}: {step.type.upper()} {step.target} ---")
            
            step_results = []
            try:
                if step.type == 'module':
                    step_results = self._execute_module_step(step, dry_run)
                    # Use module name as key to keep summary working nicely, or step_id?
                    # If we run same module twice, we need unique keys for results dict?
                    # The get_summary method iterates results.items().
                    # Let's append to existing results if key exists?
                    key = step.target
                    if key in results:
                        results[key].extend(step_results)
                    else:
                        results[key] = step_results
                        
                elif step.type == 'script':
                    step_results = self._execute_script_step(step, dry_run)
                    results[step_id] = step_results
                    
                elif step.type == 'action':
                    step_results = self._execute_action_step(step, dry_run)
                    results[step_id] = step_results
                    
            except Exception as e:
                logger.error(f"Step {step_id} failed: {e}")
                results[step_id] = [HardeningResult(
                    success=False,
                    command=step.target,
                    description=f"Pipeline step {step_id}",
                    error=str(e)
                )]
                
        return results

    def _execute_module_step(self, step: PipelineStep, dry_run: bool) -> List[HardeningResult]:
        if step.target not in self.modules_map:
            logger.warning(f"Module {step.target} not found")
            return []
        return self.modules_map[step.target].apply_all(dry_run=dry_run)

    def _execute_script_step(self, step: PipelineStep, dry_run: bool) -> List[HardeningResult]:
        """Execute a standalone script execution step"""

        script_path = step.target

        if Path(script_path).is_absolute():
            local_path = Path(script_path)
        else:
            repo_root = Path(__file__).parent.parent
            local_path = repo_root / script_path
            
        if not local_path.exists():
            return [HardeningResult(False, script_path, "Load Script", error=f"File not found: {local_path}")]
        
        # Let's implement basic upload & run here
        results = []
        remote_path = f"/tmp/ccdc_step_{Path(script_path).name}"
        log_path = f"/root/logs/hardening-scripts/step_{Path(script_path).name}.log"
        
        if dry_run:
            return [HardeningResult(True, f"bash {script_path}", "Dry Run Script Execution")]

        try:
            # 1. Upload
            self.conn.put(local_path, remote_path)
            self.conn.sudo(f"chmod +x {remote_path}")
            
            # 2. Execute
            # Use discovered shell or fallback to sh (for Alpine/others without bash)
            shell = getattr(self.server_info, 'default_shell', '/bin/sh') or '/bin/sh'
            cmd = f"{shell} {remote_path}"
            extra_args = step.args.get('args', '')
            if extra_args:
                cmd += f" {extra_args}"
                
            env_vars = step.args.get('env', {})
            env_str = ' '.join([f"{k}={v}" for k,v in env_vars.items()])
            if env_str:
                cmd = f"{env_str} {cmd}"
            
            full_cmd = f"mkdir -p /root/logs/hardening-scripts && {cmd} 2>&1 | tee {log_path}"
            
            logger.info(f"Running script: {full_cmd}")
            res = self.conn.sudo(full_cmd, warn=True, timeout=300)
            
            results.append(HardeningResult(
                success=res.ok,
                command=cmd,
                description=f"Run script {Path(script_path).name}",
                output=res.stdout,
                error=res.stderr if not res.ok else None
            ))
            
            # Cleanup
            self.conn.sudo(f"rm -f {remote_path}")
            
        except Exception as e:
            results.append(HardeningResult(False, script_path, "Execute Script", error=str(e)))
            
        return results

    def _execute_action_step(self, step: PipelineStep, dry_run: bool) -> List[HardeningResult]:
        action = step.target
        if action == 'reboot':
            if dry_run:
                 return [HardeningResult(True, "reboot", "System Reboot (Dry Run)")]
            
            # Safety Check
            if not getattr(self.server_info, 'safe_to_reboot', False):
                logger.error("Skipping reboot: Safe-to-reboot signal was not received (SSH hardening may have failed or not completed)")
                return [HardeningResult(False, "reboot", "Safeguard: Reboot Skipped", error="safe_to_reboot flag is False")]

            # Manual Verification Prompt
            decision_manager = OperatorDecisionManager(self.conn.host, "reboot_safety_check")
            options = {
                "reboot": "I have verified the system is safe (SSH/Firewall ok) - Proceed with reboot",
                "skip": "Skip reboot for now (I will reboot manually later)"
            }

            decision = decision_manager.request_decision(
                issue="System is ready for reboot. Please verify you still have access before proceeding.",
                options=options,
                timeout=600  # Give them 10 minutes to verify
            )

            if decision == "skip":
                 logger.warning("Operator chose to skip reboot.")
                 return [HardeningResult(False, "reboot", "Operator Skipped Reboot", error="Operator decision: skip")]
            elif decision is None:
                 logger.error("Reboot decision timed out.")
                 return [HardeningResult(False, "reboot", "Reboot Decision Timeout", error="Operator decision timeout")]

            # If we get here, decision is 'reboot'
            try:
                logger.info("Rebooting system...")
                self.conn.sudo("reboot", warn=True)

                logger.info("Waiting for system to go down...")
                time.sleep(5) 
                
                logger.info("Waiting for system to come back (max 300s)...")
                # Close the old connection explicitly
                try:
                    self.conn.close()
                except:
                    pass

                # Poll for reconnection with a fresh connection (host key may change)
                from fabric import Connection, Config
                import subprocess

                creds = self.server_info.credentials

                # Clear known_hosts entry to avoid mismatch errors if keys regenerated
                try:
                    subprocess.run(["ssh-keygen", "-R", creds.host], capture_output=True)
                    # Also try IP if host is different
                    if creds.host != self.conn.host:
                         subprocess.run(["ssh-keygen", "-R", self.conn.host], capture_output=True)
                except Exception as e:
                    logger.warning(f"Failed to clear known_hosts: {e}")

                deadline = time.time() + 300  # 5 minutes timeout
                reconnected = False
                
                # Build fresh connection kwargs with host key checking disabled
                fresh_connect_kwargs = {
                    'allow_agent': False,
                    'look_for_keys': False,
                    'timeout': 15,
                }
                # Disable strict host key checking for reconnection after reboot
                # Host keys may regenerate on some systems
                import paramiko
                fresh_connect_kwargs['disabled_algorithms'] = {}
                
                # Use known SSH key
                key_path = creds.key_file if creds.key_file else str(Path(__file__).parent.parent / "keys" / "test-root-key.private")
                fresh_connect_kwargs['key_filename'] = key_path
                
                # Ensure we don't load system known_hosts, which would cause "Host key mismatch" errors
                # if the key changed (not just missing)
                fresh_config = Config(overrides={'load_ssh_configs': False, 'load_system_host_keys': False})
                
                while time.time() < deadline:
                    try:
                        # Create fresh connection each attempt to avoid cached host key
                        test_conn = Connection(
                            creds.host, 
                            user=creds.user, 
                            port=creds.port,
                            config=fresh_config,
                            connect_kwargs=fresh_connect_kwargs
                        )
                        # Override paramiko's host key policy
                        test_conn.client = paramiko.SSHClient()
                        test_conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        test_conn.open()
                        
                        # Verify it's actually responsive
                        test_conn.run("echo 'Reconnected'", hide=True, timeout=5)
                        
                        # Replace our connection with the fresh one
                        self.conn = test_conn
                        reconnected = True
                        logger.info("System is back online!")
                        break
                    except Exception as e:
                        logger.debug(f"Reconnection attempt failed: {e}")
                        time.sleep(5)
                
                if not reconnected:
                    logger.error("Timed out waiting for system to reboot.")
                    logger.error("CRITICAL: Host is unreachable after reboot - manual intervention required!")
                    logger.error(f"  Host: {creds.host}")
                    logger.error(f"  Possible causes:")
                    logger.error(f"    - Firewall rules locked out SSH")
                    logger.error(f"    - System failed to boot")
                    logger.error(f"    - Network configuration issue")
                    logger.error(f"  Manual recovery steps:")
                    logger.error(f"    1. Access via console/out-of-band management")
                    logger.error(f"    2. Check firewall: firewall-cmd --set-default-zone=trusted && firewall-cmd --reload")
                    logger.error(f"    3. Check SSH: systemctl status sshd")
                    # Raise exception to abort pipeline - this host needs manual fix
                    raise CriticalPipelineError(
                        f"Host {creds.host} unreachable after reboot - requires manual intervention"
                    )

                return [HardeningResult(True, "reboot", "System Reboot")]

            except CriticalPipelineError:
                raise  # Re-raise to abort pipeline
            except Exception as e:
                logger.warning(f"Reboot trigger or wait failed: {e}")
                return [HardeningResult(False, "reboot", "System Reboot", error=str(e))]

        elif action == 'discovery':
            if dry_run:
                 return [HardeningResult(True, "discovery", "System Discovery (Dry Run)")]
            try:
                # Re-run discovery
                from .discovery import SystemDiscovery
                logger.info("Re-running system discovery...")
                discovery = SystemDiscovery(self.conn, self.server_info.credentials) # use creds from server_info?
                new_info = discovery.discover_system()
                self.server_info = new_info
                for mod in self.modules_map.values():
                    mod.server_info = new_info
                
                return [HardeningResult(True, "discovery", "System Discovery (Refreshed)")]
            except Exception as e:
                return [HardeningResult(False, "discovery", "System Discovery", error=str(e))]
        
        return [HardeningResult(False, action, "Unknown Action")]

    def get_summary(self, results: Dict[str, List[HardeningResult]]) -> str:
        """Generate a summary of hardening results"""
        summary_lines = ["Hardening Summary", "=" * 50]
        
        for module_name, module_results in results.items():
            total = len(module_results)
            successful = sum(1 for r in module_results if r.success)
            already_applied = sum(1 for r in module_results if r.already_applied)
            failed = total - successful
            
            summary_lines.append(f"\n{module_name}:")
            summary_lines.append(f"  Total commands: {total}")
            summary_lines.append(f"  Successful: {successful}")
            summary_lines.append(f"  Already applied: {already_applied}")
            summary_lines.append(f"  Failed: {failed}")
            
            if failed > 0:
                summary_lines.append("  Failed commands:")
                for result in module_results:
                    if not result.success:
                        summary_lines.append(f"    - {result.description}: {result.error}")
        
        return "\n".join(summary_lines)

    def deploy(self, dry_run: bool = False,
               modules: Optional[List[str]] = None) -> Dict:
        """
        Deploy hardening and generate report.

        Args:
            dry_run: If True, only show what would be done
            modules: List of module names to apply (None = use pipeline)

        Returns:
            Dictionary with results and summary
        """
        host_label = self.server_info.credentials.display_name.replace(":", "_").replace("/", "_")
        logger.info(f"Starting hardening deployment on {self.server_info.credentials.display_name} ({self.conn.host})")
        if dry_run:
            logger.info("DRY RUN MODE - No changes will be made")
        
        # Connection Warmer: Run a dummy command to ensure connection is active
        # This prevents the first heavy operation from failing due to initial connection setup
        try:
            logger.info("Warming up connection...")
            self.conn.run("true", hide=True, timeout=10)
        except Exception as e:
            logger.warning(f"Connection warm-up failed (proceeding anyway): {e}")

        results = self.apply_all(dry_run=dry_run, modules=modules)
        summary = self.get_summary(results)

        report_path = self._generate_report(host_label, results, summary)

        return {
            'host': self.conn.host,
            'server_info': self.server_info,
            'results': results,
            'summary': summary,
            'report_file': report_path
        }

    def _generate_report(self, host_label: str, results: Dict, summary: str) -> str:
        """Generate markdown report for the host using ReportGenerator"""
        report_gen = ReportGenerator(self.server_info, self.os_family, self.modules_map)
        return report_gen.generate_report(host_label, results, summary)
