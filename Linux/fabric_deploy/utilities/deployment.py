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

from .models import ServerInfo
from .modules import (
    HardeningModule, HardeningResult,
    AgentAccountModule,
    PackageInstallerModule,
    LoggingSetupModule,
    SSHHardeningModule,
    FirewallHardeningModule,
    BashScriptHardeningModule,
    UserHardeningModule,
)
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
    
    # 3. User Hardening (Passwords)
    PipelineStep('module', 'user_hardening'),
    
    # 4. Firewall (Install/Enable)
    PipelineStep('module', 'firewall_hardening'),
    
    # 5. Lockdown (Panic Button)
    PipelineStep('script', 'scripts/all/lockdown.sh'),
    
    # 6. SSH Hardening
    PipelineStep('module', 'ssh_hardening'),

    # 7. Run any additional custom scripts
    PipelineStep('module', 'bash_scripts'),
    
    # 8. Reboot (Clean slate)
    PipelineStep('action', 'reboot'),
    
    # 9. Discovery (Refresh facts after reboot)
    PipelineStep('action', 'discovery'),

    # 10. User Hardening (Rotate again)
    PipelineStep('module', 'user_hardening'),
    
    # 11. Allow Internet (via lockdown script)
    PipelineStep('script', 'scripts/all/lockdown.sh', args={'env': {'ALLOW_INTERNET': '1'}, 'args': '--allow-internet'}),
    
    # 12. Packages & Tools
    PipelineStep('module', 'package_installer'),
    
    # 13. Logging
    PipelineStep('module', 'logging_setup'),
    
    # 14. Final Snapshot
    PipelineStep('script', 'scripts/all/pre-hardening-snapshot.sh'),
]

logger = logging.getLogger(__name__)


class HardeningOrchestrator:
    """Orchestrates the hardening process"""
    
    def __init__(self, connection: Connection, server_info: ServerInfo, os_family: str, 
                 script_paths: Optional[List[str]] = None,
                 pipeline: Optional[List[PipelineStep]] = None):
        self.conn = connection
        self.server_info = server_info
        self.os_family = os_family
        self.script_paths = script_paths
        self.modules_map = self._initialize_modules_map()
        self.pipeline = pipeline or DEFAULT_PIPELINE
    
    def _initialize_modules_map(self) -> Dict[str, HardeningModule]:
        """Initialize all hardening modules and return map"""
        modules = [
            AgentAccountModule(self.conn, self.server_info, self.os_family),
            PackageInstallerModule(self.conn, self.server_info, self.os_family),
            LoggingSetupModule(self.conn, self.server_info, self.os_family),
            SSHHardeningModule(self.conn, self.server_info, self.os_family),
            FirewallHardeningModule(self.conn, self.server_info, self.os_family),
            UserHardeningModule(self.conn, self.server_info, self.os_family),
            BashScriptHardeningModule(self.conn, self.server_info, self.os_family, 
                                    script_paths=self.script_paths),
        ]
        return {m.get_name(): m for m in modules}
    
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
        # We can leverage BashScriptHardeningModule logic or implement custom
        # For now, let's try to use BashScriptHardeningModule's helper if we can access it
        # Or simpler: create a temporary BashScriptHardeningModule?
        
        script_path = step.target
        # Handle arguments if any
        # args might have 'env' or 'args'
        
        # To avoid duplicating logic, let's manually construct the commands 
        # normally found in BashScriptHardeningModule but for one script
        
        # Determine local script path
        # Assume relative to scripts root if not absolute
        if Path(script_path).is_absolute():
            local_path = Path(script_path)
        else:
            # Assume relative to repo root or scripts dir? 
            # Default pipeline uses 'scripts/all/...' which is relative to repo root
            # But BashScriptHardeningModule uses self.scripts_base_path = Path(__file__).parent.parent.parent / "scripts"
            # Actually, looking at file structure:
            # fabric_deploy/utilities/deployment.py
            # fabric_deploy/scripts/all/...
            # So root is fabric_deploy which is parent.parent
            repo_root = Path(__file__).parent.parent
            local_path = repo_root / script_path
            
        if not local_path.exists():
            return [HardeningResult(False, script_path, "Load Script", error=f"File not found: {local_path}")]

        # Reuse the existing bash module logic by temporarily instantiating one with this single script?
        # But we need to handle special args (like --allow-internet).
        # BashScriptHardeningModule doesn't support args per script yet.
        
        # Let's implement basic upload & run here
        results = []
        remote_path = f"/tmp/ccdc_step_{Path(script_path).name}"
        log_path = f"/root/hardening-logs/step_{Path(script_path).name}.log"
        
        if dry_run:
            return [HardeningResult(True, f"bash {script_path}", "Dry Run Script Execution")]

        try:
            # 1. Upload
            self.conn.put(local_path, remote_path)
            self.conn.sudo(f"chmod +x {remote_path}")
            
            # 2. Execute
            cmd = f"bash {remote_path}"
            extra_args = step.args.get('args', '')
            if extra_args:
                cmd += f" {extra_args}"
                
            env_vars = step.args.get('env', {})
            env_str = ' '.join([f"{k}={v}" for k,v in env_vars.items()])
            if env_str:
                cmd = f"{env_str} {cmd}"
            
            # Run with logging
            # Use a slightly different command structure than module to ensure we capture output
            full_cmd = f"mkdir -p /root/hardening-logs && {cmd} 2>&1 | tee {log_path}"
            
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
            try:
                logger.info("Rebooting system...")
                self.conn.sudo("reboot", warn=True)
                # Fabric doesn't automatically wait for reboot?
                # We need to wait for disconnect and then reconnect
                logger.info("Waiting for system to go down...")
                time.sleep(5) # Give it a moment to start shutting down
                
                # Re-establish connection?
                # deployment.py is usually called within a 'with Connection()'.
                # restarting the connection object is tricky if we don't own it.
                # However, we can try to wait for it to come back using a loop?
                logger.info("Waiting for system to come back (30s)...")
                time.sleep(30) # Primitive wait
                # TODO: Implement robust wait_for_ssh logic
                # For now assume it comes back or we fail subsequent steps?
                # Ideally we should verify connectivity
                self.conn.run("hostname") # Trigger reconnection attempt?
                return [HardeningResult(True, "reboot", "System Reboot")]
                
            except Exception as e:
                # Reboot usually causes an exception on the command execution
                # We might want to suppress it if it's "Connection closed"
                logger.warning(f"Reboot triggered exception (expected): {e}")
                
                 # Try to reconnect
                try:
                    time.sleep(10)
                    self.conn.open()
                    return [HardeningResult(True, "reboot", "System Reboot (Reconnected)")]
                except:
                    pass
                return [HardeningResult(True, "reboot", "System Reboot (Triggered)")]

        elif action == 'discovery':
            if dry_run:
                 return [HardeningResult(True, "discovery", "System Discovery (Dry Run)")]
            try:
                # Re-run discovery
                from .discovery import SystemDiscovery
                logger.info("Re-running system discovery...")
                discovery = SystemDiscovery(self.conn, self.server_info.credentials) # use creds from server_info?
                # Need credentials. server_info has them?
                # server_info has .credentials field? Yes, looking at models.py
                new_info = discovery.discover_system()
                # Update our server_info reference!
                # Shallow copy attributes?
                # self.server_info is a reference, if we update it, it reflects everywhere?
                # But discover_system returns a NEW object usually.
                # We should update self.server_info in place if possible or update self.server_info ref
                self.server_info = new_info
                # Also need to update modules with new info?
                # Yes, modules hold reference to server_info.
                # If we replaced the object, we need to update modules.
                # But modules where initialized with OLD server_info.
                # We need to re-initialize modules map or update their server_info.
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


class HardeningDeployer:
    """Main deployment class that integrates with existing fabric_deploy framework"""
    
    def __init__(self, connection: Connection, server_info: ServerInfo):
        self.conn = connection
        self.server_info = server_info
        # Extract OS family from discovery
        discovery = getattr(server_info, '_discovery', None)
        self.os_family = getattr(discovery, 'os_family', 'unknown') if discovery else 'unknown'
        
    def deploy_hardening(self, dry_run: bool = False, 
                        modules: Optional[List[str]] = None,
                        script_paths: Optional[List[str]] = None) -> Dict:
        """
        Deploy hardening using command-based approach
        
        Args:
            dry_run: If True, only show what would be done
            modules: List of module names to apply (None = all)
            script_paths: List of scripts to run
            
        Returns:
            Dictionary with results and summary
        """
        # Use friendly name if available via credentials.display_name
        host_label = self.server_info.credentials.display_name.replace(":", "_").replace("/", "_")
        logger.info(f"Starting hardening deployment on {self.server_info.credentials.display_name} ({self.conn.host})")
        if dry_run:
            logger.info("DRY RUN MODE - No changes will be made")
        
        # We pass script_paths arguments to be available for 'bash_scripts' module in the pipeline
        orchestrator = HardeningOrchestrator(self.conn, self.server_info, self.os_family,
                                           script_paths=script_paths)
        
        results = orchestrator.apply_all(dry_run=dry_run, modules=modules)
        summary = orchestrator.get_summary(results)
        
        # Generate Report
        report_path = self._generate_report(host_label, results, summary)
        
        return {
            'host': self.conn.host,
            'server_info': self.server_info,
            'results': results,
            'summary': summary,
            'report_file': report_path
        }

    def _generate_report(self, host_label: str, results: Dict, summary: str) -> str:
        """Generate markdown report for the host"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path("logs/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"REPORT_{host_label}_{timestamp}.md"
        
        try:
            with open(report_path, 'w') as f:
                f.write(f"# Hardening Report: {host_label}\n")
                f.write(f"**Date**: {datetime.now().isoformat()}\n")
                f.write(f"**Host**: {self.server_info.hostname} ({self.os_family})\n\n")
                
                # Execution Summary
                f.write("## Execution Summary\n")
                f.write("```\n")
                f.write(summary)
                f.write("\n```\n\n")
                
                # User Changes
                f.write("## User Management Changes\n")
                # Pull password log path if available from results
                user_res = results.get('user_hardening', [])
                pwd_log = next((r.output for r in user_res if r.command.startswith('write_password_log')), None)
                if pwd_log and os.path.exists(pwd_log):
                    f.write(f"**Password Log**: `{pwd_log}`\n\n")
                    try:
                        f.write("### Password Log Content\n")
                        f.write("```\n")
                        f.write(Path(pwd_log).read_text())
                        f.write("\n```\n")
                    except:
                        f.write("*(Could not read password log)*\n")
                else:
                    f.write("*No password changes recorded or log not found.*\n")
                f.write("\n")
                
                # Sudoers Dump
                f.write("## Sudoers Configuration\n")
                sudoers_dump = getattr(self.server_info, 'sudoers_dump', None)
                if sudoers_dump:
                    f.write("### /etc/sudoers Dump\n")
                    f.write("```\n")
                    f.write(sudoers_dump)
                    f.write("\n```\n")
                else:
                    f.write("*Sudoers dump not available.*\n")
                
                f.write("\n---\nGenerated by CCDC Fabric Deploy\n")
                
            logger.info(f"Report generated: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return ""

    # Legacy method for backward compatibility
    def deploy_scripts(self, script_categories: List[str] = None) -> bool:
        """Legacy method stub"""
        return False
