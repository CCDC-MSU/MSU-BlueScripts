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
    KernelHardeningModule, 
    FirewallHardeningModule,
    BashScriptHardeningModule,
    UserHardeningModule,
)

logger = logging.getLogger(__name__)


class HardeningOrchestrator:
    """Orchestrates the hardening process"""
    
    def __init__(self, connection: Connection, server_info: ServerInfo, os_family: str, 
                 script_paths: Optional[List[str]] = None):
        self.conn = connection
        self.server_info = server_info
        self.os_family = os_family
        self.script_paths = script_paths
        self.modules = self._initialize_modules()
    
    def _initialize_modules(self) -> List[HardeningModule]:
        """Initialize all hardening modules"""
        return [
            AgentAccountModule(self.conn, self.server_info, self.os_family),
            PackageInstallerModule(self.conn, self.server_info, self.os_family),
            LoggingSetupModule(self.conn, self.server_info, self.os_family),
            SSHHardeningModule(self.conn, self.server_info, self.os_family),
            KernelHardeningModule(self.conn, self.server_info, self.os_family),
            FirewallHardeningModule(self.conn, self.server_info, self.os_family),
            UserHardeningModule(self.conn, self.server_info, self.os_family),
            BashScriptHardeningModule(self.conn, self.server_info, self.os_family, 
                                    script_paths=self.script_paths),
        ]
    
    def get_applicable_modules(self) -> List[HardeningModule]:
        """Get list of applicable modules for this system"""
        return [m for m in self.modules if m.is_applicable()]
    
    def apply_module(self, module_name: str, dry_run: bool = False) -> List[HardeningResult]:
        """Apply a specific hardening module"""
        for module in self.modules:
            if module.get_name() == module_name:
                return module.apply_all(dry_run=dry_run)
        raise ValueError(f"Module {module_name} not found")
    
    def apply_all(self, dry_run: bool = False, 
                  modules: Optional[List[str]] = None) -> Dict[str, List[HardeningResult]]:
        """
        Apply all or selected hardening modules
        
        Args:
            dry_run: If True, only show what would be done
            modules: List of module names to apply (None = all applicable)
            
        Returns:
            Dictionary mapping module names to their results
        """
        results = {}
        applicable_modules = self.get_applicable_modules()
        
        # Filter modules if specific ones requested
        if modules:
            applicable_modules = [m for m in applicable_modules if m.get_name() in modules]
        
        for module in applicable_modules:
            logger.info(f"\nApplying module: {module.get_name()}")
            results[module.get_name()] = module.apply_all(dry_run=dry_run)
        
        return results
    
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
        
        # Create orchestrator (using refactored BashScriptHardeningModule)
        # We pass script_paths directly to the Bash module via constructor args hack or we update Orchestrator
        # Let's update Orchestrator first
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
