"""
Hardening deployment functionality for CCDC framework
Handles deployment of hardening configurations using modular approach
"""

import logging
from typing import Dict, List, Optional
from fabric import Connection

from .models import ServerInfo
from .modules import (
    HardeningModule, HardeningResult,
    AgentAccountModule,
    PackageInstallerModule,
    InstallationStatusModule,
    LoggingSetupModule,
    SSHHardeningModule,
    KernelHardeningModule, 
    FirewallHardeningModule,
    ServiceHardeningModule,
    FilePermissionsModule,
    BashScriptHardeningModule,
)

logger = logging.getLogger(__name__)


class HardeningOrchestrator:
    """Orchestrates the hardening process"""
    
    def __init__(self, connection: Connection, server_info: ServerInfo, os_family: str, 
                 script_categories: Optional[List[str]] = None, priority_only: bool = False):
        self.conn = connection
        self.server_info = server_info
        self.os_family = os_family
        self.script_categories = script_categories
        self.priority_only = priority_only
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
            ServiceHardeningModule(self.conn, self.server_info, self.os_family),
            FilePermissionsModule(self.conn, self.server_info, self.os_family),
            BashScriptHardeningModule(self.conn, self.server_info, self.os_family, 
                                    self.script_categories, self.priority_only),
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
                        script_categories: Optional[List[str]] = None,
                        priority_only: bool = False) -> Dict:
        """
        Deploy hardening using command-based approach
        
        Args:
            dry_run: If True, only show what would be done
            modules: List of module names to apply (None = all)
            script_categories: List of script categories to apply (for bash_scripts module)
            priority_only: If True, only apply priority scripts (for bash_scripts module)
            
        Returns:
            Dictionary with results and summary
        """
        logger.info(f"Starting hardening deployment on {self.conn.host}")
        if dry_run:
            logger.info("DRY RUN MODE - No changes will be made")
        
        # Create orchestrator and apply hardening
        orchestrator = HardeningOrchestrator(self.conn, self.server_info, self.os_family,
                                           script_categories, priority_only)
        
        results = orchestrator.apply_all(dry_run=dry_run, modules=modules)
        summary = orchestrator.get_summary(results)
        
        return {
            'host': self.conn.host,
            'server_info': self.server_info,
            'results': results,
            'summary': summary
        }
    
    # Legacy method for backward compatibility
    def deploy_scripts(self, script_categories: List[str] = None) -> bool:
        """Legacy method - now uses command-based hardening"""
        try:
            result = self.deploy_hardening(dry_run=False)
            return len(result['results']) > 0
        except Exception as e:
            logger.error(f"Hardening deployment failed: {e}")
            return False