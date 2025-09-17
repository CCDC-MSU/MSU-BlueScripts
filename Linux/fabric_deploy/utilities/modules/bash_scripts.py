"""
Bash script deployment module for CCDC framework
"""

import logging
from pathlib import Path
from typing import List, Optional
from .base import HardeningModule, HardeningCommand
from ..discovery import OSFamily
from ..utils import load_config

logger = logging.getLogger(__name__)


class BashScriptHardeningModule(HardeningModule):
    """Deploy and execute bash scripts based on OS type and categories"""
    
    def __init__(self, connection, server_info, os_family, 
                 script_categories: Optional[List[str]] = None, priority_only: bool = False):
        super().__init__(connection, server_info, os_family)
        self.script_categories = script_categories or []
        self.priority_only = priority_only
        self.config = load_config()
        self.scripts_base_path = Path(__file__).parent.parent.parent.parent / "repos"
        
    def get_name(self) -> str:
        return "bash_scripts"
    
    def is_applicable(self) -> bool:
        """Check if we have scripts configured for this system"""
        return len(self.get_script_paths()) > 0
    
    def get_commands(self) -> List[HardeningCommand]:
        """Generate commands to deploy and execute bash scripts"""
        commands = []
        script_paths = self.get_script_paths()
        
        if not script_paths:
            logger.info("No bash scripts configured for this system")
            return commands
        
        # Create remote staging directory
        commands.append(HardeningCommand(
            command="mkdir -p /tmp/ccdc_scripts && chmod 755 /tmp/ccdc_scripts",
            description="Create script staging directory",
            check_command="test -d /tmp/ccdc_scripts && echo exists",
            requires_sudo=True
        ))
        
        # Deploy and execute each script
        for script_rel_path in script_paths:
            script_path = self.scripts_base_path / script_rel_path
            
            if not script_path.exists():
                logger.warning(f"Script not found: {script_path}")
                continue
                
            script_name = script_path.name
            remote_path = f"/tmp/ccdc_scripts/{script_name}"
            
            # Upload script command
            commands.append(self._create_upload_command(script_path, remote_path))
            
            # Make executable
            commands.append(HardeningCommand(
                command=f"chmod +x {remote_path}",
                description=f"Make {script_name} executable",
                requires_sudo=True
            ))
            
            # Execute script
            commands.append(HardeningCommand(
                command=f"cd /tmp/ccdc_scripts && timeout 300 bash {remote_path}",
                description=f"Execute {script_name}",
                requires_sudo=True
            ))
        
        # Clean up staging directory
        commands.append(HardeningCommand(
            command="rm -rf /tmp/ccdc_scripts",
            description="Clean up script staging directory",
            requires_sudo=True
        ))
        
        return commands
    
    def get_script_paths(self) -> List[str]:
        """Get list of script paths based on OS family and categories"""
        script_paths = []
        
        # If specific categories requested, use those
        if self.script_categories:
            script_paths.extend(self._get_scripts_by_category())
        else:
            # Otherwise use OS-based deployment profiles
            script_paths.extend(self._get_scripts_by_os_profile())
        
        return list(set(script_paths))  # Remove duplicates
    
    def _get_scripts_by_category(self) -> List[str]:
        """Get scripts based on requested categories"""
        scripts = []
        script_categories = self.config.get('script_categories', {})
        
        for category in self.script_categories:
            if category in script_categories:
                scripts.extend(script_categories[category])
            else:
                logger.warning(f"Unknown script category: {category}")
        
        return scripts
    
    def _get_scripts_by_os_profile(self) -> List[str]:
        """Get scripts based on OS family deployment profile"""
        scripts = []
        deployment_profiles = self.config.get('deployment_profiles', {})
        
        # Map OS family to deployment profile
        os_profile = self._map_os_family_to_profile()
        
        if os_profile in deployment_profiles:
            profile = deployment_profiles[os_profile]
            
            # Always include priority scripts
            scripts.extend(profile.get('priority_scripts', []))
            
            # Include secondary scripts unless priority_only is set
            if not self.priority_only:
                scripts.extend(profile.get('secondary_scripts', []))
        else:
            logger.warning(f"No deployment profile found for OS family: {self.os_family}")
            # Fallback to generic profile
            if 'generic' in deployment_profiles:
                profile = deployment_profiles['generic']
                scripts.extend(profile.get('priority_scripts', []))
                if not self.priority_only:
                    scripts.extend(profile.get('secondary_scripts', []))
        
        return scripts
    
    def _map_os_family_to_profile(self) -> str:
        """Map detected OS family to deployment profile key"""
        try:
            os_family_enum = OSFamily(self.os_family)
            
            if os_family_enum in [OSFamily.DEBIAN]:
                return 'debian_ubuntu'
            elif os_family_enum in [OSFamily.REDHAT]:
                return 'centos_rhel'
            else:
                return 'generic'
        except ValueError:
            return 'generic'
    
    def _create_upload_command(self, local_path: Path, remote_path: str) -> HardeningCommand:
        """Create a command to upload a script file"""
        # Read the script content and create a command to write it remotely
        try:
            with open(local_path, 'r') as f:
                script_content = f.read()
            
            # Escape single quotes in the script content for safe transmission
            escaped_content = script_content.replace("'", "'\"'\"'")
            
            return HardeningCommand(
                command=f"cat > {remote_path} << 'CCDC_SCRIPT_EOF'\n{script_content}\nCCDC_SCRIPT_EOF",
                description=f"Upload {local_path.name}",
                check_command=f"test -f {remote_path} && echo exists",
                requires_sudo=True
            )
        except Exception as e:
            logger.error(f"Failed to read script {local_path}: {e}")
            return HardeningCommand(
                command=f"echo 'Failed to upload {local_path.name}: {e}' && false",
                description=f"Upload {local_path.name} (FAILED)",
                requires_sudo=True
            )