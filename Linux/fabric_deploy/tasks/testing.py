from fabric import task
import logging
from tasks.hardening import harden
from .common import _get_console_logger

logger = logging.getLogger(__name__)

@task
def setup_test_env(c, hosts_file='hosts.txt', dry_run=False):
    """
    Inject vulnerabilities and misconfigurations into the environment.
    Runs 'vulnerability_injector' module and 'inject_vulnerabilities.sh' script.
    """
    console_logger = _get_console_logger()
    console_logger.info("=" * 60)
    console_logger.info("SETTING UP TEST ENVIRONMENT (INJECTING VULNERABILITIES)")
    console_logger.info("WARNING: THIS WILL COMPROMISE THE TARGET SYSTEMS")
    console_logger.info("=" * 60)
        
    return harden(c, 
                  hosts_file=hosts_file, 
                  dry_run=dry_run, 
                  modules='vulnerability_injector', 
                  scripts='all/inject_vulnerabilities.sh')
