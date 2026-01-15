"""
Operator Interaction Utilities
Handles user prompts and decisions during hardening operations
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Decision file location
DECISIONS_FILE = Path(__file__).parent.parent / "ansible" / "operator_decisions.json"


class OperatorDecision:
    """Represents an operator's decision for a host"""
    SKIP_USE_AUTO_DISCOVERY = "skip_auto_discovery"
    RETRY_AFTER_MANUAL_FIX = "retry"
    ABORT = "abort"


def save_decisions(decisions: Dict[str, str]):
    """Save operator decisions to file"""
    try:
        DECISIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "timestamp": datetime.now().isoformat(),
            "decisions": decisions
        }
        with open(DECISIONS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Operator decisions saved to {DECISIONS_FILE}")
    except Exception as e:
        logger.error(f"Failed to save operator decisions: {e}")


def load_decisions() -> Dict[str, str]:
    """Load operator decisions from file"""
    if DECISIONS_FILE.exists():
        try:
            with open(DECISIONS_FILE, 'r') as f:
                data = json.load(f)
                return data.get("decisions", {})
        except Exception as e:
            logger.warning(f"Failed to load operator decisions: {e}")
    return {}


def clear_decisions():
    """Clear operator decisions file"""
    if DECISIONS_FILE.exists():
        try:
            DECISIONS_FILE.unlink()
            logger.info("Operator decisions cleared")
        except Exception as e:
            logger.warning(f"Failed to clear operator decisions: {e}")


def get_decision_for_host(host_ip: str) -> Optional[str]:
    """Get operator decision for a specific host"""
    decisions = load_decisions()
    return decisions.get(host_ip)


def prompt_operator_for_failures(failures: List[Dict]) -> Dict[str, str]:
    """
    Present dependency failures to operator and collect decisions.

    Args:
        failures: List of failure dicts with keys: host, ip, missing_deps, hostname

    Returns:
        Dict mapping host IPs to decisions
    """
    print("\n" + "=" * 80)
    print("PYTHON BOOTSTRAP DEPENDENCY FAILURES DETECTED")
    print("=" * 80)
    print(f"\n{len(failures)} host(s) are missing required dependencies for Python 3.12 installation:\n")

    for i, failure in enumerate(failures, 1):
        print(f"{i}. {failure['hostname']} ({failure['ip']})")
        print(f"   Missing: {', '.join(failure['missing_deps'])}")
        print()

    print("=" * 80)
    print("OPTIONS:")
    print("=" * 80)
    print("For each host, you can:")
    print("  [F] Fix manually - Pause to let you install dependencies, then retry")
    print("  [S] Skip - Continue with Ansible auto-discovery (use system Python)")
    print("  [A] Abort - Stop the entire hardening process")
    print()

    decisions = {}

    # Check if we should use batch mode (all hosts same decision)
    if len(failures) > 1:
        print("Apply same decision to all hosts? [y/N]: ", end='', flush=True)
        batch_response = input().strip().lower()

        if batch_response == 'y':
            print("\nDecision for ALL hosts:")
            print("  [F] Fix manually and retry")
            print("  [S] Skip (use auto-discovery)")
            print("  [A] Abort hardening")
            print("\nYour choice [F/S/A]: ", end='', flush=True)

            while True:
                choice = input().strip().upper()
                if choice in ['F', 'S', 'A']:
                    break
                print("Invalid choice. Please enter F, S, or A: ", end='', flush=True)

            if choice == 'A':
                decision = OperatorDecision.ABORT
            elif choice == 'F':
                decision = OperatorDecision.RETRY_AFTER_MANUAL_FIX
            else:  # S
                decision = OperatorDecision.SKIP_USE_AUTO_DISCOVERY

            for failure in failures:
                decisions[failure['ip']] = decision

            return decisions

    # Individual decisions for each host
    print("\n" + "=" * 80)
    print("DECISIONS PER HOST")
    print("=" * 80 + "\n")

    for i, failure in enumerate(failures, 1):
        print(f"\n[{i}/{len(failures)}] {failure['hostname']} ({failure['ip']})")
        print(f"Missing: {', '.join(failure['missing_deps'])}")
        print("\nDecision for this host [F/S/A]: ", end='', flush=True)

        while True:
            choice = input().strip().upper()
            if choice in ['F', 'S', 'A']:
                break
            print("Invalid choice. Please enter F, S, or A: ", end='', flush=True)

        if choice == 'A':
            print("\n⚠  Aborting hardening process...")
            decisions[failure['ip']] = OperatorDecision.ABORT
            # Set abort for all remaining hosts too
            for remaining in failures[i:]:
                decisions[remaining['ip']] = OperatorDecision.ABORT
            break
        elif choice == 'F':
            decisions[failure['ip']] = OperatorDecision.RETRY_AFTER_MANUAL_FIX
        else:  # S
            decisions[failure['ip']] = OperatorDecision.SKIP_USE_AUTO_DISCOVERY

    return decisions


def wait_for_manual_fix(hosts_to_fix: List[Dict]):
    """
    Wait for operator to fix dependencies manually.

    Args:
        hosts_to_fix: List of host dicts that need manual fixes
    """
    print("\n" + "=" * 80)
    print("WAITING FOR MANUAL DEPENDENCY INSTALLATION")
    print("=" * 80)
    print(f"\nPlease install the missing dependencies on {len(hosts_to_fix)} host(s):\n")

    for host in hosts_to_fix:
        print(f"  {host['hostname']} ({host['ip']}) - Missing: {', '.join(host['missing_deps'])}")

        # Provide distro-specific commands
        if 'tar' in host['missing_deps']:
            print(f"    Install with:")
            print(f"      Fedora/RHEL: ssh root@{host['ip']} 'dnf install -y tar'")
            print(f"      Debian/Ubuntu: ssh root@{host['ip']} 'apt-get install -y tar'")
            print(f"      Alpine: ssh root@{host['ip']} 'apk add tar'")
        print()

    print("Once dependencies are installed, press ENTER to continue...", end='', flush=True)
    input()
    print("Continuing with dependency re-verification...\n")
