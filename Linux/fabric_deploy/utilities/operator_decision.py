"""
Operator Decision System for Hardening Pipeline

Allows the operator to make decisions during parallel hardening execution
when automated processes encounter issues requiring human judgment.
"""

import logging
import time
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Decision files directory
DECISIONS_DIR = Path(__file__).parent.parent / "decisions"


@dataclass
class OperatorDecision:
    """Represents an operator decision request"""
    host: str
    module: str
    issue: str
    options: Dict[str, str]
    decision: Optional[str] = None
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            'host': self.host,
            'module': self.module,
            'issue': self.issue,
            'options': self.options,
            'decision': self.decision,
            'timestamp': self.timestamp
        }


class OperatorDecisionManager:
    """Manages operator decision requests during hardening"""

    def __init__(self, host: str, module: str):
        self.host = host
        self.module = module
        self.decisions_dir = DECISIONS_DIR
        self.decisions_dir.mkdir(parents=True, exist_ok=True)

    def _get_decision_file_path(self) -> Path:
        """Get the path for this host's decision file"""
        safe_host = self.host.replace('.', '_').replace(':', '_')
        return self.decisions_dir / f"{safe_host}_{self.module}.decision"

    def _create_decision_file(self, issue: str, options: Dict[str, str]) -> Path:
        """Create a decision file for the operator"""
        decision_file = self._get_decision_file_path()

        decision = OperatorDecision(
            host=self.host,
            module=self.module,
            issue=issue,
            options=options,
            decision="PENDING",
            timestamp=datetime.now().isoformat()
        )

        # Create human-readable decision file
        content = f"""{'=' * 80}
OPERATOR DECISION REQUIRED
{'=' * 80}

Host:    {self.host}
Module:  {self.module}
Issue:   {issue}
Time:    {decision.timestamp}

{'=' * 80}
OPTIONS
{'=' * 80}

"""
        for key, description in options.items():
            content += f"{key}. {description}\n"

        content += f"""
{'=' * 80}
INSTRUCTIONS
{'=' * 80}

1. Review the issue and options above
2. Edit the 'decision' line below with your choice ({', '.join(options.keys())})
3. Save the file
4. The hardening process will automatically continue

{'=' * 80}
YOUR DECISION (Edit the value below)
{'=' * 80}

decision: PENDING

"""

        # Write the decision file
        with open(decision_file, 'w') as f:
            f.write(content)

        # Also write JSON for programmatic access
        json_file = decision_file.with_suffix('.json')
        with open(json_file, 'w') as f:
            json.dump(decision.to_dict(), f, indent=2)

        return decision_file

    def _read_decision(self, decision_file: Path) -> Optional[str]:
        """Read the operator's decision from the file"""
        try:
            with open(decision_file, 'r') as f:
                content = f.read()

            # Parse the decision line
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('decision:'):
                    decision = line.split(':', 1)[1].strip()
                    if decision and decision != 'PENDING':
                        return decision

            return None
        except Exception as e:
            logger.error(f"Failed to read decision file: {e}")
            return None

    def _cleanup_decision_files(self):
        """Clean up decision files after use"""
        decision_file = self._get_decision_file_path()
        json_file = decision_file.with_suffix('.json')

        try:
            if decision_file.exists():
                decision_file.unlink()
            if json_file.exists():
                json_file.unlink()
        except Exception as e:
            logger.warning(f"Failed to cleanup decision files: {e}")

    def request_decision(self,
                        issue: str,
                        options: Dict[str, str],
                        timeout: int = 300,
                        poll_interval: int = 2) -> Optional[str]:
        """
        Request a decision from the operator.

        Args:
            issue: Description of the issue
            options: Dict of {choice_key: description}
            timeout: Maximum time to wait for decision (seconds)
            poll_interval: How often to check for decision (seconds)

        Returns:
            The operator's choice key, or None if timeout
        """
        decision_file = self._create_decision_file(issue, options)

        # Print prominent notification
        self._print_notification(decision_file, options)

        # Poll for decision
        start_time = time.time()
        while time.time() - start_time < timeout:
            decision = self._read_decision(decision_file)

            if decision and decision in options:
                logger.info(f"Operator decision received: {decision} - {options[decision]}")
                self._cleanup_decision_files()
                return decision
            elif decision:
                logger.warning(f"Invalid decision '{decision}', waiting for valid choice...")

            time.sleep(poll_interval)

        # Timeout
        logger.error(f"Decision timeout after {timeout}s for {self.host}")
        self._cleanup_decision_files()
        return None

    def _print_notification(self, decision_file: Path, options: Dict[str, str]):
        """Print a prominent notification to the console"""
        border = "!" * 80

        notification = f"""

{border}
{border}
!!!  OPERATOR DECISION REQUIRED - Host: {self.host}
{border}
{border}

Module: {self.module}
Decision File: {decision_file}

ACTION REQUIRED:
1. Open the decision file in an editor:

   nano {decision_file}

2. Review the issue and options
3. Edit the 'decision: PENDING' line with your choice
4. Save and exit - hardening will continue automatically

Available Options:
"""

        for key, description in options.items():
            notification += f"  {key}. {description}\n"

        notification += f"""
{border}
{border}

"""

        print(notification, flush=True)
        logger.warning(f"OPERATOR DECISION REQUIRED: {decision_file}")

    @staticmethod
    def get_pending_decisions() -> list:
        """Get list of all pending decision files"""
        if not DECISIONS_DIR.exists():
            return []

        return list(DECISIONS_DIR.glob("*.decision"))

    @staticmethod
    def cleanup_all_decisions():
        """Clean up all decision files"""
        if not DECISIONS_DIR.exists():
            return

        for file in DECISIONS_DIR.glob("*"):
            try:
                file.unlink()
            except Exception as e:
                logger.warning(f"Failed to delete {file}: {e}")
