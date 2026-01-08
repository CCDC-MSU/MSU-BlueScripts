"""
Hardening deployment functionality for CCDC framework.
"""

import contextlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from fabric import Connection

from .logging_context import LogCaptureStream, log_context
from .models import ServerInfo
from .modules import (
    MODE_ALLOW_INTERNET,
    MODE_STRICT,
    C2DetectionModule,
    FirewallHardeningModule,
    HardeningModule,
    HardeningResult,
    LoggingHardeningModule,
    PythonBootstrapModule,
    ShellScriptHardeningModule,
    SSHHardeningModule,
    UserHardeningModule,
)
from .operator_decision import OperatorDecisionManager
from .reporting import ReportGenerator


class CriticalPipelineError(Exception):
    """Raised when a critical failure requires pipeline abort and manual intervention"""

    pass


@dataclass
class PipelineStep:
    type: str  # 'module', 'script', 'action'
    target: str  # Module name, script path, or action name
    args: dict = field(default_factory=dict)  # Optional arguments


# Define the default hardening pipeline
# Note: Discovery is NOT included at pipeline start because it already runs
# in hardening.py before the orchestrator is created. The only discovery step
# needed is after reboot to refresh system state.
DEFAULT_PIPELINE = [
    # 1. Snapshot
    PipelineStep("script", "scripts/all/pre-hardening-snapshot.sh"),
    # 2. Archive SSH keys (before user_hardening adds root key)
    PipelineStep("script", "scripts/all/archive_ssh_keys.sh"),
    # 3. User Hardening (Password changes and root key setup)
    PipelineStep("module", "user_hardening"),
    # 4. Firewall (Strict Mode - Trusted IPs only)
    # PipelineStep("module", "firewall_hardening"),
    # 5. SSH Hardening
    PipelineStep("module", "ssh_hardening"),
    # 6. Run any additional custom scripts
    PipelineStep("module", "shell_scripts"),
    # 7. Reboot (Clean slate)
    # PipelineStep("action", "reboot"),
    # 8. Discovery (Refresh facts after reboot)
    # PipelineStep("action", "discovery"),
    # 9. User Hardening (Rotate again)
    # PipelineStep("module", "user_hardening"),
    # 10. Firewall (Allow Internet Mode - for package updates)
    # PipelineStep("module", "firewall_hardening_allow_internet"),
    # 11. Packages & Tools (enable manually if needed)
    # PipelineStep('module', 'package_management'),
    # 12. Python Bootstrap (Install Python 3.12 for Ansible)
    PipelineStep("module", "python_bootstrap"),
    # 13. Logging
    PipelineStep("module", "logging_hardening"),
    # 14. C2 Detection (Deploy hawk + YARA, requires internet for yara package)
    PipelineStep("module", "c2_detection"),
    # 15. Final Snapshot
    PipelineStep("script", "scripts/all/pre-hardening-snapshot.sh"),
]

logger = logging.getLogger(__name__)


class HardeningOrchestrator:
    """Orchestrates the hardening process and deploys configurations"""

    def __init__(
        self,
        connection: Connection,
        server_info: ServerInfo,
        script_paths: list[str] | None = None,
        pipeline: list[PipelineStep] | None = None,
        firewall_mode: str = MODE_STRICT,
    ):
        self.conn = connection
        self.server_info = server_info
        # Extract OS family from discovery
        discovery = getattr(server_info, "_discovery", None)
        self.os_family = (
            getattr(discovery, "os_family", "unknown") if discovery else "unknown"
        )
        self.script_paths = script_paths
        self.firewall_mode = firewall_mode
        self.modules_map = self._initialize_modules_map()
        self.pipeline = pipeline or DEFAULT_PIPELINE

    def _initialize_modules_map(self) -> dict[str, HardeningModule]:
        """
        Initialize all hardening modules and return map.

        Note: PackageManagementModule is commented out due to timeout issues
        on slow networks. Re-enable by uncommenting if needed.
        """
        modules = [
            # PackageManagementModule(self.conn, self.server_info, self.os_family),
            PythonBootstrapModule(self.conn, self.server_info, self.os_family),
            LoggingHardeningModule(self.conn, self.server_info, self.os_family),
            SSHHardeningModule(self.conn, self.server_info, self.os_family),
            # Strict mode firewall (default)
            FirewallHardeningModule(
                self.conn, self.server_info, self.os_family, mode=MODE_STRICT
            ),
            UserHardeningModule(self.conn, self.server_info, self.os_family),
            ShellScriptHardeningModule(
                self.conn,
                self.server_info,
                self.os_family,
                script_paths=self.script_paths,
            ),
            C2DetectionModule(self.conn, self.server_info, self.os_family),
        ]
        modules_map = {m.get_name(): m for m in modules}

        # Add a second firewall instance for allow_internet mode with a distinct name
        firewall_allow_internet = FirewallHardeningModule(
            self.conn, self.server_info, self.os_family, mode=MODE_ALLOW_INTERNET
        )
        modules_map["firewall_hardening_allow_internet"] = firewall_allow_internet

        return modules_map

    def get_applicable_modules(self) -> list[HardeningModule]:
        """Get list of applicable modules for this system"""
        return [m for m in self.modules_map.values() if m.is_applicable()]

    def apply_module(
        self, module_name: str, dry_run: bool = False
    ) -> list[HardeningResult]:
        """Apply a specific hardening module"""
        if module_name not in self.modules_map:
            raise ValueError(f"Module {module_name} not found")
        return self.modules_map[module_name].apply_all(dry_run=dry_run)

    def apply_all(
        self,
        dry_run: bool = False,
        modules: list[str] | None = None,
        bypass_reboot_prompt: bool = False,
    ) -> dict[str, list[HardeningResult]]:
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
                    results[mod_name] = self.modules_map[mod_name].apply_all(
                        dry_run=dry_run
                    )
                else:
                    logger.warning(f"Module {mod_name} not found, skipping")
            return results

        # Otherwise execute pipeline
        for i, step in enumerate(self.pipeline):
            step_id = f"{i + 1}_{step.type}_{Path(step.target).name}"
            step_results = []
            if step.type == "module":
                step_label = step.target
            elif step.type == "script":
                step_label = f"script:{Path(step.target).name}"
            else:
                step_label = f"action:{step.target}"

            with log_context(module=step_label):
                logger.info(
                    f"\n--- Pipeline Step {i + 1}: {step.type.upper()} {step.target} ---"
                )
                try:
                    if step.type == "module":
                        # Module execution is simple - modules handle their own complexity
                        if step.target in self.modules_map:
                            step_results = self.modules_map[step.target].apply_all(
                                dry_run=dry_run
                            )
                        else:
                            logger.warning(f"Module {step.target} not found, skipping")
                            step_results = []

                        key = step.target
                        if key in results:
                            results[key].extend(step_results)
                        else:
                            results[key] = step_results

                    elif step.type == "script":
                        step_results = self._execute_script_step(step, dry_run)
                        results[step_id] = step_results

                    elif step.type == "action":
                        step_results = self._execute_action_step(
                            step, dry_run, bypass_reboot_prompt=bypass_reboot_prompt
                        )
                        results[step_id] = step_results

                except CriticalPipelineError:
                    # Re-raise critical errors to abort pipeline immediately
                    # These require manual intervention and should not continue
                    raise
                except Exception as e:
                    logger.error(f"Step {step_id} failed: {e}")
                    results[step_id] = [
                        HardeningResult(
                            success=False,
                            command=step.target,
                            description=f"Pipeline step {step_id}",
                            error=str(e),
                        )
                    ]

        return results

    def _execute_script_step(
        self, step: PipelineStep, dry_run: bool
    ) -> list[HardeningResult]:
        """Execute a standalone script execution step"""

        script_path = step.target

        if Path(script_path).is_absolute():
            local_path = Path(script_path)
        else:
            repo_root = Path(__file__).parent.parent
            local_path = repo_root / script_path

        if not local_path.exists():
            return [
                HardeningResult(
                    False,
                    script_path,
                    "Load Script",
                    error=f"File not found: {local_path}",
                )
            ]

        # Let's implement basic upload & run here
        results = []
        remote_path = f"/tmp/ccdc_step_{Path(script_path).name}"
        log_path = f"/root/logs/hardening-scripts/step_{Path(script_path).name}.log"

        if dry_run:
            return [
                HardeningResult(True, f"bash {script_path}", "Dry Run Script Execution")
            ]

        try:
            # 1. Upload
            self.conn.put(local_path, remote_path)
            self.conn.run(f"chmod +x {remote_path}")

            # 2. Execute
            # Use discovered shell or fallback to sh (for Alpine/others without bash)
            shell = getattr(self.server_info, "default_shell", "/bin/sh") or "/bin/sh"
            cmd = f"{shell} {remote_path}"
            extra_args = step.args.get("args", "")
            if extra_args:
                cmd += f" {extra_args}"

            env_vars = step.args.get("env", {})
            env_str = " ".join([f"{k}={v}" for k, v in env_vars.items()])
            if env_str:
                cmd = f"{env_str} {cmd}"

            full_cmd = (
                f"mkdir -p /root/logs/hardening-scripts && {cmd} 2>&1 | tee {log_path}"
            )

            logger.info(f"Running script: {full_cmd}")
            console_logger = logging.getLogger("console")
            mirror_logger = console_logger if console_logger.handlers else None
            out_stream = LogCaptureStream(
                logger,
                default_level=logging.DEBUG,
                mirror_logger=mirror_logger,
            )
            err_stream = LogCaptureStream(
                logger,
                default_level=logging.ERROR,
                mirror_logger=mirror_logger,
            )
            res = self.conn.run(
                full_cmd,
                warn=True,
                timeout=300,
                out_stream=out_stream,
                err_stream=err_stream,
            )
            out_stream.flush()
            err_stream.flush()

            results.append(
                HardeningResult(
                    success=res.ok,
                    command=cmd,
                    description=f"Run script {Path(script_path).name}",
                    output=res.stdout,
                    error=res.stderr if not res.ok else None,
                )
            )

            # Cleanup
            self.conn.run(f"rm -f {remote_path}")

        except Exception as e:
            results.append(
                HardeningResult(False, script_path, "Execute Script", error=str(e))
            )

        return results

    def _execute_action_step(
        self, step: PipelineStep, dry_run: bool, bypass_reboot_prompt: bool = False
    ) -> list[HardeningResult]:
        """
        Execute a pipeline action step (reboot, discovery, etc.).

        Actions are special pipeline steps that don't map to modules but perform
        orchestration tasks. Each action is handled by a dedicated method.
        """
        action = step.target
        match action:
            case "reboot":
                return self._handle_reboot(dry_run, bypass_reboot_prompt)
            case "discovery":
                return self._handle_discovery(dry_run)
            case _:
                return [HardeningResult(False, action, "Unknown Action")]

    # =========================================================================
    # Action Handlers
    # =========================================================================
    # These methods handle complex pipeline actions. They are intentionally
    # verbose because they contain critical safety logic that should not be
    # abstracted away. Each handler is self-contained and testable.
    # =========================================================================

    def _handle_reboot(
        self, dry_run: bool, bypass_prompt: bool = False
    ) -> list[HardeningResult]:
        """
        Handle system reboot with safety checks and reconnection.

        This method is intentionally long because it handles:
        1. Safety flag verification (safe_to_reboot)
        2. Operator confirmation prompt
        3. Connection teardown
        4. Host key management (keys may regenerate on reboot)
        5. Reconnection polling with timeout
        6. Critical failure handling

        Do NOT simplify this method - every step is safety-critical.
        """
        if dry_run:
            return [HardeningResult(True, "reboot", "System Reboot (Dry Run)")]

        # === SAFETY CHECK ===
        # The safe_to_reboot flag is set by SSH hardening after verifying
        # that the fallback root key is installed. Without this, we could
        # lock ourselves out after reboot.
        if not getattr(self.server_info, "safe_to_reboot", False):
            logger.error(
                "Skipping reboot: Safe-to-reboot signal was not received "
                "(SSH hardening may have failed or not completed)"
            )
            return [
                HardeningResult(
                    False,
                    "reboot",
                    "Safeguard: Reboot Skipped",
                    error="safe_to_reboot flag is False",
                )
            ]

        # === OPERATOR CONFIRMATION ===
        # Require human verification before rebooting. This prevents
        # accidental lockouts if something went wrong during hardening.
        if not bypass_prompt:
            skip_result = self._prompt_reboot_confirmation()
            if skip_result is not None:
                return skip_result  # Operator chose to skip or timeout

        # === EXECUTE REBOOT ===
        try:
            return self._execute_reboot_and_reconnect()
        except CriticalPipelineError:
            raise  # Re-raise to abort pipeline
        except Exception as e:
            logger.warning(f"Reboot trigger or wait failed: {e}")
            return [HardeningResult(False, "reboot", "System Reboot", error=str(e))]

    def _prompt_reboot_confirmation(self) -> list[HardeningResult] | None:
        """
        Prompt operator for reboot confirmation.

        Returns:
            None if operator approved, or list[HardeningResult] if skipped/timeout
        """
        decision_manager = OperatorDecisionManager(
            self.conn.host, "reboot_safety_check"
        )
        options = {
            "reboot": "I have verified the system is safe - Proceed with reboot",
            "skip": "Skip reboot for now (I will reboot manually later)",
        }

        checklist = """
VERIFICATION CHECKLIST:
[ ] SSH Access: Verify you can currently SSH into the box (try another terminal).
[ ] Firewall: Verify rules allow SSH from your IP.
[ ] Users: Verify your user account is active and has sudo access.
[ ] Persistence: Verify the fallback root key is installed (if used).

ESTIMATE: Reboot cycle typically takes 30-60 seconds.
TIMEOUT: This prompt will timeout in 30 minutes and SKIP the reboot.
"""

        decision = decision_manager.request_decision(
            issue=f"System is ready for reboot. Please verify you still have access before proceeding.\n{checklist}",
            options=options,
            timeout=1800,  # 30 minutes
        )

        if decision == "skip":
            logger.warning("Operator chose to skip reboot.")
            return [
                HardeningResult(
                    False,
                    "reboot",
                    "Operator Skipped Reboot",
                    error="Operator decision: skip",
                )
            ]
        elif decision is None:
            logger.error("Reboot decision timed out - SKIPPING REBOOT for safety.")
            return [
                HardeningResult(
                    False,
                    "reboot",
                    "Safeguard: Reboot Skipped (Timeout)",
                    error="Operator decision timeout",
                )
            ]

        # Operator approved
        return None

    def _execute_reboot_and_reconnect(self) -> list[HardeningResult]:
        """
        Execute the actual reboot and wait for reconnection.

        This handles the complex process of:
        1. Triggering reboot
        2. Closing the old connection
        3. Clearing known_hosts (keys may regenerate)
        4. Polling for reconnection
        5. Updating self.conn with fresh connection

        Raises:
            CriticalPipelineError: If host is unreachable after timeout
        """
        import paramiko
        from fabric import Config, Connection

        logger.info("Rebooting system...")
        self.conn.run("reboot", warn=True)

        logger.info("Waiting for system to go down...")
        time.sleep(5)

        logger.info("Waiting for system to come back (max 300s)...")

        # Close the old connection explicitly
        with contextlib.suppress(Exception):
            self.conn.close()

        creds = self.server_info.credentials

        # Clear known_hosts entry to avoid mismatch errors if keys regenerated
        self._clear_known_hosts(creds.host)
        if creds.host != self.conn.host:
            self._clear_known_hosts(self.conn.host)

        # Build fresh connection with host key checking disabled
        fresh_connect_kwargs = {
            "allow_agent": False,
            "look_for_keys": False,
            "timeout": 15,
            "disabled_algorithms": {},
        }

        # Use known SSH key for authentication
        key_path = (
            creds.key_file
            if creds.key_file
            else str(Path(__file__).parent.parent / "keys" / "test-root-key.private")
        )
        fresh_connect_kwargs["key_filename"] = key_path

        # Don't load system known_hosts (avoids "Host key mismatch" errors)
        fresh_config = Config(
            overrides={
                "load_ssh_configs": False,
                "load_system_host_keys": False,
            }
        )

        # Poll for reconnection
        deadline = time.time() + 300  # 5 minutes timeout
        reconnected = False

        while time.time() < deadline:
            try:
                test_conn = Connection(
                    creds.host,
                    user=creds.user,
                    port=creds.port,
                    config=fresh_config,
                    connect_kwargs=fresh_connect_kwargs,
                )
                # Override paramiko's host key policy to accept new keys
                test_conn.client = paramiko.SSHClient()
                test_conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                test_conn.open()

                # Enable keepalive to prevent timeouts during long local operations (e.g. Ansible)
                test_conn.transport.set_keepalive(30)

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
            self._log_reboot_failure(creds.host)
            raise CriticalPipelineError(
                f"Host {creds.host} unreachable after reboot - requires manual intervention"
            )

        return [HardeningResult(True, "reboot", "System Reboot")]

    def _clear_known_hosts(self, host: str) -> None:
        """Clear a host from known_hosts to avoid key mismatch errors."""
        import subprocess

        try:
            subprocess.run(["ssh-keygen", "-R", host], capture_output=True)
        except Exception as e:
            logger.warning(f"Failed to clear known_hosts for {host}: {e}")

    def _log_reboot_failure(self, host: str) -> None:
        """Log detailed failure information when reboot reconnection times out."""
        logger.error("Timed out waiting for system to reboot.")
        logger.error(
            "CRITICAL: Host is unreachable after reboot - manual intervention required!"
        )
        logger.error(f"  Host: {host}")
        logger.error("  Possible causes:")
        logger.error("    - Firewall rules locked out SSH")
        logger.error("    - System failed to boot")
        logger.error("    - Network configuration issue")
        logger.error("  Manual recovery steps:")
        logger.error("    1. Access via console/out-of-band management")
        logger.error(
            "    2. Check firewall: firewall-cmd --set-default-zone=trusted && firewall-cmd --reload"
        )
        logger.error("    3. Check SSH: systemctl status sshd")

    def _handle_discovery(self, dry_run: bool) -> list[HardeningResult]:
        """
        Handle system discovery refresh.

        This re-runs discovery and propagates the new ServerInfo to all modules.
        It's called after reboot to ensure modules have fresh system state.
        """
        if dry_run:
            return [HardeningResult(True, "discovery", "System Discovery (Dry Run)")]

        try:
            from .discovery import SystemDiscovery

            logger.info("Re-running system discovery...")
            discovery = SystemDiscovery(self.conn, self.server_info.credentials)
            new_info = discovery.discover_system()

            # Update orchestrator state
            self.server_info = new_info

            # Propagate to all modules so they have fresh data
            for mod in self.modules_map.values():
                mod.server_info = new_info

            return [HardeningResult(True, "discovery", "System Discovery (Refreshed)")]

        except Exception as e:
            return [
                HardeningResult(False, "discovery", "System Discovery", error=str(e))
            ]

    def get_summary(self, results: dict[str, list[HardeningResult]]) -> str:
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
                        summary_lines.append(
                            f"    - {result.description}: {result.error}"
                        )

        return "\n".join(summary_lines)

    def deploy(
        self,
        dry_run: bool = False,
        modules: list[str] | None = None,
        bypass_reboot_prompt: bool = False,
    ) -> dict:
        """
        Deploy hardening and generate report.

        Args:
            dry_run: If True, only show what would be done
            modules: List of module names to apply (None = use pipeline)

        Returns:
            Dictionary with results and summary
        """
        host_label = self.server_info.credentials.display_name.replace(
            ":", "_"
        ).replace("/", "_")
        logger.info(
            f"Starting hardening deployment on {self.server_info.credentials.display_name} ({self.conn.host})"
        )
        if dry_run:
            logger.info("DRY RUN MODE - No changes will be made")

        # Connection Warmer: Run a dummy command to ensure connection is active
        # This prevents the first heavy operation from failing due to initial connection setup
        try:
            logger.info("Warming up connection...")
            self.conn.run("true", hide=True, timeout=10)
        except Exception as e:
            logger.warning(f"Connection warm-up failed (proceeding anyway): {e}")

        results = self.apply_all(
            dry_run=dry_run, modules=modules, bypass_reboot_prompt=bypass_reboot_prompt
        )
        summary = self.get_summary(results)

        report_path = self._generate_report(host_label, results, summary)

        return {
            "host": self.conn.host,
            "server_info": self.server_info,
            "results": results,
            "summary": summary,
            "report_file": report_path,
        }

    def _generate_report(self, host_label: str, results: dict, summary: str) -> str:
        """Generate markdown report for the host using ReportGenerator."""
        report_gen = ReportGenerator(self.server_info, self.os_family, self.modules_map)
        return report_gen.generate_report(host_label, results, summary)
