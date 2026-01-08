"""
SSH hardening module for CCDC framework
Enhanced with proper backup/rollback and connection testing
"""

import json
import logging
import os
import time

from fabric import Config, Connection

from .base import CommandAction, HardeningModule, HardeningResult, PythonAction

ROOT_KEY_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../keys/test-root-key.private")
)

logger = logging.getLogger(__name__)




class SSHHardeningModule(HardeningModule):
    """SSH hardening commands with backup, rollback, and connection testing"""

    def __init__(self, connection, server_info, os_family):
        super().__init__(connection, server_info, os_family)
        self.users_config = self._load_users_config()

        # Cache patterns for efficient matching
        self.do_not_change_patterns = self._get_pattern_list("do_not_change_users")
        self.regular_patterns = self._get_pattern_list("regular_users")
        self.super_patterns = self._get_pattern_list("super_users")

        self.allowed_users = self._get_allowed_users()
        self.trapped_users = self._get_trapped_users()
        self.allowed_users = self.allowed_users | set(self.trapped_users)
        self.dead_mans_switch_pid = None

    def get_name(self) -> str:
        return "ssh_hardening"

    def _load_users_config(self):
        """Load users configuration from users.json"""
        config_path = os.path.join(os.path.dirname(__file__), "../../users.json")
        try:
            with open(config_path) as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("users.json not found at %s", config_path)
            return {
                "regular_users": {},
                "super_users": {},
                "do_not_change_users": {"root": "system account"},
            }
        except json.JSONDecodeError as exc:
            logger.error("users.json is invalid: %s", exc)
            return {
                "regular_users": {},
                "super_users": {},
                "do_not_change_users": {"root": "system account"},
            }

    def _get_user_set(self, key: str) -> set[str]:
        """Extract user set from config (handles dict or list)"""
        value = self.users_config.get(key, {})
        if isinstance(value, dict):
            return {k for k in value.keys() if not k.startswith("pattern:")}
        elif isinstance(value, list):
            return {item for item in value if not item.startswith("pattern:")}
        return set()

    def _get_pattern_list(self, key: str) -> list[str]:
        """Extract pattern entries (starting with 'pattern:') from config."""
        patterns: list[str] = []
        value = self.users_config.get(key, {})
        if isinstance(value, dict):
            for k in value.keys():
                if k.startswith("pattern:"):
                    pattern = k[8:].strip()
                    if pattern:
                        patterns.append(pattern)
                    else:
                        logger.warning("Empty pattern entry ignored in %s", key)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.startswith("pattern:"):
                    pattern = item[8:].strip()
                    if pattern:
                        patterns.append(pattern)
                    else:
                        logger.warning("Empty pattern entry ignored in %s", key)
        return patterns

    def _matches_pattern(self, username: str, patterns: list[str]) -> bool:
        """Check if username matches any pattern using fnmatch."""
        import fnmatch

        for pattern in patterns:
            try:
                if fnmatch.fnmatch(username, pattern):
                    return True
            except Exception as e:
                logger.warning("Invalid pattern '%s': %s", pattern, e)
        return False

    def _get_allowed_users(self) -> set[str]:
        """Get all users that should be allowed to SSH (not trapped)"""
        regular = self._get_user_set("regular_users")
        super_users = self._get_user_set("super_users")
        do_not_change = self._get_user_set("do_not_change_users")
        return regular | super_users | do_not_change

    def _is_allowed_user(self, username: str) -> bool:
        """Check if username is allowed (literal or pattern match)."""
        if username in self.allowed_users:
            return True
        # Check against all pattern lists
        all_patterns = (
            self.regular_patterns + self.super_patterns + self.do_not_change_patterns
        )
        return self._matches_pattern(username, all_patterns)

    def _get_trapped_users(self) -> list[str]:
        """Get 1 user for honeypot trapping, prioritizing users with SSH keys"""
        current_valid_users = {
            user.username for user in self.server_info.users if user.valid_shell
        }
        # Filter out allowed users (including pattern matches)
        non_allowed = {
            user for user in current_valid_users if not self._is_allowed_user(user)
        }

        # Get full user objects for non-allowed users
        non_allowed_users = [
            user for user in self.server_info.users if user.username in non_allowed
        ]

        # First, try to find users with SSH keys
        users_with_keys = [u for u in non_allowed_users if u.had_key]

        if users_with_keys:
            # Prioritize users with keys, sort by length (descending) as tiebreaker
            sorted_users = sorted(
                users_with_keys, key=lambda u: (-len(u.username), u.username)
            )
            trapped = [sorted_users[0].username]
            logger.info(
                f"Selected user with SSH key for honeypot trapping: {trapped[0]}"
            )
        else:
            # Fall back to longest username
            sorted_users = sorted(non_allowed, key=lambda u: (-len(u), u))
            trapped = sorted_users[:1] if sorted_users else []
            if trapped:
                logger.info(
                    f"Selected user (no keys found) for honeypot trapping: {trapped[0]}"
                )
            else:
                logger.info("No suitable users found for honeypot trapping")

        return trapped

    def _generate_ssh_config(self) -> str:
        """Generate the complete SSH hardening configuration"""
        # Include both allowed users AND trapped users in AllowUsers directive
        all_allowed = sorted(self.allowed_users | set(self.trapped_users))
        allowed_users_str = " ".join(all_allowed)

        config = f"""# ===== BEGIN SSH HARDENING CONFIG FABRIC EDITION V 1.0 =====
# Generated by MSU-BlueScripts SSH Hardening Module
# Do not manually edit this section

# Core Security Settings
Protocol 2
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes

# Disable Legacy/Insecure Features
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no

# Authentication & Session Settings
MaxAuthTries 3
LoginGraceTime 60s
ClientAliveInterval 300
ClientAliveCountMax 2

# System Integration
UsePAM yes
SyslogFacility AUTH
AcceptEnv LANG LC_*

# User Access Control (includes trapped honeypot users)
AllowUsers {allowed_users_str}

# ===== END SSH HARDENING CONFIG =====

"""
        return config

    def _generate_trap_config(self) -> str:
        trapped_users_str = ",".join(self.trapped_users)
        return f"""Match User {trapped_users_str}
    ForceCommand env -u $(env | cut -d= -f1) /bin/honeypot
    ChrootDirectory none
    AllowTcpForwarding no 
    X11Forwarding no 
    PermitTunnel no 
    GatewayPorts no 
    AllowAgentForwarding no 
    PermitOpen none
"""

    def get_commands(self) -> list[CommandAction]:
        commands = []

        # Deploy honeypot shell if there are trapped users
        if self.trapped_users:
            commands.append(
                PythonAction(
                    function=self._deploy_honeypot_shell,
                    description="Deploy honeypot shell to /bin/honeypot",
                    requires_sudo=True,
                )
            )

        # Create backup with timestamp and store backup path
        backup_file = "/etc/ssh/sshd_config.fabric.backup"

        # 1. Safer Backup Creation
        # Check if the backup already exists, if it does do nothing to preserve the original state before ANY fabric runs
        commands.append(
            CommandAction(
                command=f"test -f {backup_file} && echo 'Backup {backup_file} already exists, skipping' || (cp /etc/ssh/sshd_config {backup_file} && echo 'Backup created: {backup_file}')",
                description="Create timestamped SSH configuration backup (if not exists)",
                check_command=f"ls {backup_file} >/dev/null 2>&1 && echo backup_exists",
                requires_sudo=True,
            )
        )

        # 2. Original Config Validation & Fallback
        # Validate original config. If invalid, backup as broken and assert a minimal valid config.
        # We first write and test the minimal config to ensure sshd -t itself is working.
        minimal_config = "Protocol 2\\nPermitRootLogin prohibit-password\\nPasswordAuthentication yes\\nPubkeyAuthentication yes\\nSubsystem sftp /usr/lib/openssh/sftp-server"
        minimal_file = "/etc/ssh/sshd_config.minimal.config"
        broken_backup = f"{backup_file}.original.broken"

        validate_and_fix_cmd = (
            # 1. Create minimal file
            f"printf '{minimal_config}' > {minimal_file} && "
            f"chmod 644 {minimal_file} && "
            # 2. Test minimal file (verifies sshd -t works)
            f"sshd -t -f {minimal_file} && "
            # 3. Check original config
            f"(sshd -t -f /etc/ssh/sshd_config && echo 'Original config valid' || "
            # 4. Fallback if original broken using the verified minimal file
            f"(echo 'Original config BROKEN. Backing up and resetting...' && "
            f"cp /etc/ssh/sshd_config {broken_backup} && "
            f"cp {minimal_file} /etc/ssh/sshd_config && "
            f"echo 'Reset to minimal valid config'))"
        )

        commands.append(
            CommandAction(
                command=validate_and_fix_cmd,
                description="Validate original SSH configuration (reset to minimal if broken, verifies check command first)",
                requires_sudo=True,
            )
        )

        # Generate and prepend hardening config
        hardening_config = self._generate_ssh_config()
        commands.append(
            PythonAction(
                function=self._prepend_ssh_config,
                description="Prepend hardening configuration to sshd_config",
                args=(hardening_config,),
                requires_sudo=True,
            )
        )

        # Append trapped users Match blocks to end of config (if any)
        trap_config = self._generate_trap_config()
        if self.trapped_users:
            commands.append(
                PythonAction(
                    function=self._append_trapped_users,
                    description=f"Append honeypot traps for users: {', '.join(self.trapped_users)}",
                    args=(trap_config,),
                    requires_sudo=True,
                )
            )

        # Arm Dead Man's Switch before reload
        commands.append(
            PythonAction(
                function=self._arm_dead_mans_switch,
                description="Arm Dead Man's Switch (60s fuse)",
                args=(backup_file,),
                requires_sudo=True,
            )
        )

        # Ensure SSH is enabled at boot
        enable_cmd = self._get_ssh_enable_command()
        commands.append(
            CommandAction(
                command=enable_cmd,
                description="Ensure SSH service is enabled at boot",
                requires_sudo=True,
            )
        )

        # Mark as safe to reboot ONLY if we get here (meaning test checks passed)
        commands.append(
            PythonAction(
                function=self._set_reboot_safety,
                description="Signal that reboot is safe",
                requires_sudo=False,
            )
        )

        # 4. Combined Validation and Reload
        # Combine these into one task so that if the validation of new config fails we don't proceed with reloading the ssh service
        reload_cmd = self._get_ssh_reload_command()
        commands.append(
            CommandAction(
                command=f"sshd -t -f /etc/ssh/sshd_config && echo 'New config valid' && {reload_cmd}",
                description="Validate new SSH configuration and reload service",
                requires_sudo=True,
            )
        )

        # Test SSH connectivity with Python function
        commands.append(
            PythonAction(
                function=self._test_ssh_connectivity,
                description="Test SSH connectivity after changes",
                requires_sudo=False,
            )
        )

        return commands

    def _append_trapped_users(self, conn, server_info, trap_config):
        """append hardening config to /etc/ssh/sshd_config"""
        try:
            # Read current config
            result = conn.run("cat /etc/ssh/sshd_config", hide=True, warn=True)
            if not result.ok:
                return HardeningResult(
                    success=False,
                    command="append_trap_sshd",
                    description="Read current sshd_config",
                    output="",
                    error=f"Failed to read sshd_config: {result.stderr}",
                )

            trap_config = self._generate_trap_config()

            write_result = conn.run(
                f"printf '%s' '{trap_config}' >> /etc/ssh/sshd_config",
                hide=True,
                warn=True,
            )

            if not write_result.ok:
                return HardeningResult(
                    success=False,
                    command="append_trap_sshd",
                    description="append config to file",
                    output="",
                    error=f"Failed to append trap config: {write_result.stderr}",
                )

            trapped_count = len(self.trapped_users)

            return HardeningResult(
                success=True,
                command="append_trap_sshd",
                description="Prepend hardening configuration to sshd_config",
                output=f"Successfully appened SSH trapping config. Trapped users: {trapped_count}",
            )

        except Exception as e:
            logger.error(f"Error prepending SSH config: {e}")
            return HardeningResult(
                success=False,
                command="append_trap_sshd",
                description="Prepend hardening configuration to sshd_config",
                output="",
                error=str(e),
            )

    def _deploy_honeypot_shell(self, conn, server_info):
        """Deploy the honeypot shell script to /bin/honeypot and configure it"""
        try:
            # Get the path to the honeypot script
            honeypot_script_path = os.path.join(
                os.path.dirname(__file__), "../../scripts/helpers/blue-sweet-tooth.sh"
            )

            # Check if the script exists locally
            if not os.path.exists(honeypot_script_path):
                return HardeningResult(
                    success=False,
                    command="deploy_honeypot",
                    description="Deploy honeypot shell",
                    output="",
                    error=f"Honeypot script not found at {honeypot_script_path}",
                )

            # Read the script content
            with open(honeypot_script_path) as f:
                script_content = f.read()

            # Escape for shell
            escaped_content = script_content.replace("'", "'\"'\"'")

            # Upload script to /bin/honeypot
            write_result = conn.run(
                f"printf '%s' '{escaped_content}' > /bin/honeypot", hide=True, warn=True
            )

            if not write_result.ok:
                return HardeningResult(
                    success=False,
                    command="deploy_honeypot",
                    description="Write honeypot script to /bin/honeypot",
                    output="",
                    error=f"Failed to write honeypot script: {write_result.stderr}",
                )

            # Make it executable
            chmod_result = conn.run("chmod +x /bin/honeypot", hide=True, warn=True)
            if not chmod_result.ok:
                return HardeningResult(
                    success=False,
                    command="deploy_honeypot",
                    description="Make honeypot executable",
                    output="",
                    error=f"Failed to chmod honeypot: {chmod_result.stderr}",
                )

            # Add to /etc/shells if not already present
            check_shells_result = conn.run(
                "grep -Fxq '/bin/honeypot' /etc/shells || echo '/bin/honeypot' >> /etc/shells",
                hide=True,
                warn=True,
            )

            if not check_shells_result.ok:
                logger.warning("Failed to add honeypot to /etc/shells, but continuing")

            # Create log file in /var/log with proper permissions (world-writable for honeypot)
            varlog_result = conn.run(
                "touch /var/log/honeypot.log && chmod 666 /var/log/honeypot.log",
                hide=True,
                warn=True,
            )
            if not varlog_result.ok:
                logger.warning("Failed to create /var/log/honeypot.log, but continuing")

            # Create /root/logs directory (world-readable/executable so symlink can be followed)
            # and symlink to /var/log/honeypot.log
            symlink_result = conn.run(
                "mkdir -p /root/logs && chmod 755 /root/logs && ln -sf /var/log/honeypot.log /root/logs/honeypot.log",
                hide=True,
                warn=True,
            )
            if not symlink_result.ok:
                logger.warning(
                    "Failed to create symlink for honeypot log, but continuing"
                )

            return HardeningResult(
                success=True,
                command="deploy_honeypot",
                description="Deploy honeypot shell to /bin/honeypot",
                output=f"Successfully deployed honeypot shell for trapped users: {', '.join(self.trapped_users)}",
            )

        except Exception as e:
            logger.error(f"Error deploying honeypot shell: {e}")
            return HardeningResult(
                success=False,
                command="deploy_honeypot",
                description="Deploy honeypot shell",
                output="",
                error=str(e),
            )

    def _prepend_ssh_config(self, conn, server_info, hardening_config: str):
        """Prepend hardening config to /etc/ssh/sshd_config"""
        try:
            # 3. Idempotency Check
            # Read first line to see if already hardened
            HARDENING_HEADER = (
                "# ===== BEGIN SSH HARDENING CONFIG FABRIC EDITION V 1.0 ====="
            )
            head_result = conn.run(
                "head -n 1 /etc/ssh/sshd_config", hide=True, warn=True
            )

            if head_result.ok and head_result.stdout.strip() == HARDENING_HEADER:
                return HardeningResult(
                    success=True,
                    command="prepend_ssh_config",
                    description="Prepend hardening configuration",
                    output="SSH config already hardened (idempotency check passed)",
                )

            # Read current config
            result = conn.run("cat /etc/ssh/sshd_config", hide=True, warn=True)
            if not result.ok:
                return HardeningResult(
                    success=False,
                    command="prepend_ssh_config",
                    description="Read current sshd_config",
                    output="",
                    error=f"Failed to read sshd_config: {result.stderr}",
                )

            current_config = result.stdout

            # Combine: hardening config + original config
            new_config = hardening_config + current_config

            # Write to temporary file first
            temp_file = "/tmp/sshd_config.new"

            # Escape special characters for shell
            escaped_config = new_config.replace("'", "'\"'\"'")

            write_result = conn.run(
                f"printf '%s' '{escaped_config}' > {temp_file}", hide=True, warn=True
            )

            if not write_result.ok:
                return HardeningResult(
                    success=False,
                    command="prepend_ssh_config",
                    description="Write new config to temp file",
                    output="",
                    error=f"Failed to write temp config: {write_result.stderr}",
                )

            # Move temp file to actual location
            move_result = conn.run(
                f"mv {temp_file} /etc/ssh/sshd_config && chmod 644 /etc/ssh/sshd_config",
                hide=True,
                warn=True,
            )

            if not move_result.ok:
                return HardeningResult(
                    success=False,
                    command="prepend_ssh_config",
                    description="Move new config to /etc/ssh/sshd_config",
                    output="",
                    error=f"Failed to move config: {move_result.stderr}",
                )

            allowed_count = len(self.allowed_users)

            return HardeningResult(
                success=True,
                command="prepend_ssh_config",
                description="Prepend hardening configuration to sshd_config",
                output=f"Successfully prepended SSH hardening config. Allowed users: {allowed_count}",
            )

        except Exception as e:
            logger.error(f"Error prepending SSH config: {e}")
            return HardeningResult(
                success=False,
                command="prepend_ssh_config",
                description="Prepend hardening configuration to sshd_config",
                output="",
                error=str(e),
            )

    def _arm_dead_mans_switch(self, conn, server_info, backup_file):
        """
        ARM DEAD MAN'S SWITCH - Critical safety mechanism for SSH hardening.
        """
        try:
            reload_cmd = self._get_ssh_reload_command()
            # Complex shell command to sleep, restore, and reload
            # We use nohup to ensure it survives connection loss

            revert_cmd = (
                f"sleep 60 && "
                f"mv {backup_file} /etc/ssh/sshd_config && "
                f"{reload_cmd} && "
                f"echo 'Dead mans switch triggered: reverted SSH config'"
            )

            # Wrap in a way that gives us the PID of the sleep process or the shell
            # We want to be able to kill this entire chain.
            # Using a subshell in background: ( ... ) & echo $!

            full_cmd = f'nohup sh -c "{revert_cmd}" >/dev/null 2>&1 & echo $!'

            result = conn.run(full_cmd, hide=True)
            if result.ok and result.stdout.strip().isdigit():
                self.dead_mans_switch_pid = result.stdout.strip()
                logger.info(
                    f"Armed Dead Man's Switch with PID: {self.dead_mans_switch_pid}"
                )
                return HardeningResult(
                    success=True,
                    command="arm_dead_mans_switch",
                    description="Armed Dead Man's Switch",
                    output=f"Armed with PID {self.dead_mans_switch_pid}",
                )
            else:
                return HardeningResult(
                    success=False,
                    command="arm_dead_mans_switch",
                    description="Arm Dead Man's Switch",
                    output="",
                    error=f"Failed to get PID: {result.stderr}",
                )
        except Exception as e:
            return HardeningResult(
                success=False,
                command="arm_dead_mans_switch",
                description="Arm Dead Man's Switch",
                output="",
                error=str(e),
            )

    def _test_ssh_connectivity(self, conn, server_info):
        """Test SSH connectivity after configuration changes with automatic rollback on failure"""
        import logging

        logger = logging.getLogger(__name__)

        try:
            # Get connection details from server_info
            host = server_info.credentials.host
            user = server_info.credentials.user
            port = getattr(server_info.credentials, "port", 22)
            password = getattr(server_info.credentials, "password", None)
            key_file = getattr(server_info.credentials, "key_file", None)

            logger.info(f"Testing SSH connectivity to {host}:{port} as {user}")

            # Set up connection configuration
            connect_kwargs = {"allow_agent": False, "look_for_keys": False}
            config_overrides = {
                "sudo": {"password": password},
                "load_ssh_configs": False,
            }

            # Special handling for root user - use the designated root key if available
            # This is critical because after hardening, root password login is disabled
            if user == "root" and os.path.exists(ROOT_KEY_PATH):
                logger.info(
                    f"Using root recovery key for connectivity test: {ROOT_KEY_PATH}"
                )
                current_keys = [ROOT_KEY_PATH]
                if key_file:
                    if isinstance(key_file, list):
                        current_keys.extend(key_file)
                    else:
                        current_keys.append(key_file)
                connect_kwargs["key_filename"] = current_keys
                # Do NOT use password for root - key auth only after SSH hardening

            else:
                # Standard logic: use key if available, else password
                if key_file:
                    connect_kwargs["key_filename"] = key_file
                elif password:
                    connect_kwargs["password"] = password

            if port != 22:
                connect_kwargs["port"] = port

            config = Config(overrides=config_overrides)

            # Retry with increasing delays (sshd needs time to restart after reload)
            max_retries = 3
            delays = [3, 5, 8]  # Seconds to wait before each attempt
            test_success = False
            error_msg = None

            for attempt in range(max_retries):
                delay = delays[attempt] if attempt < len(delays) else 5
                logger.info(
                    f"Testing SSH connectivity (attempt {attempt + 1}/{max_retries}, waiting {delay}s)..."
                )
                time.sleep(delay)

                try:
                    with Connection(
                        host, user=user, config=config, connect_kwargs=connect_kwargs
                    ) as test_conn:
                        result = test_conn.run(
                            'echo "SSH test successful"',
                            hide=True,
                            warn=True,
                            timeout=10,
                        )
                        test_success = result.ok
                        if not test_success:
                            error_msg = f"SSH test command failed: {result.stderr}"
                        else:
                            error_msg = None
                            break  # Success, exit retry loop

                except Exception as e:
                    test_success = False
                    error_msg = f"SSH connection failed: {str(e)}"
                    logger.warning(
                        f"Connectivity check attempt {attempt + 1} failed: {e}"
                    )

            if test_success:
                msg = "SSH connectivity test successful - new configuration is working"

                # Disarm Dead Man's Switch
                if self.dead_mans_switch_pid:
                    # Kill the background process (usually sleep or sh)
                    # We kill the process group or just the pid
                    conn.run(
                        f"kill {self.dead_mans_switch_pid} || true",
                        hide=True,
                        warn=True,
                    )
                    logger.info(
                        f"Disarmed Dead Man's Switch (PID {self.dead_mans_switch_pid})"
                    )
                    msg += " | Dead Man's Switch Disarmed"

                return HardeningResult(
                    success=True,
                    command="python_function:_test_ssh_connectivity",
                    description="Test SSH connectivity after changes",
                    output=msg,
                )
            else:
                # Connection failed - attempt automatic rollback
                logger.warning(f"SSH connectivity test failed: {error_msg}")
                logger.info("Attempting automatic rollback of SSH configuration...")

                # Find the most recent backup
                backup_result = conn.run(
                    "ls -t /etc/ssh/sshd_config.backup.* 2>/dev/null | head -1",
                    hide=True,
                    warn=True,
                )

                if backup_result.ok and backup_result.stdout.strip():
                    backup_file = backup_result.stdout.strip()
                    logger.info(f"Found backup file: {backup_file}")

                    # Restore the backup
                    restore_result = conn.run(
                        f"cp {backup_file} /etc/ssh/sshd_config", hide=True, warn=True
                    )

                    if restore_result.ok:
                        # Restart SSH service
                        reload_cmd = self._get_ssh_reload_command()
                        restart_result = conn.run(reload_cmd, hide=True, warn=True)

                        if restart_result.ok:
                            logger.info("SSH configuration rolled back successfully")

                            # Also disarm the switch since we rolled back manually
                            if self.dead_mans_switch_pid:
                                conn.run(
                                    f"kill {self.dead_mans_switch_pid} || true",
                                    hide=True,
                                    warn=True,
                                )

                            return HardeningResult(
                                success=False,
                                command="python_function:_test_ssh_connectivity",
                                description="Test SSH connectivity after changes",
                                output="SSH test failed, configuration rolled back automatically",
                                error=f"Original error: {error_msg}. Rollback completed successfully.",
                            )
                        else:
                            logger.error("Failed to restart SSH service after rollback")
                    else:
                        logger.error("Failed to restore SSH configuration backup")
                else:
                    logger.error("No SSH configuration backup found for rollback")

                # If we get here, manual rollback failed or no backup found.
                # Hopefully the Dead Man's Switch will save us in <60s.
                return HardeningResult(
                    success=False,
                    command="python_function:_test_ssh_connectivity",
                    description="Test SSH connectivity after changes",
                    output="SSH connectivity test failed",
                    error=f"SSH test failed: {error_msg}. Manual intervention may be required. Dead Man's Switch active.",
                )

        except Exception as e:
            logger.error(f"SSH connectivity test encountered an error: {e}")
            return HardeningResult(
                success=False,
                command="python_function:_test_ssh_connectivity",
                description="Test SSH connectivity after changes",
                output="SSH connectivity test encountered an error",
                error=str(e),
            )

    def _get_ssh_reload_command(self) -> str:
        """Get the appropriate SSH reload command (tries both ssh and sshd)"""
        try:
            init_system = getattr(self.server_info, "init_system", "unknown")

            # Helper to construct "reload OR restart" for a service name
            def cmd_for(srv, sys_type):
                # Fallback "spray and pray" chain for unknown systems
                # Includes: systemd, openrc, bsd, sysvinit, slackware
                fallback = (
                    f"(service {srv} reload || "
                    f"systemctl restart {srv} || "
                    f"/etc/init.d/{srv} restart || "
                    f"rc-service {srv} reload || "
                    f"rc-service {srv} restart || "
                    f"/etc/rc.d/rc.{srv} restart)"
                )

                commands = {
                    "systemd": f"(systemctl reload {srv} || sudo systemctl restart {srv})",
                    "openrc": f"(rc-service {srv} reload || sudo rc-service {srv} restart)",
                    "bsd": f"service {srv} reload",
                    "sysvinit": f"(service {srv} reload || /etc/init.d/{srv} reload)",
                }
                return commands.get(sys_type, fallback)

            # Generate commands for both 'ssh' and 'sshd'
            # We chain them with OR (||) so if 'ssh' fails (e.g. not found), 'sshd' runs.
            # If 'sshd' succeeds, we are done.
            ssh_cmd = cmd_for("ssh", init_system)
            sshd_cmd = cmd_for("sshd", init_system)

            return f"{sshd_cmd} || {ssh_cmd} "

        except Exception as e:
            logger.warning(f"Error determining SSH reload command: {e}")
            # Robust fallback
            return "(service ssh reload || service sshd reload || systemctl restart sshd || /etc/rc.d/rc.sshd restart)"

    def _set_reboot_safety(self, conn, server_info) -> HardeningResult:
        """Mark the server as safe to reboot (SSH is verified working)"""
        server_info.safe_to_reboot = True
        return HardeningResult(
            success=True,
            command="python_function:_set_reboot_safety",
            description="Mark server as safe to reboot",
            output="Server marked as safe to reboot",
        )

    def _get_ssh_enable_command(self) -> str:
        """Get the appropriate command to enable SSH at boot"""
        try:
            init_system = getattr(self.server_info, "init_system", "unknown")

            def cmd_for(srv, sys_type):
                # Fallback "spray and pray" chain for unknown systems
                # Includes: systemd, openrc, debian-sysv, redhat-sysv, bsd, slackware
                fallback = (
                    f"(systemctl enable {srv} || "
                    f"rc-update add {srv} default || "
                    f"update-rc.d {srv} defaults || "
                    f"chkconfig {srv} on || "
                    f"sysrc sshd_enable=YES || "
                    f"chmod +x /etc/rc.d/rc.{srv})"
                )

                commands = {
                    "systemd": f"systemctl enable {srv}",
                    "openrc": f"rc-update add {srv} default",
                    # sysrc for FreeBSD/NetBSD, rcctl for OpenBSD
                    "bsd": f"(sysrc sshd_enable=YES || rcctl enable {srv})",
                    # generic sysvinit fallback (Debian/RedHat legacy)
                    "sysvinit": f"(update-rc.d {srv} defaults || chkconfig {srv} on)",
                }
                return commands.get(sys_type, fallback)

            ssh_cmd = cmd_for("ssh", init_system)
            sshd_cmd = cmd_for("sshd", init_system)

            return f"{sshd_cmd} || {ssh_cmd}"

        except Exception as e:
            logger.warning(f"Error determining SSH enable command: {e}")
            return "systemctl enable sshd || rc-update add sshd default || chmod +x /etc/rc.d/rc.sshd"
