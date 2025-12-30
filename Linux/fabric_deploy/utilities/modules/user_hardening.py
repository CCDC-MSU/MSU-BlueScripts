"""
User hardening module for CCDC framework.
Manages user accounts, passwords, sudo access, and account security.
"""

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

from .base import HardeningModule, HardeningCommand, PythonAction, HardeningResult
from ..actions import UserManager
from ..utils import generate_password

logger = logging.getLogger(__name__)

ROOT_KEY_PATH = os.path.join(os.path.dirname(__file__), "/home/antimony/Desktop/cyber/repos/MSU-BlueScripts/Linux/fabric_deploy/keys/test-root-key.pub")
ROOT_KEY_PATH_PRIVATE = os.path.join(os.path.dirname(__file__), "/home/antimony/Desktop/cyber/repos/MSU-BlueScripts/Linux/fabric_deploy/keys/test-root-key.private")

class UserHardeningModule(HardeningModule):
    """User account hardening based on users.json."""

    PER_HOST_SENTINEL = "__PER_HOST__"
    _password_lock = threading.Lock()
    _password_cache: Dict[str, str] = {}
    _per_host_users: Set[str] = set()
    _config_cache: Dict = {}
    _passwords_loaded = False

    def __init__(self, connection, server_info, os_family):
        super().__init__(connection, server_info, os_family)
        self.user_manager = UserManager(
            server_info.available_commands,
            server_info.groups,
            server_info.sudoers_info,
        )
        self.users_config = self._ensure_passwords_loaded()
        self.required_regular_users = self._get_user_set("regular_users")
        self.required_super_users = self._get_user_set("super_users")
        self.do_not_change_users = self._get_user_set("do_not_change_users")
        overlap = self.required_regular_users & self.required_super_users
        if overlap:
            logger.warning(
                "Users listed as both regular and super: %s",
                ", ".join(sorted(overlap)),
            )
            self.required_regular_users -= overlap
        self.required_users = self.required_regular_users | self.required_super_users
        self.current_valid_users = {
            user.username for user in server_info.users if user.valid_shell
        }
        self.current_sudo_users = self._discover_current_sudo_users()
        self.run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.password_log_path = self._build_password_log_path()
        self.password_cache = dict(UserHardeningModule._password_cache)
        self.per_host_users = set(UserHardeningModule._per_host_users)

    def get_name(self) -> str:
        return "user_hardening"

    def _load_users_config(self) -> Dict:
        """Load users configuration from users.json."""
        config_path = os.path.join(os.path.dirname(__file__), "../../users.json")
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("users.json not found at %s", config_path)
        except json.JSONDecodeError as exc:
            logger.error("users.json is invalid: %s", exc)

        return {
            "regular_users": {},
            "super_users": {},
            "do_not_change_users": {
                "root": "system account",
                "scan-agent": "do not change",
            },
        }

    def _get_user_set(self, *keys: str) -> Set[str]:
        users: Set[str] = set()
        for key in keys:
            value = self.users_config.get(key, {})
            if isinstance(value, dict):
                users.update(value.keys())
            elif isinstance(value, list):
                users.update(value)
        return users

    def _normalize_user_map(self, value: object) -> Dict[str, object]:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, list):
            return {user: None for user in value}
        return {}

    def _ensure_passwords_loaded(self) -> Dict:
        config_path = os.path.join(os.path.dirname(__file__), "../../users.json")
        with UserHardeningModule._password_lock:
            if UserHardeningModule._passwords_loaded:
                return UserHardeningModule._config_cache

            config = self._load_users_config()
            regular_map = self._normalize_user_map(config.get("regular_users", {}))
            super_map = self._normalize_user_map(config.get("super_users", {}))

            config["regular_users"] = regular_map
            config["super_users"] = super_map

            password_cache: Dict[str, str] = {}
            per_host_users: Set[str] = set()
            changed = False

            def populate_passwords(
                user_map: Dict[str, object],
            ) -> None:
                nonlocal changed
                for username, value in user_map.items():
                    if isinstance(value, str):
                        trimmed = value.strip()
                        if trimmed == self.PER_HOST_SENTINEL:
                            if value != self.PER_HOST_SENTINEL:
                                user_map[username] = self.PER_HOST_SENTINEL
                                changed = True
                            per_host_users.add(username)
                            continue
                        if trimmed:
                            password_cache[username] = value
                            continue

                    if value is None or (isinstance(value, str) and value.strip() == ""):
                        password = generate_password()
                        user_map[username] = password
                        password_cache[username] = password
                        changed = True
                        continue

                    password = str(value)
                    user_map[username] = password
                    password_cache[username] = password
                    changed = True

            populate_passwords(regular_map)
            populate_passwords(super_map)

            per_host_users -= set(password_cache)

            if changed:
                try:
                    with open(config_path, "w") as f:
                        json.dump(config, f, indent=2)
                        f.write("\n")
                    logger.info("Updated users.json with generated passwords")
                except OSError as exc:
                    logger.error("Failed to update users.json: %s", exc)

            UserHardeningModule._password_cache = password_cache
            UserHardeningModule._per_host_users = per_host_users
            UserHardeningModule._config_cache = config
            UserHardeningModule._passwords_loaded = True

            return config

    def _discover_current_sudo_users(self) -> Set[str]:
        sudo_users = set(self.server_info.sudoers_info.sudoer_users or [])
        sudo_groups = set(self.server_info.sudoers_info.sudoer_groups or [])
        sudo_groups.update(self.server_info.sudoers_info.sudoer_group_all or [])

        for group in sorted(sudo_groups):
            script = self.user_manager.get_users_in_group(group)
            result = self._run_command(script, use_sudo=False)
            if result.success and result.output:
                for line in result.output.splitlines():
                    user = line.strip()
                    if user:
                        sudo_users.add(user)
            elif result.error:
                logger.debug("Failed to query group %s: %s", group, result.error)

        return sudo_users

    def _host_label(self) -> str:
        # Use friendly name if available, otherwise use host IP
        base = self.server_info.credentials.display_name
        label = base.replace(":", "_").replace("/", "_").replace(" ", "_")
        port = getattr(self.server_info.credentials, "port", 22)
        if port != 22:
            label = f"{label}_{port}"
        return label

    def _build_password_log_path(self) -> str:
        host_label = self._host_label()
        log_dir = Path("logs") / "user-hardening" / host_label
        return str(log_dir / f"passwords_{self.run_timestamp}.txt")

    def _write_password_log(
        self,
        conn,
        server_info,
        log_path: str,
        records: List[Tuple[str, str, str]],
    ) -> HardeningResult:
        if not records:
            return HardeningResult(
                success=True,
                command="write_password_log",
                description="Write password log",
                output="No password changes to record",
            )

        log_file = Path(log_path)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        creds = server_info.credentials
        host_line = f"{creds.display_name} ({creds.host})" if creds.friendly_name else creds.host
        lines = [
            "User hardening password log",
            f"Host: {host_line}",
            f"Generated: {self.run_timestamp}",
            "",
            "username\trole\tpassword",
        ]
        for username, role, password in records:
            lines.append(f"{username}\t{role}\t{password}")

        log_file.write_text("\n".join(lines) + "\n")
        os.chmod(log_file, 0o600)

        logger.info("Password log written to %s", log_file)
        return HardeningResult(
            success=True,
            command=f"write_password_log:{log_file}",
            description="Write password log",
            output=str(log_file),
        )

    def _configure_root_access(self, conn, server_info) -> HardeningResult:
        """Read the local root key, append to remote authorized_keys, and update connection."""
        if not os.path.exists(ROOT_KEY_PATH):
            logger.warning("Root key not found at %s", ROOT_KEY_PATH)
            return HardeningResult(False, "configure_root_access", "Check Root Key", error="Root key file missing")

        try:
            with open(ROOT_KEY_PATH, "r") as f:
                key_content = f.read().strip()
        except OSError as e:
            return HardeningResult(False, "configure_root_access", "Read Root Key", error=str(e))

        if not key_content:
             return HardeningResult(False, "configure_root_access", "Read Root Key", error="Root key file empty")

        try:
            # 1. Ensure .ssh directory exists and has correct permissions
            conn.run("mkdir -p /root/.ssh", hide=True)
            conn.run("chmod 700 /root/.ssh", hide=True)
            
            # 2. Check if key exists, if not append it
            check = conn.run(f"grep -Fq '{key_content}' /root/.ssh/authorized_keys", warn=True, hide=True)
            if check.failed:
                conn.run(f"printf '\\n%s\\n' '{key_content}' >> /root/.ssh/authorized_keys", hide=True)
                conn.run("chmod 600 /root/.ssh/authorized_keys", hide=True)
                action_output = "Injected root key into authorized_keys"
            else:
                action_output = "Root key already present"

            # 3. Update Fabric connection to use the private key for future operations checking if not already using a key
            # Check if we are already using a key configuration
            current_keys = conn.connect_kwargs.get('key_filename')
            already_using_key = bool(current_keys)
            
            if already_using_key:
                 logger.info("Connection already configured with key(s), skipping connection update.")
                 action_output += ". Key auth already configured."
            elif os.path.exists(ROOT_KEY_PATH_PRIVATE):
                # Ensure key_filename is a list
                if 'key_filename' not in conn.connect_kwargs:
                    conn.connect_kwargs['key_filename'] = []
                elif not isinstance(conn.connect_kwargs['key_filename'], list):
                    conn.connect_kwargs['key_filename'] = [conn.connect_kwargs['key_filename']]
                
                # Add private key if not already present
                if ROOT_KEY_PATH_PRIVATE not in conn.connect_kwargs['key_filename']:
                    conn.connect_kwargs['key_filename'].insert(0, ROOT_KEY_PATH_PRIVATE)
                    logger.info(f"Updated Fabric connection to use private key: {ROOT_KEY_PATH_PRIVATE}")
                    action_output += ". Updated connection to use private key."
            else:
                logger.warning(f"Private key not found at {ROOT_KEY_PATH_PRIVATE}. Cannot update connection.")
                action_output += ". Warning: Private key missing locally."

            return HardeningResult(True, "configure_root_access", "Configure Root Access", output=action_output)

        except Exception as e:
            logger.error(f"Failed to configure root access: {e}")
            return HardeningResult(False, "configure_root_access", "Configure Root Access", error=str(e))

    def get_commands(self) -> List[HardeningCommand]:
        commands: List[HardeningCommand] = []
        password_records: List[Tuple[str, str, str]] = []

        if not self.required_users:
            logger.error("No users listed in users.json. The script refuses to continue.")
            return commands
        
        for username in sorted(self.required_super_users):
            if username in self.do_not_change_users:
                logger.info("Skipping do-not-change account: %s", username)
                continue

            if username in self.per_host_users:
                password = generate_password()
            else:
                password = self.password_cache.get(username, generate_password())
            password_records.append((username, "super", password))

            scripts = self.user_manager.add_sudo_user(username, password)
            for index, script in enumerate(scripts, start=1):
                commands.append(
                    HardeningCommand(
                        command=script,
                        description=(
                            f"Ensure super user {username} has sudo access "
                            f"({index}/{len(scripts)})"
                        ),
                        requires_sudo=True,
                    )
                )

        for username in sorted(self.required_regular_users):
            if username in self.do_not_change_users:
                logger.info("Skipping do-not-change account: %s", username)
                continue

            if username in self.per_host_users:
                password = generate_password()
            else:
                password = self.password_cache.get(username, generate_password())
            password_records.append((username, "regular", password))

            commands.append(
                HardeningCommand(
                    command=self.user_manager.add_user(username),
                    description=f"Ensure regular user exists: {username}",
                    requires_sudo=True,
                )
            )
            commands.append(
                HardeningCommand(
                    command=self.user_manager.set_user_password(username, password),
                    description=f"Set password for regular user: {username}",
                    requires_sudo=True,
                )
            )

            if username in self.current_sudo_users:
                commands.append(
                    HardeningCommand(
                        command=self.user_manager.remove_user_from_sudoers(username),
                        description=f"Remove sudo access from regular user: {username}",
                        requires_sudo=True,
                    )
                )

        unauthorized_valid_users = sorted(
            self.current_valid_users
            - self.required_users
            - self.do_not_change_users
        )
        for username in unauthorized_valid_users:
            if username in self.current_sudo_users:
                commands.append(
                    HardeningCommand(
                        command=self.user_manager.remove_user_from_sudoers(username),
                        description=(
                            f"Remove sudo access from unauthorized user: {username}"
                        ),
                        requires_sudo=True,
                    )
                )
            commands.append(
                HardeningCommand(
                    command=self.user_manager.lock_user(username),
                    description=f"Lock unauthorized user: {username}",
                    requires_sudo=True,
                )
            )


        if password_records:
            commands.insert(
                0,
                PythonAction(
                    function=self._write_password_log,
                    description=f"Write password log to {self.password_log_path}",
                    args=(self.password_log_path, list(password_records)),
                    requires_sudo=False,
                ),
            )

        # Insert Root Access Configuration at the very beginning
        commands.insert(
            0,
            PythonAction(
                function=self._configure_root_access,
                description="Ensure root recovery key is authorized and update connection",
                requires_sudo=True
            )
        )

        return commands

    def is_applicable(self) -> bool:
        """This module is applicable to all Unix-like systems."""
        return True
