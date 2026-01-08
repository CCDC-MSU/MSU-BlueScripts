import logging

from .models import SudoersInfo

logger = logging.getLogger(__name__)


class UserManager:
    def __init__(
        self,
        available_commands: list[str],
        groups: list[str],
        sudoers_info: SudoersInfo,
    ):
        self.available_commands = list(available_commands or [])
        self.available_groups = list(groups or [])
        self.sudoers_groups: list[str] = sudoers_info.sudoer_group_all
        logger.debug(
            "UserManager init: available_commands=%d available_groups=%d sudoers_groups=%s",
            len(self.available_commands),
            len(self.available_groups),
            self.sudoers_groups,
        )

    def _log_choice(self, action: str, choice: str) -> None:
        logger.debug("UserManager %s: %s", action, choice)

    def _has(self, cmd: str) -> bool:
        return cmd in set(self.available_commands or [])

    @staticmethod
    def _sh_quote(s: str) -> str:
        """POSIX-sh safe single-quote escaping"""
        return "'" + s.replace("'", "'\"'\"'") + "'"

    # ============================================================================
    # ATOMIC OPERATIONS
    # ============================================================================

    def add_user(self, username: str) -> str:
        """Create a new user account (no password set)."""
        u = self._sh_quote(username)

        # macOS
        if self._has("dscl"):
            self._log_choice(f"add_user: {u}", "dscl")
            return f"""set -eu
u={u}

# Create user only if missing
if ! dscl . -read "/Users/$u" >/dev/null 2>&1; then
  max_uid="$(dscl . -list /Users UniqueID 2>/dev/null | awk '{{print $2}}' | awk 'BEGIN{{m=500}} {{if($1>m)m=$1}} END{{print m}}')"
  new_uid="$((max_uid + 1))"
  dscl . -create "/Users/$u"
  dscl . -create "/Users/$u" UserShell "/bin/bash"
  dscl . -create "/Users/$u" RealName "$u"
  dscl . -create "/Users/$u" UniqueID "$new_uid"
  dscl . -create "/Users/$u" PrimaryGroupID 20
  dscl . -create "/Users/$u" NFSHomeDirectory "/Users/$u"
  mkdir -p "/Users/$u"
  chown "$u":staff "/Users/$u" || true
fi
"""

        # BSD
        if self._has("pw"):
            self._log_choice(f"add_user: {u}", "pw")
            return f"""set -eu
u={u}

if ! id "$u" >/dev/null 2>&1; then
  pw useradd -n "$u" -m -s /bin/sh
fi
"""

        # Linux
        if self._has("useradd"):
            self._log_choice(f"add_user: {u}", "useradd")
            return f"""set -eu
u={u}
if ! id -u "$u" >/dev/null 2>&1; then
  useradd -m -s /bin/sh "$u"
fi
"""

        if self._has("adduser"):
            self._log_choice(f"add_user: {u}", "adduser")
            return f"""set -eu
u={u}
if ! id -u "$u" >/dev/null 2>&1; then
  adduser -D "$u" 2>/dev/null || adduser --disabled-password --gecos "" "$u"
fi
"""

        self._log_choice(f"add_user: {u}", "no supported tool")
        return f"""set -eu
u={u}
echo "No supported user creation tool found" >&2
exit 1
"""

    def set_user_password(self, username: str, password: str) -> str:
        """Set or change a user's password."""
        u = self._sh_quote(username)
        p = self._sh_quote(password)

        # macOS
        if self._has("dscl"):
            self._log_choice(f"set_user_password: {u}", "dscl")
            return f"""set -eu
u={u}
p={p}

if ! dscl . -read "/Users/$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

dscl . -passwd "/Users/$u" "$p"
"""

        # BSD
        if self._has("pw"):
            self._log_choice(f"set_user_password: {u}", "pw")
            return f"""set -eu
u={u}
p={p}

if ! id "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

printf '%s\\n' "$p" | pw usermod -n "$u" -h 0
"""

        # Linux - prefer chpasswd
        if self._has("chpasswd"):
            self._log_choice(f"set_user_password: {u}", "chpasswd")
            return f"""set -eu
u={u}
p={p}

if ! id -u "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

printf '%s:%s\\n' "$u" "$p" | chpasswd
"""

        if self._has("passwd"):
            self._log_choice(f"set_user_password: {u}", "passwd")
            return f"""set -eu
u={u}
p={p}

if ! id -u "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

printf '%s\\n%s\\n' "$p" "$p" | passwd "$u" >/dev/null
"""

        self._log_choice(f"set_user_password: {u}", "no supported tool")
        return f"""set -eu
u={u}
echo "No supported password tool found" >&2
exit 1
"""

    def add_group(self, groupname: str) -> str:
        """Create a new group."""
        g = self._sh_quote(groupname)

        # macOS
        if self._has("dscl"):
            self._log_choice(f"add_group: {g}", "dscl")
            return f"""set -eu
g={g}

if ! dscl . -read "/Groups/$g" >/dev/null 2>&1; then
  max_gid="$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{{print $2}}' | awk 'BEGIN{{m=500}} {{if($1>m)m=$1}} END{{print m}}')"
  new_gid="$((max_gid + 1))"
  dscl . -create "/Groups/$g"
  dscl . -create "/Groups/$g" PrimaryGroupID "$new_gid"
fi
"""
        # BSD
        if self._has("pw"):
            self._log_choice(f"add_group: {g}", "pw")
            return f"""set -eu
g={g}

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    pw groupadd -n "$g"
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    pw groupadd -n "$g"
  fi
fi
"""
        # Linux
        if self._has("groupadd"):
            self._log_choice(f"add_group: {g}", "groupadd")
            return f"""set -eu
g={g}

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    groupadd "$g"
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    groupadd "$g"
  fi
fi
"""
        if self._has("addgroup"):
            self._log_choice(f"add_group: {g}", "addgroup")
            return f"""set -eu
g={g}

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    addgroup "$g"
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    addgroup "$g"
  fi
fi
"""

        self._log_choice(f"add_group: {g}", "no supported tool")
        return f"""set -eu
g={g}
echo "No supported group creation tool found" >&2
exit 1
"""

    def add_group_to_sudoers(self, groupname: str) -> str:
        """Configure a group to have full sudo access via sudoers.d."""
        g = self._sh_quote(groupname)

        # macOS - admin group is built-in, no need to configure
        if self._has("dscl") or self._has("dseditgroup"):
            if groupname == "admin":
                self._log_choice(
                    f"add_group_to_sudoers: {g}", "macos admin group (noop)"
                )
                return """set -eu
# macOS admin group already has sudo by default
:
"""
            self._log_choice(f"add_group_to_sudoers: {g}", "macos sudoers.d")
            return f"""set -eu
g={g}

# For custom groups on macOS, add to sudoers.d
for d in /etc/sudoers.d /private/etc/sudoers.d; do
  if [ -d "$d" ]; then
    f="$d/$g"
    printf '%%%s ALL=(ALL) ALL\\n' "$g" > "$f"
    chmod 0440 "$f"
    if command -v visudo >/dev/null 2>&1; then
      visudo -cf "$f" >/dev/null
    fi
    exit 0
  fi
done

echo "Could not find sudoers.d directory" >&2
exit 1
"""

        # BSD
        if self._has("pw"):
            self._log_choice(f"add_group_to_sudoers: {g}", "bsd sudoers.d")
            return f"""set -eu
g={g}

for d in /etc/sudoers.d /usr/local/etc/sudoers.d; do
  if [ -d "$d" ]; then
    f="$d/$g"
    printf '%%%s ALL=(ALL) ALL\\n' "$g" > "$f"
    chmod 0440 "$f"
    if command -v visudo >/dev/null 2>&1; then
      visudo -cf "$f" >/dev/null
    fi
    exit 0
  fi
done

echo "Could not find sudoers.d directory" >&2
"""

        # Linux
        self._log_choice(f"add_group_to_sudoers: {g}", "linux sudoers.d")
        return f"""set -eu
g={g}

# Ensure /etc/sudoers.d exists
if [ ! -d /etc/sudoers.d ]; then
  mkdir -p /etc/sudoers.d
  chmod 750 /etc/sudoers.d
fi

# Ensure /etc/sudoers includes /etc/sudoers.d
if ! grep -q "^#includedir /etc/sudoers.d" /etc/sudoers; then
  # Verify we can modify sudoers safely
  cp /etc/sudoers /etc/sudoers.bak
  echo "#includedir /etc/sudoers.d" >> /etc/sudoers
  if command -v visudo >/dev/null 2>&1; then
    if ! visudo -c >/dev/null; then
      echo "Broken sudoers config detected, restoring backup" >&2
      mv /etc/sudoers.bak /etc/sudoers
      exit 1
    fi
  fi
fi

f="/etc/sudoers.d/$g"
printf '%%%s ALL=(ALL) ALL\\n' "$g" > "$f"
chmod 0440 "$f"

if command -v visudo >/dev/null 2>&1; then
  visudo -cf "$f" >/dev/null
fi
"""

    def add_user_to_group(self, username: str, groupname: str) -> str:
        """Add a user to an existing group."""
        u = self._sh_quote(username)
        g = self._sh_quote(groupname)

        # macOS
        if self._has("dseditgroup"):
            self._log_choice(f"add_user_to_group: {u} {g}", "dseditgroup")
            return f"""set -eu
u={u}
g={g}

if dscl . -read "/Users/$u" >/dev/null 2>&1; then
  if dscl . -read "/Groups/$g" >/dev/null 2>&1; then
    dseditgroup -o edit -a "$u" -t user "$g"
  fi
fi
"""
        # BSD
        if self._has("pw"):
            self._log_choice(f"add_user_to_group: {u}", "pw")
            return f"""set -eu
u={u}
g={g}

if ! id "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
fi

pw groupmod "$g" -m "$u"
"""

        # Linux - prefer usermod, then gpasswd, then adduser
        if self._has("usermod"):
            self._log_choice(f"add_user_to_group: {u}", "usermod")
            return f"""set -eu
u={u}
g={g}

if ! id -u "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
fi

usermod -aG "$g" "$u"
"""

        if self._has("gpasswd"):
            self._log_choice(f"add_user_to_group: {u}", "gpasswd")
            return f"""set -eu
u={u}
g={g}

if ! id -u "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
fi

gpasswd -a "$u" "$g"
"""

        if self._has("adduser"):
            self._log_choice(f"add_user_to_group: {u}", "adduser")
            return f"""set -eu
u={u}
g={g}

if ! id -u "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
fi

adduser "$u" "$g"
"""

        self._log_choice(f"add_user_to_group: {u}", "no supported tool")
        return f"""set -eu
u={u}
g={g}
echo "No supported tool to add user to group" >&2
exit 1
"""

    def remove_user_from_group(self, username: str, groupname: str) -> str:
        """Remove a user from a specific group."""
        u = self._sh_quote(username)
        g = self._sh_quote(groupname)

        # macOS
        if self._has("dseditgroup"):
            self._log_choice(f"remove_user_from_group: {u} {g}", "dseditgroup")
            return f"""set -eu
u={u}
g={g}

if ! dscl . -read "/Users/$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

if ! dscl . -read "/Groups/$g" >/dev/null 2>&1; then
  echo "Group $g does not exist" >&2
  exit 1
fi

dseditgroup -o edit -d "$u" -t user "$g" || true
"""

        # BSD
        if self._has("pw"):
            self._log_choice(f"remove_user_from_group: {u} {g}", "pw")
            return f"""set -eu
u={u}
g={g}

if ! id "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    echo "Group $g does not exist" >&2
    exit 1
  fi
fi

pw groupmod "$g" -d "$u" 2>/dev/null || true
"""

        # Linux - prefer gpasswd, then deluser
        if self._has("gpasswd"):
            self._log_choice(f"remove_user_from_group: {u} {g}", "gpasswd")
            return f"""set -eu
u={u}
g={g}

if ! id -u "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
fi

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    echo "Group $g does not exist" >&2
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    echo "Group $g does not exist" >&2
  fi
fi

gpasswd -d "$u" "$g" >/dev/null 2>&1 || true
"""

        if self._has("deluser"):
            self._log_choice(f"remove_user_from_group: {u} {g}", "deluser")
            return f"""set -eu
u={u}
g={g}

if ! id -u "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
  exit 1
fi

if command -v getent >/dev/null 2>&1; then
  if ! getent group "$g" >/dev/null 2>&1; then
    echo "Group $g does not exist" >&2
  fi
else
  if ! grep -q "^$g:" /etc/group 2>/dev/null; then
    echo "Group $g does not exist" >&2
  fi
fi

deluser "$u" "$g" >/dev/null 2>&1 || true
"""

        self._log_choice(f"remove_user_from_group: {u} {g}", "no supported tool")
        return f"""set -eu
u={u}
g={g}
echo "No supported tool to remove user from group" >&2
exit 1
"""

    def kill_user_processes(self, username: str) -> str:
        """Kill all processes owned by a user (except PID 1, and only if UID != 0)."""
        u = self._sh_quote(username)
        self._log_choice(f"kill_user_processes: {u}", "generate script")

        # Common logic for all platforms
        return f"""set -eu
u={u}

# Check if user exists
if ! id "$u" >/dev/null 2>&1; then
  echo "User $u does not exist" >&2
fi

# Get UID and ensure it's not 0 (root)
uid="$(id -u "$u" 2>/dev/null || echo "")"
if [ -z "$uid" ] || [ "$uid" -eq 0 ]; then
  echo "Cannot kill processes for root user (UID 0)" >&2
  exit 1
fi

# Get all PIDs for this user, excluding PID 1
if command -v pgrep >/dev/null 2>&1; then
  pids="$(pgrep -u "$u" 2>/dev/null | grep -v '^1$' || true)"
else
  pids="$(ps -u "$u" -o pid= 2>/dev/null | grep -v '^1$' | tr -d ' ' || true)"
fi

for pid in $pids; do
  echo $pid
  kill -9 "$pid" 2>/dev/null || true
done
    """

    def remove_user(self, username: str) -> str:
        """Remove a user account and home directory (kills processes first if UID != 0)."""
        u = self._sh_quote(username)

        # macOS
        if self._has("dscl"):
            self._log_choice(f"remove_user: {u}", "dscl")
            return f"""set -eu
u={u}

if dscl . -read "/Users/$u" >/dev/null 2>&1; then
  homedir="$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{{print $2}}' || true)"
  dscl . -delete "/Users/$u" || true
  if [ -n "${{homedir:-}}" ] && [ -d "$homedir" ]; then 
    rm -rf "$homedir"
  fi
fi
"""

        # BSD
        if self._has("pw"):
            self._log_choice(f"remove_user: {u}", "pw")
            return f"""set -eu
u={u}

if id "$u" >/dev/null 2>&1; then
  pw userdel -n "$u" -r || pw userdel -n "$u" || true
fi
"""

        # Linux
        if self._has("userdel"):
            self._log_choice(f"remove_user: {u}", "userdel")
            return f"""set -eu
u={u}

if id -u "$u" >/dev/null 2>&1; then
  userdel -r "$u" 2>/dev/null || userdel "$u"
fi
"""

        if self._has("deluser"):
            self._log_choice(f"remove_user: {u}", "deluser")
            return f"""set -eu
u={u}

if id -u "$u" >/dev/null 2>&1; then
  deluser --remove-home "$u" 2>/dev/null || deluser "$u"
fi
"""

        self._log_choice(f"remove_user: {u}", "no supported tool")
        return f"""set -eu
u={u}
echo "No supported user deletion tool found" >&2
exit 1
    """

    def lock_user(self, username: str) -> str:
        """Lock a user account to prevent login."""
        u = self._sh_quote(username)

        # macOS
        if self._has("dscl"):
            self._log_choice(f"lock_user: {u}", "dscl")
            return f"""set -eu
u={u}

if dscl . -read "/Users/$u" >/dev/null 2>&1; then
  dscl . -passwd "/Users/$u" '*' >/dev/null 2>&1 || true
fi
"""

        # BSD
        if self._has("pw"):
            self._log_choice(f"lock_user: {u}", "pw")
            return f"""set -eu
u={u}

if id "$u" >/dev/null 2>&1; then
  pw lock "$u" >/dev/null 2>&1 || true
fi
"""

        # Linux
        if self._has("usermod"):
            self._log_choice(f"lock_user: {u}", "usermod")
            return f"""set -eu
u={u}

if id -u "$u" >/dev/null 2>&1; then
  usermod -L "$u" >/dev/null 2>&1 || true
fi
"""

        if self._has("passwd"):
            self._log_choice(f"lock_user: {u}", "passwd")
            return f"""set -eu
u={u}

if id -u "$u" >/dev/null 2>&1; then
  passwd -l "$u" >/dev/null 2>&1 || true
fi
"""

        self._log_choice(f"lock_user: {u}", "no supported tool")
        return f"""set -eu
u={u}
echo "No supported account lock mechanism found" >&2
exit 1
"""

    def get_users_in_group(self, groupname: str) -> str:
        """Query: print usernames in the specified group (newline-separated)."""
        g = self._sh_quote(groupname)

        # macOS
        if self._has("dscl"):
            self._log_choice(f"get_users_in_group: {g}", "dscl")
            return f"""set -eu
g={g}
dscl . -read "/Groups/$g" GroupMembership 2>/dev/null | sed 's/^GroupMembership: *//' | tr ' ' '\\n' | sed '/^$/d'
"""

        # Prefer getent
        if self._has("getent"):
            self._log_choice(f"get_users_in_group: {g}", "getent")
            return f"""set -eu
g={g}
getent group "$g" | awk -F: '{{print $4}}' | tr ',' '\\n' | sed '/^$/d'
"""

        # BSD
        if self._has("pw"):
            self._log_choice(f"get_users_in_group: {g}", "pw")
            return f"""set -eu
g={g}
pw groupshow "$g" 2>/dev/null | awk -F: '{{print $4}}' | tr ',' '\\n' | sed '/^$/d'
"""

        # Fallback
        self._log_choice(f"get_users_in_group: {g}", "grep /etc/group")
        return f"""set -eu
g={g}
grep -E "^$g:" /etc/group 2>/dev/null | awk -F: '{{print $4}}' | tr ',' '\\n' | sed '/^$/d'
"""

    # ============================================================================
    # CONVENIENCE METHODS (compose atomic operations)
    # ============================================================================

    def add_sudo_user(self, username: str, password: str) -> list[str]:
        """Convenience: Create user, set password, and grant sudo access."""
        output_list = []
        # Select appropriate sudo group
        if "sudo" in self.sudoers_groups:
            grp = "sudo"
        elif "wheel" in self.sudoers_groups:
            grp = "wheel"
        elif "admin" in self.sudoers_groups:
            grp = "admin"
        elif self.sudoers_groups:
            grp = self.sudoers_groups[0]
        else:
            grp = "blue-sudoer"
            add_grp = self.add_group(groupname=grp)
            make_sudoer = self.add_group_to_sudoers(groupname=grp)
            output_list.append(add_grp)
            output_list.append(make_sudoer)

        self._log_choice("add_sudo_user", f"selected group={grp}")
        post_script = f"""set -eu

# Add user
{self.add_user(username)}

# Set password
{self.set_user_password(username, password)}

# Add to sudo group
{self.add_user_to_group(username, grp)}
"""
        output_list.append(post_script)
        return output_list

    def remove_user_from_sudoers(self, username: str) -> str:
        """Convenience: Remove user from all sudo-related groups and sudoers.d entries."""
        u = self._sh_quote(username)
        self._log_choice(
            f"remove_user_from_sudoers: {u}", f"groups={self.sudoers_groups}"
        )

        lines = ["set -eu", f"u={u}", "", "# Remove any sudoers.d drop-in files"]

        # macOS and BSD may have multiple paths
        if self._has("dscl") or self._has("pw"):
            lines.append(
                "for d in /etc/sudoers.d /usr/local/etc/sudoers.d /private/etc/sudoers.d; do"
            )
            lines.append('  [ -d "$d" ] && rm -f "$d/$u" 2>/dev/null || true')
            lines.append("done")
        else:
            lines.append('rm -f "/etc/sudoers.d/$u" 2>/dev/null || true')

        lines.append("")
        lines.append("# Remove from common sudo groups")

        # Remove from all known sudo groups
        for grp in self.sudoers_groups:
            lines.append(f"# Remove from {grp}")
            lines.append(self.remove_user_from_group(username, grp))

        return "\n".join(lines)
