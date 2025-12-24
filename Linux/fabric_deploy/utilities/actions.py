from typing import List

# This class exports 4 commands to manage users, all based on installed commands
# add_user(self, username: str, password: str) -> str:
# add_sudo_user(self, username: str, password: str) -> str:
# remove_user(self, username: str) -> str:
# def remove_user_from_sudoers(self, username: str) -> str:

class UserManager:
    def __init__(self, available_commands :list[str]):
        self.available_commands = available_commands
        
    def _has(self, cmd: str) -> bool:
        return cmd in set(self.available_commands or [])

    @staticmethod
    def _sh_quote(s: str) -> str:
        # POSIX-sh safe single-quote escaping
        return "'" + s.replace("'", "'\"'\"'") + "'"

    def add_user(self, username: str, password: str) -> str:
        """Return a sh-compatible command that adds a new regular user and sets its password."""
        u = self._sh_quote(username)
        p = self._sh_quote(password)

        # macOS
        if self._has("dscl"):
            # Create local user with next available UID, default group 20 (staff), and home dir
            return f"""set -eu
u={u}
p={p}

# Create user only if missing
if dscl . -read "/Users/$u" >/dev/null 2>&1; then
  :
else
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

# Set password
dscl . -passwd "/Users/$u" "$p"
"""

        # FreeBSD / BSD
        if self._has("pw"):
            # pw(8) can read password from stdin with -h 0
            return f"""set -eu
u={u}
p={p}

if id "$u" >/dev/null 2>&1; then
  :
else
  # create user with home dir
  pw useradd -n "$u" -m -s /bin/sh
fi

# set password (stdin)
printf '%s\\n' "$p" | pw usermod -n "$u" -h 0
"""

        # Linux / BusyBox / general
        # Prefer shadow-utils if available
        if self._has("useradd"):
            add_cmd = """id -u "$u" >/dev/null 2>&1 || useradd -m -s /bin/sh "$u" """
        elif self._has("adduser"):
            # Works for BusyBox (adduser -D) and Debian/Ubuntu (adduser --disabled-password)
            add_cmd = """id -u "$u" >/dev/null 2>&1 || (adduser -D "$u" 2>/dev/null || adduser --disabled-password --gecos "" "$u")"""
        else:
            # last-resort minimal local account creation (Linux-style files); risky, but better than nothing
            add_cmd = """id -u "$u" >/dev/null 2>&1 || (echo "No supported user creation tool found" >&2; exit 1)"""

        # Password setting
        if self._has("chpasswd"):
            pass_cmd = """printf '%s:%s\\n' "$u" "$p" | chpasswd"""
        elif self._has("passwd"):
            # Not universal, but works on many (including lots of BusyBox builds)
            pass_cmd = """printf '%s\\n%s\\n' "$p" "$p" | passwd "$u" >/dev/null"""
        else:
            pass_cmd = """echo "No supported password tool found" >&2; exit 1"""

        return f"""set -eu
u={u}
p={p}

{add_cmd}
{pass_cmd}
"""

    def add_sudo_user(self, username: str, password: str) -> str:
        """Return a sh-compatible command that adds a user, sets password, and grants sudo/admin."""
        u = self._sh_quote(username)
        p = self._sh_quote(password)

        # macOS: add to admin group
        if self._has("dscl") and self._has("dseditgroup"):
            return f"""set -eu
u={u}
p={p}

# ensure user exists + password set
{self.add_user(username, password)}

# grant admin
dseditgroup -o edit -a "$u" -t user admin
"""

        # BSD: wheel is typical, but we’ll probe
        if self._has("pw"):
            return f"""set -eu
u={u}
p={p}

# ensure user exists + password set
{self.add_user(username, password)}

# Determine sudo-equivalent group (prefer wheel, else sudo if present)
grp=""
if command -v getent >/dev/null 2>&1; then
  if getent group wheel >/dev/null 2>&1; then grp="wheel"; fi
  if [ -z "$grp" ] && getent group sudo >/dev/null 2>&1; then grp="sudo"; fi
else
  if grep -q '^wheel:' /etc/group 2>/dev/null; then grp="wheel"; fi
  if [ -z "$grp" ] && grep -q '^sudo:' /etc/group 2>/dev/null; then grp="sudo"; fi
fi

if [ -n "$grp" ]; then
  pw groupmod "$grp" -m "$u" || true
else
  # Fallback: sudoers.d drop-in if sudo is installed and includedir exists
  if [ -d /usr/local/etc/sudoers.d ] && command -v visudo >/dev/null 2>&1; then
    f="/usr/local/etc/sudoers.d/$u"
    printf '%s ALL=(ALL) ALL\\n' "$u" > "$f"
    chmod 0440 "$f"
    visudo -cf "$f"
  fi
fi
"""

        # Linux: add user, then grant via group if it exists; else sudoers.d drop-in
        # Pick best tool for adding to groups: usermod, gpasswd, adduser
        if self._has("usermod"):
            group_add = """usermod -aG "$grp" "$u" """
        elif self._has("gpasswd"):
            group_add = """gpasswd -a "$u" "$grp" """
        elif self._has("adduser"):
            # Debian style: adduser USER GROUP
            group_add = """adduser "$u" "$grp" """
        else:
            group_add = """echo "No supported tool to add user to groups" >&2; exit 1"""

        sudoers_dir = "/etc/sudoers.d"

        visudo_check = "command -v visudo >/dev/null 2>&1"

        return f"""set -eu
u={u}
p={p}

# ensure user exists + password set
{self.add_user(username, password)}

# Determine sudo-equivalent group (prefer sudo, else wheel)
grp=""
if command -v getent >/dev/null 2>&1; then
  if getent group sudo >/dev/null 2>&1; then grp="sudo"; fi
  if [ -z "$grp" ] && getent group wheel >/dev/null 2>&1; then grp="wheel"; fi
else
  if grep -q '^sudo:' /etc/group 2>/dev/null; then grp="sudo"; fi
  if [ -z "$grp" ] && grep -q '^wheel:' /etc/group 2>/dev/null; then grp="wheel"; fi
fi

if [ -n "$grp" ]; then
  {group_add} || true
else
  # Fallback: sudoers.d entry if possible
  if [ -d {sudoers_dir} ] && {visudo_check}; then
    f="{sudoers_dir}/$u"
    printf '%s ALL=(ALL) ALL\\n' "$u" > "$f"
    chmod 0440 "$f"
    visudo -cf "$f"
  else
    echo "No sudo/wheel group found and no sudoers.d+visudo available" >&2
    exit 1
  fi
fi
"""

    def remove_user(self, username: str) -> str:
        """Return a sh-compatible command that removes a user account (and home if supported)."""
        u = self._sh_quote(username)

        # macOS
        if self._has("dscl"):
            return f"""set -eu
u={u}

if dscl . -read "/Users/$u" >/dev/null 2>&1; then
  homedir="$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{{print $2}}' || true)"
  dscl . -delete "/Users/$u" || true
  if [ -n "${{homedir:-}}" ] && [ -d "$homedir" ]; then rm -rf "$homedir"; fi
fi
"""

        # BSD
        if self._has("pw"):
            return f"""set -eu
u={u}

if id "$u" >/dev/null 2>&1; then
  pw userdel -n "$u" -r || pw userdel -n "$u" || true
fi
"""

        # Linux
        if self._has("userdel"):
            return f"""set -eu
u={u}
id -u "$u" >/dev/null 2>&1 || exit 0
userdel -r "$u" || userdel "$u"
"""
        if self._has("deluser"):
            return f"""set -eu
u={u}
id -u "$u" >/dev/null 2>&1 || exit 0
deluser --remove-home "$u" 2>/dev/null || deluser "$u"
"""
        if self._has("deluser"):  # kept for clarity; above handles
            return f"""set -eu
u={u}
id -u "$u" >/dev/null 2>&1 || exit 0
deluser "$u"
"""
        if self._has("deluser") is False and self._has("adduser") and self._has("busybox"):
            return f"""set -eu
u={u}
id -u "$u" >/dev/null 2>&1 || exit 0
deluser "$u" || true
"""
        # Last-resort
        return f"""set -eu
u={u}
echo "No supported user deletion tool found for $u" >&2
exit 1
"""

    def remove_user_from_sudoers(self, username: str) -> str:
        """Return a sh-compatible command that removes sudo/admin access for a user."""
        u = self._sh_quote(username)

        # macOS: remove from admin group
        if self._has("dseditgroup"):
            return f"""set -eu
u={u}
dseditgroup -o edit -d "$u" -t user admin || true
"""

        # BSD: try wheel/sudo group, then sudoers.d
        if self._has("pw"):
            return f"""set -eu
u={u}

# Remove sudoers.d drop-in if present (common paths)
rm -f "/usr/local/etc/sudoers.d/$u" "/etc/sudoers.d/$u" 2>/dev/null || true

# Remove from wheel/sudo groups if they exist
for grp in wheel sudo; do
  if command -v getent >/dev/null 2>&1; then
    getent group "$grp" >/dev/null 2>&1 || continue
  else
    grep -q "^$grp:" /etc/group 2>/dev/null || continue
  fi
  pw groupmod "$grp" -d "$u" 2>/dev/null || true
done
"""

        # Linux: prefer gpasswd/deluser, else usermod recalculation is messy; also remove sudoers.d entry
        lines = [f"set -eu", f"u={u}", "", "rm -f \"/etc/sudoers.d/$u\" 2>/dev/null || true", ""]

        # group removals
        if self._has("gpasswd"):
            lines.append('for grp in sudo wheel; do')
            lines.append('  if command -v getent >/dev/null 2>&1; then')
            lines.append('    getent group "$grp" >/dev/null 2>&1 || continue')
            lines.append('  else')
            lines.append('    grep -q "^$grp:" /etc/group 2>/dev/null || continue')
            lines.append('  fi')
            lines.append('  gpasswd -d "$u" "$grp" >/dev/null 2>&1 || true')
            lines.append('done')
        elif self._has("deluser"):
            lines.append('for grp in sudo wheel; do')
            lines.append('  if command -v getent >/dev/null 2>&1; then')
            lines.append('    getent group "$grp" >/dev/null 2>&1 || continue')
            lines.append('  else')
            lines.append('    grep -q "^$grp:" /etc/group 2>/dev/null || continue')
            lines.append('  fi')
            lines.append('  deluser "$u" "$grp" >/dev/null 2>&1 || true')
            lines.append('done')
        else:
            # best-effort: if usermod exists we can attempt "gpasswd -d" alternative not available.
            lines.append('echo "No supported group removal tool (gpasswd/deluser) found; only removed sudoers.d drop-in." >&2')

        return "\n".join(lines) + "\n"

    def get_users_in_group(self, groupname: str) -> str:
        """Return a sh-compatible command that prints usernames in the specified group (newline-separated)."""
        g = self._sh_quote(groupname)

        # macOS
        if self._has("dscl"):
            return f"""set -eu
g={g}
dscl . -read "/Groups/$g" GroupMembership 2>/dev/null | sed 's/^GroupMembership: *//' | tr ' ' '\\n' | sed '/^$/d'
"""

        # Prefer getent on Unix-like
        if self._has("getent"):
            # Note: prints supplemental members listed in group entry.
            return f"""set -eu
g={g}
getent group "$g" | awk -F: '{{print $4}}' | tr ',' '\\n' | sed '/^$/d'
"""

        # BSD pw groupshow can output group members similarly (if present)
        if self._has("pw"):
            return f"""set -eu
g={g}
pw groupshow "$g" 2>/dev/null | awk -F: '{{print $4}}' | tr ',' '\\n' | sed '/^$/d'
"""

        # Fallback to /etc/group
        return f"""set -eu
g={g}
grep -E "^$g:" /etc/group 2>/dev/null | awk -F: '{{print $4}}' | tr ',' '\\n' | sed '/^$/d'
"""

