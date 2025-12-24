from typing import List, Optional
from .models import SudoersInfo

# This class exports 4 commands to manage users, all based on installed commands
# add_user(self, username: str, password: str) -> str:
# add_sudo_user(self, username: str, password: str) -> str:
# remove_user(self, username: str) -> str:
# def remove_user_from_sudoers(self, username: str) -> str:
# def lock_user(self, username: str) -> str:
class UserManager:
    def __init__(self, available_commands: list[str], groups: list[str], sudoers_info: SudoersInfo):
        self.available_commands = list(available_commands or [])
        self.available_groups = list(groups or [])

        self.sudoers_groups :list[str] = sudoers_info.sudoer_group_all  # this is a list of groups mentioned in sudoers config and can run all commands
        
        # If sudoers parsing finds no "full sudo" groups, fall back to a known group name
        # and expose a bootstrap command to create/configure it.
        self.fallback_sudoers_group: Optional[str] = None
        self.sudoers_bootstrap_cmd: str = ""

        if not self.sudoers_groups:
            self.fallback_sudoers_group = "blue-sudoers"
            self.sudoers_groups = [self.fallback_sudoers_group]

            # Caller can run this once (as root) to create the group + grant sudo via sudoers.d
            self.sudoers_bootstrap_cmd = self._bootstrap_sudoers_group_cmd(self.fallback_sudoers_group)

    def _has(self, cmd: str) -> bool:
        return cmd in set(self.available_commands or [])

    @staticmethod
    def _sh_quote(s: str) -> str:
        # POSIX-sh safe single-quote escaping
        return "'" + s.replace("'", "'\"'\"'") + "'"

    def _bootstrap_sudoers_group_cmd(self, group: str) -> str:
        """
        Return a sh-compatible command that:
          1) ensures GROUP exists
          2) grants GROUP full sudo via sudoers.d (preferred)
        """
        g = self._sh_quote(group)

        # macOS: add_sudo_user should use built-in 'admin'; no need to bootstrap a custom group.
        if self._has("dscl") or self._has("dseditgroup"):
            return f"""set -eu
g={g}
# macOS: no-op (use 'admin' group in add_sudo_user)
:
"""

        # BSD: pw for group, common sudoers.d paths
        if self._has("pw"):
            return f"""set -eu
g={g}

# Ensure group exists
if command -v getent >/dev/null 2>&1; then
  getent group "$g" >/dev/null 2>&1 || pw groupadd -n "$g" || true
else
  grep -q "^$g:" /etc/group 2>/dev/null || pw groupadd -n "$g" || true
fi

# Configure sudoers.d for the group (try common paths)
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

echo "Could not find a sudoers.d directory to configure group $g" >&2
exit 1
"""

        # Linux/BusyBox: groupadd/addgroup + /etc/sudoers.d
        ensure_group = r'''if command -v getent >/dev/null 2>&1; then
  getent group "$g" >/dev/null 2>&1 && exit 0
else
  grep -q "^$g:" /etc/group 2>/dev/null && exit 0
fi

if command -v groupadd >/dev/null 2>&1; then
  groupadd "$g" 2>/dev/null || true
elif command -v addgroup >/dev/null 2>&1; then
  addgroup "$g" 2>/dev/null || true
else
  echo "No supported group creation tool (groupadd/addgroup) found" >&2
  exit 1
fi
'''
        return f"""set -eu
g={g}

{ensure_group}

if [ -d /etc/sudoers.d ]; then
  f="/etc/sudoers.d/$g"
  printf '%%%s ALL=(ALL) ALL\\n' "$g" > "$f"
  chmod 0440 "$f"
  if command -v visudo >/dev/null 2>&1; then
    visudo -cf "$f" >/dev/null
  fi
else
  echo "/etc/sudoers.d not found; cannot configure sudoers for group $g" >&2
  exit 1
fi
"""

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
        u = self._sh_quote(username)  # uname
        p = self._sh_quote(password)  # passwd
        # select correct group
        if "sudo" in self.sudoers_groups:
            grp = "sudo"
        elif "wheel" in self.sudoers_groups:
            grp = "wheel"
        else:
            grp = self.sudoers_groups[0]

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
grp={grp}

# ensure user exists + password set
{self.add_user(username, password)}

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
grp={grp}

# ensure user exists + password set
{self.add_user(username, password)}

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
        # todo: fix to remove the user from all sudoers_groups
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

    def lock_user(self, username: str) -> str:
        """Return a sh-compatible command that locks a user account (best-effort, cross-platform)."""
        u = self._sh_quote(username)

        # macOS: disable password login by setting an invalid password hash marker
        # (macOS doesn't have a single universal "lock" primitive; this is best-effort.)
        if self._has("dscl"):
            return f"""set -eu
    u={u}

    # If user doesn't exist, succeed (idempotent)
    dscl . -read "/Users/$u" >/dev/null 2>&1 || exit 0

    # Set password to a value that prevents interactive login
    # '*' is commonly used as a disabled marker in some setups; if this fails, we still exit 0.
    dscl . -passwd "/Users/$u" '*' >/dev/null 2>&1 || true
    """

        # BSD: pw lock
        if self._has("pw"):
            return f"""set -eu
    u={u}
    id "$u" >/dev/null 2>&1 || exit 0
    pw lock "$u" >/dev/null 2>&1 || true
    """

        # Linux: prefer usermod/passwd if present
        if self._has("usermod"):
            return f"""set -eu
    u={u}
    id -u "$u" >/dev/null 2>&1 || exit 0
    usermod -L "$u" >/dev/null 2>&1 || true
    """
        if self._has("passwd"):
            return f"""set -eu
    u={u}
    id -u "$u" >/dev/null 2>&1 || exit 0
    passwd -l "$u" >/dev/null 2>&1 || true
    """

        # Last resort: no supported lock mechanism discovered
        return f"""set -eu
    u={u}
    echo "No supported account lock mechanism found for $u" >&2
    exit 1
    """

