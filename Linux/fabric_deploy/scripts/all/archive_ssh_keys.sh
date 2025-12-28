#!/bin/sh
# Archive all users' authorized_keys into /root/ssh/keys/

set -eu

DEST_BASE="/root/ssh/keys"
TS="$(date +%Y%m%d_%H%M%S)"
DEST="$DEST_BASE/$TS"

is_alpine() {
  [ -f /etc/alpine-release ] || grep -qi '^ID=alpine' /etc/os-release 2>/dev/null
}

ensure_root() {
  if [ "$(id -u)" != "0" ]; then
    echo "Error: run as root." >&2
    exit 1
  fi
}

mkdirs() {
  mkdir -p "$DEST"
  chmod 700 "$DEST_BASE" 2>/dev/null || true
  chmod 700 "$DEST" 2>/dev/null || true
}

copy_one() {
  src="$1"
  out="$2"

  # preserve content, set restrictive perms
  cp -f "$src" "$out"
  chmod 600 "$out" 2>/dev/null || true
}

archive_alpine() {
  # Alpine users are defined in /etc/passwd (BusyBox-compatible parsing)
  # Include only real accounts with an existing home dir.
  while IFS=: read -r user _ uid gid gecos home shell; do
    [ -n "$user" ] || continue
    [ -d "$home" ] || continue

    ak="$home/.ssh/authorized_keys"
    if [ -f "$ak" ]; then
      safe_home="$(printf '%s' "$home" | sed 's,/,_,g; s,^_,,')"
      out="$DEST/${user}__${safe_home}__authorized_keys"
      copy_one "$ak" "$out"
    fi
  done < /etc/passwd
}

archive_non_alpine() {
  # Generic POSIX-ish fallback:
  # Try to use getent if available; otherwise read /etc/passwd.
  if command -v getent >/dev/null 2>&1; then
    getent passwd | while IFS=: read -r user _ uid gid gecos home shell; do
      [ -n "$user" ] || continue
      [ -d "$home" ] || continue
      ak="$home/.ssh/authorized_keys"
      if [ -f "$ak" ]; then
        safe_home="$(printf '%s' "$home" | sed 's,/,_,g; s,^_,,')"
        out="$DEST/${user}__${safe_home}__authorized_keys"
        copy_one "$ak" "$out"
      fi
    done
  else
    while IFS=: read -r user _ uid gid gecos home shell; do
      [ -n "$user" ] || continue
      [ -d "$home" ] || continue
      ak="$home/.ssh/authorized_keys"
      if [ -f "$ak" ]; then
        safe_home="$(printf '%s' "$home" | sed 's,/,_,g; s,^_,,')"
        out="$DEST/${user}__${safe_home}__authorized_keys"
        copy_one "$ak" "$out"
      fi
    done < /etc/passwd
  fi
}

main() {
  ensure_root
  mkdirs

  # Archive legacy SSH trust files (considered security risks)
  test -f /etc/hosts.equiv && mv /etc/hosts.equiv /etc/hosts.equiv~ &> /dev/null
  test -f /etc/shosts.equiv && mv /etc/shosts.equiv /etc/shosts.equiv~ &> /dev/null

  if is_alpine; then
    echo "Detected Alpine: archiving authorized_keys to $DEST"
    archive_alpine
  else
    echo "Non-Alpine detected: archiving authorized_keys to $DEST"
    archive_non_alpine
  fi

  # Quick summary
  count="$(find "$DEST" -type f 2>/dev/null | wc -l | tr -d ' ')"
  echo "Done. Archived $count file(s) into: $DEST"
}

main "$@"