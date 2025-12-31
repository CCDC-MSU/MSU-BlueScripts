#!/bin/sh
# Archive all users' authorized_keys into /root/ssh/keys/

set -eu

# --- CONFIGURATION ---
# Space-separated list of users to exclude from archiving.
# These accounts will be completely ignored by this script.
SKIP_USERS="root admin deploy"

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

# Helper to check if a user is in the skip list
# Returns 0 (true) if user should be skipped, 1 (false) otherwise.
is_excluded() {
  u="$1"
  # Wrap both the list and the search term in spaces to ensure exact word matching.
  # This is the POSIX way to emulate "array contains".
  case " $SKIP_USERS " in
    *" $u "*) return 0 ;;
    *) return 1 ;;
  esac
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

archive_logic() {
  # Common logic to process a single user found in the loop
  # Arguments: user home
  user="$1"
  home="$2"

  # 1. Basic validity checks
  [ -n "$user" ] || return 0
  [ -d "$home" ] || return 0

  # 2. Check whitelist
  if is_excluded "$user"; then
    echo " > Skipping whitelisted user: $user"
    return 0
  fi

  safe_home="$(printf '%s' "$home" | sed 's,/,_,g; s,^_,,')"

  # Archive authorized_keys
  ak="$home/.ssh/authorized_keys"
  if [ -f "$ak" ]; then
    out="$DEST/${user}__${safe_home}__authorized_keys"
    copy_one "$ak" "$out"
  fi

  # Archive per-user host trust files
  shosts="$home/.ssh/shosts"
  if [ -f "$shosts" ]; then
    out="$DEST/${user}__${safe_home}__shosts"
    copy_one "$shosts" "$out"
  fi

  shosts_equiv="$home/.ssh/shosts.equiv"
  if [ -f "$shosts_equiv" ]; then
    out="$DEST/${user}__${safe_home}__shosts.equiv"
    copy_one "$shosts_equiv" "$out"
  fi
}

archive_alpine() {
  # Alpine users are defined in /etc/passwd (BusyBox-compatible parsing)
  while IFS=: read -r user _ uid gid gecos home shell; do
    archive_logic "$user" "$home"
  done < /etc/passwd
}

archive_non_alpine() {
  # Generic POSIX-ish fallback:
  if command -v getent >/dev/null 2>&1; then
    getent passwd | while IFS=: read -r user _ uid gid gecos home shell; do
      archive_logic "$user" "$home"
    done
  else
    while IFS=: read -r user _ uid gid gecos home shell; do
      archive_logic "$user" "$home"
    done < /etc/passwd
  fi
}

main() {
  ensure_root
  mkdirs

  echo "Starting archive to: $DEST"
  echo "Whitelisted accounts: $SKIP_USERS"

  # Archive legacy SSH trust files (System Wide)
  # NOTE: This affects the whole system. If you need to keep these active
  # even for whitelisted users, comment these lines out.
  if [ -f /etc/hosts.equiv ]; then
    echo "Disabling /etc/hosts.equiv"
    mv /etc/hosts.equiv /etc/hosts.equiv~ 2>/dev/null || true
  fi
  if [ -f /etc/shosts.equiv ]; then
     echo "Disabling /etc/shosts.equiv"
     mv /etc/shosts.equiv /etc/shosts.equiv~ 2>/dev/null || true
  fi

  if is_alpine; then
    echo "Detected Alpine."
    archive_alpine
  else
    echo "Non-Alpine detected."
    archive_non_alpine
  fi

  # Quick summary
  count="$(find "$DEST" -type f 2>/dev/null | wc -l | tr -d ' ')"
  echo "Done. Archived $count file(s) into: $DEST"
}

main "$@"