#!/bin/sh
# Quarantine cron jobs by ARCHIVING then REMOVING/MOVING them so only approved jobs run.
# All stdout is meant to be tee'd to a log.
#
# PRESERVATION: Users/entries starting with "preserveme" are preserved (not quarantined).
#
set -eu

ARCHIVE_BASE="/root/archive/cronjobs"
TS="$(date +%Y%m%d_%H%M%S)"
ARCHIVE_DIR="${ARCHIVE_BASE}/${TS}"
PRESERVE_PREFIX="preserveme"

# Safety: must be root (needed to read/remove other users' crontabs + move /etc cron files)
if [ "$(id -u)" != "0" ]; then
  echo "[ERROR] Must run as root."
  exit 1
fi

umask 077

echo "[INFO] Creating archive directory: ${ARCHIVE_DIR}"
mkdir -p "${ARCHIVE_DIR}/user-crontabs"
mkdir -p "${ARCHIVE_DIR}/system"

echo
echo "================ RESTORE GUIDE (will repeat at end) ================"
echo "[RESTORE] User crontabs: crontab -u <user> '${ARCHIVE_DIR}/user-crontabs/<user>.crontab'"
echo "[RESTORE] System cron jobs: move files back from '${ARCHIVE_DIR}/system' to their original paths."
echo "===================================================================="
echo

###############################################################################
# Helper: Check if a crontab-style file contains any entries for preserveme* users
# Returns 0 (true) if preserveme* entries found, 1 (false) otherwise
###############################################################################
file_has_preserved_user() {
  _file="$1"
  [ -f "$_file" ] || return 1
  # Parse crontab format: skip comments, empty lines, and variable assignments
  # Check if 6th field (user) starts with preserve prefix
  awk -v prefix="$PRESERVE_PREFIX" '
    /^[[:space:]]*#/                    { next }  # skip comments
    /^[[:space:]]*$/                    { next }  # skip empty lines
    /^[[:space:]]*[A-Za-z_][A-Za-z_0-9]*=/ { next }  # skip VAR=value
    {
      # Standard cron entry: min hour dom month dow user command
      if (NF >= 6) {
        user = $6
        if (substr(user, 1, length(prefix)) == prefix) {
          found = 1
          exit
        }
      }
    }
    END { exit (found ? 0 : 1) }
  ' "$_file"
}

###############################################################################
# Helper: Check if username starts with preserved prefix
###############################################################################
is_preserved_user() {
  _user="$1"
  case "$_user" in
    ${PRESERVE_PREFIX}*) return 0 ;;
    *) return 1 ;;
  esac
}

###############################################################################
# 1) Archive + remove user crontabs (portable approach: use crontab command)
#    SKIP users whose name starts with preserveme
###############################################################################
echo "[INFO] Archiving and removing user crontabs found via /etc/passwd"
echo "[INFO] Preserving crontabs for users starting with '${PRESERVE_PREFIX}'"

# Read /etc/passwd; first field is username
while IFS=: read -r user _rest; do
  # Skip preserved users
  if is_preserved_user "$user"; then
    echo "[PRESERVE] Skipping user crontab for preserved user: $user"
    continue
  fi

  tmp="${ARCHIVE_DIR}/user-crontabs/.tmp.${user}"
  # If user has a crontab, archive it
  if crontab -l -u "$user" > "$tmp" 2>/dev/null; then
    if [ -s "$tmp" ]; then
      dest="${ARCHIVE_DIR}/user-crontabs/${user}.crontab"
      mv "$tmp" "$dest"
      echo "[MOVE] Archived user crontab: $user -> $dest"
      # Remove the user's crontab so it no longer runs
      if crontab -r -u "$user" 2>/dev/null; then
        echo "[REMOVE] Removed active user crontab for: $user"
        echo "[RESTORE] To restore $user: crontab -u '$user' '$dest'"
      else
        echo "[WARN] Could not remove crontab for $user (maybe none / permissions)."
      fi
    else
      # empty listing; clean up temp
      rm -f "$tmp"
    fi
  else
    # no crontab or not readable
    rm -f "$tmp" 2>/dev/null || true
  fi
done < /etc/passwd

echo

###############################################################################
# 2) Move system-wide cron jobs (move contents of cron.* dirs; move crontab files)
###############################################################################

# Move contents of a cron directory (for cron.daily, cron.hourly, etc.)
# These scripts don't have user fields, so move all of them.
move_dir_contents() {
  src="$1"
  if [ -d "$src" ]; then
    dest="${ARCHIVE_DIR}/system${src}"
    echo "[INFO] Quarantining contents of directory: $src -> $dest"
    mkdir -p "$dest"
    # Move all entries in the directory (leave the directory itself in place)
    for f in "$src"/*; do
      [ -e "$f" ] || continue
      mv "$f" "$dest"/
      echo "[MOVE] $f -> $dest/"
      echo "[RESTORE] mv '$dest/$(basename "$f")' '$src/'"
    done
  else
    echo "[SKIP] Directory not found: $src"
  fi
}

# Move contents of /etc/cron.d, but SKIP files that contain preserveme* user entries
move_cron_d_contents() {
  src="$1"
  if [ -d "$src" ]; then
    dest="${ARCHIVE_DIR}/system${src}"
    echo "[INFO] Quarantining contents of directory: $src -> $dest"
    echo "[INFO] (Skipping files with entries for '${PRESERVE_PREFIX}*' users)"
    mkdir -p "$dest"
    for f in "$src"/*; do
      [ -e "$f" ] || continue
      [ -f "$f" ] || continue  # only process regular files
      if file_has_preserved_user "$f"; then
        echo "[PRESERVE] Skipping $f (contains entries for '${PRESERVE_PREFIX}*' user)"
        echo "[WARNING] File $f was NOT quarantined because it contains preserved user entries."
        echo "[WARNING] Other entries in this file will continue to run!"
      else
        mv "$f" "$dest"/
        echo "[MOVE] $f -> $dest/"
        echo "[RESTORE] mv '$dest/$(basename "$f")' '$src/'"
      fi
    done
  else
    echo "[SKIP] Directory not found: $src"
  fi
}

# Move a crontab-style file, but SKIP if it contains preserveme* user entries
move_crontab_file() {
  src="$1"
  if [ -f "$src" ]; then
    if file_has_preserved_user "$src"; then
      echo "[PRESERVE] Skipping $src (contains entries for '${PRESERVE_PREFIX}*' user)"
      echo "[WARNING] File $src was NOT quarantined because it contains preserved user entries."
      echo "[WARNING] Other entries in this file will continue to run!"
    else
      dest="${ARCHIVE_DIR}/system${src}"
      echo "[INFO] Quarantining file: $src -> $dest"
      mkdir -p "$(dirname "$dest")"
      mv "$src" "$dest"
      echo "[MOVE] $src -> $dest"
      echo "[RESTORE] mv '$dest' '$src'"
    fi
  else
    echo "[SKIP] File not found: $src"
  fi
}

# Move a non-crontab file unconditionally (e.g., anacrontab which has different format)
move_file() {
  src="$1"
  if [ -f "$src" ]; then
    dest="${ARCHIVE_DIR}/system${src}"
    echo "[INFO] Quarantining file: $src -> $dest"
    mkdir -p "$(dirname "$dest")"
    mv "$src" "$dest"
    echo "[MOVE] $src -> $dest"
    echo "[RESTORE] mv '$dest' '$src'"
  else
    echo "[SKIP] File not found: $src"
  fi
}

# /etc/cron.d - uses crontab format with user field; check for preserved users
move_cron_d_contents /etc/cron.d

# Directories without user fields: move all contents
move_dir_contents /etc/cron.daily
move_dir_contents /etc/cron.hourly
move_dir_contents /etc/cron.weekly
move_dir_contents /etc/cron.monthly

# /etc/crontab - uses crontab format with user field; check for preserved users
move_crontab_file /etc/crontab
if [ ! -f /etc/crontab ]; then
  echo "[INFO] Writing minimal /etc/crontab placeholder (no jobs)."
  cat > /etc/crontab <<EOF
# /etc/crontab quarantined by script on ${TS}
# Original moved to: ${ARCHIVE_DIR}/system/etc/crontab
# Restore with:
#   mv '${ARCHIVE_DIR}/system/etc/crontab' /etc/crontab
#
# This placeholder intentionally contains no scheduled jobs.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
EOF
fi

# /etc/anacrontab - different format (no user field in standard anacrontab)
move_file /etc/anacrontab
if [ ! -f /etc/anacrontab ]; then
  echo "[INFO] Writing minimal /etc/anacrontab placeholder (no jobs)."
  cat > /etc/anacrontab <<EOF
# /etc/anacrontab quarantined by script on ${TS}
# Original moved to: ${ARCHIVE_DIR}/system/etc/anacrontab
# Restore with:
#   mv '${ARCHIVE_DIR}/system/etc/anacrontab' /etc/anacrontab
#
# This placeholder intentionally contains no scheduled jobs.
EOF
fi

echo
echo "=========================== SUMMARY ==========================="
echo "[DONE] Cron jobs quarantined."
echo "[ARCHIVE] ${ARCHIVE_DIR}"
echo
echo "[NOTE] Users/files starting with '${PRESERVE_PREFIX}' were preserved."
echo
echo "[RESTORE] User crontabs:"
echo "          crontab -u <user> '${ARCHIVE_DIR}/user-crontabs/<user>.crontab'"
echo
echo "[RESTORE] System cron jobs:"
echo "          Move files back from '${ARCHIVE_DIR}/system' to their original paths."
echo "==============================================================="