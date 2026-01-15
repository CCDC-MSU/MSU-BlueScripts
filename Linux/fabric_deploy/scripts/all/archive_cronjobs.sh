#!/bin/sh
# Quarantine cron jobs by ARCHIVING then REMOVING/MOVING them so only approved jobs run.
# All stdout is meant to be tee'd to a log.

set -eu

ARCHIVE_BASE="/root/archive/cronjobs"
TS="$(date +%Y%m%d_%H%M%S)"
ARCHIVE_DIR="${ARCHIVE_BASE}/${TS}"

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
# 1) Archive + remove user crontabs (portable approach: use crontab command)
###############################################################################
echo "[INFO] Archiving and removing user crontabs found via /etc/passwd"

# Read /etc/passwd; first field is username
while IFS=: read -r user _rest
do
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

# Directories: move their contents (so cron doesn't error on missing dirs)
move_dir_contents /etc/cron.d
move_dir_contents /etc/cron.daily
move_dir_contents /etc/cron.hourly
move_dir_contents /etc/cron.weekly
move_dir_contents /etc/cron.monthly

# Files: move them, then replace with safe minimal placeholders (so cron/anacron don't break)
move_file /etc/crontab
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
echo "[RESTORE] User crontabs:"
echo "          crontab -u <user> '${ARCHIVE_DIR}/user-crontabs/<user>.crontab'"
echo
echo "[RESTORE] System cron jobs:"
echo "          Move files back from '${ARCHIVE_DIR}/system' to their original paths."
echo "==============================================================="
