#!/bin/sh

# This script could be easily modified to check for any strings in binaries.

# for all binaries larger than 1MB, check if they contain go1.
sudo find / -type f -executable -size +1M \
  ! -path '*snap*' ! -path '*container*' ! -path '*docker*' \
  -exec sh -c '
    for i do
      if strings "$i" 2>/dev/null | grep -q "go1\."
      then
        echo "Detected GO Binary : $i"
      fi
    done
  ' sh {} + 2>/dev/null

# if last exit code is not 0 try this (mainly to handle alpine)
if [ $? -ne 0 ]; then
  # Use sudo if available (Alpine often doesn't have it by default)
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    SUDO=""
  fi

  # BusyBox-friendly:
  # - executable test via perms (any of u/g/o execute bit set)
  # - size > 1 MiB via +1024k
  $SUDO find / -type f \
    \( -perm -001 -o -perm -010 -o -perm -100 \) \
    -size +1024k \
    ! -path '*snap*' ! -path '*container*' ! -path '*docker*' \
    -exec sh -c '
      for i do
        if strings "$i" 2>/dev/null | grep -q "go1\."; then
          echo "Detected GO Binary : $i"
        fi
      done
    ' sh {} \; 2>/dev/null
fi
