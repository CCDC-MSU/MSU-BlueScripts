#!/bin/sh

# Directory to search (default: /home)
dir=${1:-/home}

is_alpine=0
[ -f /etc/alpine-release ] && is_alpine=1

########################################
# Alpine Linux (BusyBox /bin/sh = ash)
########################################
if [ "$is_alpine" -eq 1 ]; then
  # Prefer pcregrep if installed (apk add pcre2-tools), else fall back to grep -E approximations.
  if command -v pcregrep >/dev/null 2>&1; then
    MODE="pcregrep"
  else
    MODE="ere"
  fi

  # PCRE patterns (used only if pcregrep exists)
  creditCardPCRE='\b(?!000)(?:[0-9][- ]*?){13,19}\b'
  addressPCRE='\b[0-9]+\s\w+\s\w+\b'
  ssnPCRE='\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
  phonePCRE='^(?:\+?[0-9]{1,3}[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'

  # ERE approximations (works with BusyBox grep -E; less accurate than PCRE)
  creditCardERE='([0-9][ -]?){13,19}'
  addressERE='[0-9]+[[:space:]]+[[:alnum:]'"'"'-]+[[:space:]]+[[:alnum:]'"'"'-]+'
  ssnERE='[0-9]{3}-[0-9]{2}-[0-9]{4}'
  phoneERE='^(\+?[0-9]{1,3}[-.[:space:]]?)?(\([0-9]{3}\)|[0-9]{3})[-.[:space:]]?[0-9]{3}[-.[:space:]]?[0-9]{4}$'

  scan_file_alpine() {
    filePath=$1

    if [ "$MODE" = "pcregrep" ]; then
      cc=$(pcregrep -o "$creditCardPCRE" "$filePath" 2>/dev/null)
      if [ -n "$cc" ]; then
        echo "File: $filePath"
        echo "Credit Card Numbers:"
        printf "%s\n" "$cc"
        echo "------------------------"
      fi

      addr=$(pcregrep -o "$addressPCRE" "$filePath" 2>/dev/null)
      if [ -n "$addr" ]; then
        echo "File: $filePath"
        echo "Addresses:"
        printf "%s\n" "$addr"
        echo "------------------------"
      fi

      ssn=$(pcregrep -o "$ssnPCRE" "$filePath" 2>/dev/null)
      if [ -n "$ssn" ]; then
        echo "File: $filePath"
        echo "Social Security Numbers:"
        printf "%s\n" "$ssn"
        echo "------------------------"
      fi

      phone=$(pcregrep -o "$phonePCRE" "$filePath" 2>/dev/null)
      if [ -n "$phone" ]; then
        echo "File: $filePath"
        echo "Phone Numbers:"
        printf "%s\n" "$phone"
        echo "------------------------"
      fi
    else
      # ERE fallback
      cc=$(grep -Eo "$creditCardERE" "$filePath" 2>/dev/null)
      if [ -n "$cc" ]; then
        echo "File: $filePath"
        echo "Credit Card Numbers (approx):"
        printf "%s\n" "$cc"
        echo "------------------------"
      fi

      addr=$(grep -Eo "$addressERE" "$filePath" 2>/dev/null)
      if [ -n "$addr" ]; then
        echo "File: $filePath"
        echo "Addresses (approx):"
        printf "%s\n" "$addr"
        echo "------------------------"
      fi

      ssn=$(grep -Eo "$ssnERE" "$filePath" 2>/dev/null)
      if [ -n "$ssn" ]; then
        echo "File: $filePath"
        echo "Social Security Numbers (approx):"
        printf "%s\n" "$ssn"
        echo "------------------------"
      fi

      phone=$(grep -Eo "$phoneERE" "$filePath" 2>/dev/null)
      if [ -n "$phone" ]; then
        echo "File: $filePath"
        echo "Phone Numbers (approx):"
        printf "%s\n" "$phone"
        echo "------------------------"
      fi
    fi
  }

  # Alpine BusyBox read supports -d, so we can do a NUL-safe loop here.
  find "$dir" -type f -print0 2>/dev/null |
  while IFS= read -r -d '' f; do
    scan_file_alpine "$f"
  done

  exit 0
fi

########################################
# Non-Alpine (assume GNU grep w/ -P/-o)
########################################
find "$dir" -type f -exec sh -c '
  creditCardRegex='\''\b(?!000)(?:[0-9][- ]*?){13,19}\b'\''
  addressRegex='\''\b[0-9]+\s\w+\s\w+\b'\''
  ssnRegex='\''\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'\''
  phoneNumberRegex='\''^(?:\+?[0-9]{1,3}[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'\''

  scan_one() {
    filePath=$1

    cc=$(grep -Po "$creditCardRegex" "$filePath" 2>/dev/null)
    if [ -n "$cc" ]; then
      echo "File: $filePath"
      echo "Credit Card Numbers:"
      printf "%s\n" "$cc"
      echo "------------------------"
    fi

    addr=$(grep -Po "$addressRegex" "$filePath" 2>/dev/null)
    if [ -n "$addr" ]; then
      echo "File: $filePath"
      echo "Addresses:"
      printf "%s\n" "$addr"
      echo "------------------------"
    fi

    ssn=$(grep -Po "$ssnRegex" "$filePath" 2>/dev/null)
    if [ -n "$ssn" ]; then
      echo "File: $filePath"
      echo "Social Security Numbers:"
      printf "%s\n" "$ssn"
      echo "------------------------"
    fi

    phone=$(grep -Po "$phoneNumberRegex" "$filePath" 2>/dev/null)
    if [ -n "$phone" ]; then
      echo "File: $filePath"
      echo "Phone Numbers:"
      printf "%s\n" "$phone"
      echo "------------------------"
    fi
  }

  for f do
    scan_one "$f"
  done
' sh {} + 2>/dev/null
