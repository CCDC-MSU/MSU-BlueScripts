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
# Non-Alpine / Generic (Linux, BSD, etc.)
########################################

# 1. Define Patterns

# PCRE Patterns (Best Accuracy)
export PCRE_CC='\b(?!000)(?:[0-9][- ]*?){13,19}\b'
export PCRE_ADDR='\b[0-9]+\s\w+\s\w+\b'
export PCRE_SSN='\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
export PCRE_PHONE='^(?:\+?[0-9]{1,3}[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'

# ERE Patterns (Fallback)
# Note: Single quotes in ERE need careful handling if passed around, but env vars help.
# Pattern: Alphanumeric, single quote, or dash.
export ERE_CC='([0-9][ -]?){13,19}'
export ERE_ADDR='[0-9]+[[:space:]]+[[:alnum:]'\''-]+[[:space:]]+[[:alnum:]'\''-]+'
export ERE_SSN='[0-9]{3}-[0-9]{2}-[0-9]{4}'
export ERE_PHONE='^(\+?[0-9]{1,3}[-.[:space:]]?)?(\([0-9]{3}\)|[0-9]{3})[-.[:space:]]?[0-9]{3}[-.[:space:]]?[0-9]{4}$'

# 2. Select Search Method

if echo | grep -P "" >/dev/null 2>&1; then
    # GNU Grep (Linux standard)
    export SEARCH_CMD="grep -Po"
    export SEARCH_TYPE="PCRE"
elif command -v pcregrep >/dev/null 2>&1; then
    # PCRE Grep (Common on BSDs/Hardened systems)
    export SEARCH_CMD="pcregrep -o"
    export SEARCH_TYPE="PCRE"
else
    # Standard POSIX/BSD Grep (ERE)
    export SEARCH_CMD="grep -Eo"
    export SEARCH_TYPE="ERE"
fi

# 3. Execution

# We use find with -exec sh -c.
# Variables exported above are inherited by the subshell.
find "$dir" -type f -exec sh -c '
    # Select specific regex variables based on detected type
    if [ "$SEARCH_TYPE" = "PCRE" ]; then
        RE_CC="$PCRE_CC"
        RE_ADDR="$PCRE_ADDR"
        RE_SSN="$PCRE_SSN"
        RE_PHONE="$PCRE_PHONE"
    else
        RE_CC="$ERE_CC"
        RE_ADDR="$ERE_ADDR"
        RE_SSN="$ERE_SSN"
        RE_PHONE="$ERE_PHONE"
    fi

    # Helper function to scan a single file
    scan_one() {
        filePath="$1"
        
        # Credit Card
        # Word splitting on SEARCH_CMD is intended here (e.g. "grep -Po")
        cc=$($SEARCH_CMD "$RE_CC" "$filePath" 2>/dev/null)
        if [ -n "$cc" ]; then
            echo "File: $filePath"
            echo "Credit Card Numbers:"
            printf "%s\n" "$cc"
            echo "------------------------"
        fi

        # Address
        addr=$($SEARCH_CMD "$RE_ADDR" "$filePath" 2>/dev/null)
        if [ -n "$addr" ]; then
            echo "File: $filePath"
            echo "Addresses:"
            printf "%s\n" "$addr"
            echo "------------------------"
        fi

        # SSN
        ssn=$($SEARCH_CMD "$RE_SSN" "$filePath" 2>/dev/null)
        if [ -n "$ssn" ]; then
            echo "File: $filePath"
            echo "Social Security Numbers:"
            printf "%s\n" "$ssn"
            echo "------------------------"
        fi

        # Phone
        phone=$($SEARCH_CMD "$RE_PHONE" "$filePath" 2>/dev/null)
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

