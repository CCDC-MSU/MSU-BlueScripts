#!/bin/sh

ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'

# Scan both /home and /root
find /home /root -type f \( -name '*.txt' -o -name '*.csv' \) \
  -exec sh -c '
    pattern=$1
    shift
    for file do
      grep -Hn -e "$pattern" -- "$file" 2>/dev/null |
      while IFS= read -r line
      do
        printf "%s:SSN:%s\n" "$file" "$line"
      done
    done
  ' sh "$ssn_pattern" {} +
