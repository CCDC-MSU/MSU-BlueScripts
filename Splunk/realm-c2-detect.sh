#!/bin/sh
# Realm/Imix C2 Beacon Detection via tcpdump
# Monitors TCP traffic for Realm signatures
# EXCLUDES self-referencing traffic to prevent loops

tcpdump -i any -l -n -A -s 512 'tcp' 2>/dev/null | \
grep -iE --line-buffered "imix|realm|tavern|eldritch|spellshift" | \
grep -v "realm_c2_detect" | \
grep -v "splunk" | \
while IFS= read -r line; do
    logger -p local0.warning -t realm_c2_detect "REALM_C2_DETECTED: $line"
done
