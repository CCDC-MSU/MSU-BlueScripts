#!/bin/bash
# Auto-responder script - waits for decision file and chooses "skip"

echo "[Auto-Responder] Watching for decision files..."

for i in {1..60}; do
    DECISION_FILE=$(find decisions/ -name "*.decision" 2>/dev/null | head -1)
    if [ -n "$DECISION_FILE" ]; then
        echo "[Auto-Responder] Decision file found: $DECISION_FILE"
        echo "[Auto-Responder] Waiting 5 seconds before responding..."
        sleep 5
        
        echo "[Auto-Responder] Reading decision file:"
        cat "$DECISION_FILE" | grep -A 5 "OPTIONS"
        
        echo "[Auto-Responder] Choosing: skip"
        sed -i 's/decision: PENDING/decision: skip/' "$DECISION_FILE"
        
        echo "[Auto-Responder] Decision saved. Exiting."
        exit 0
    fi
    sleep 1
done

echo "[Auto-Responder] Timeout - no decision file appeared"
exit 1
