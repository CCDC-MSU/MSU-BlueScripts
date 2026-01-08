#!/bin/bash
# Test script for operator decision system

echo "=================================="
echo "OPERATOR DECISION SYSTEM TEST"
echo "=================================="
echo ""
echo "This script will:"
echo "1. Start python_bootstrap module on Fedora (missing tar)"
echo "2. Wait for decision request"
echo "3. Simulate operator response"
echo ""

# Start the module test in background
echo "Starting python_bootstrap test..."
uv run fab test-module --module=python_bootstrap --live --hosts=hosts_test_fedora.txt > test_output.log 2>&1 &
TEST_PID=$!

echo "Test PID: $TEST_PID"
echo "Waiting for decision file to appear..."

# Wait for decision file
DECISION_FILE=""
for i in {1..30}; do
    sleep 2
    DECISION_FILE=$(find decisions/ -name "*.decision" 2>/dev/null | head -1)
    if [ -n "$DECISION_FILE" ]; then
        echo "Decision file found: $DECISION_FILE"
        break
    fi
    echo "Waiting... ($i/30)"
done

if [ -z "$DECISION_FILE" ]; then
    echo "ERROR: No decision file appeared within 60 seconds"
    kill $TEST_PID 2>/dev/null
    exit 1
fi

echo ""
echo "=================================="
echo "DECISION FILE CONTENT:"
echo "=================================="
cat "$DECISION_FILE"
echo "=================================="
echo ""

# Simulate operator choosing "skip"
echo "Simulating operator decision: skip"
sleep 2
sed -i 's/decision: PENDING/decision: skip/' "$DECISION_FILE"

echo "Decision updated. Waiting for test to complete..."
wait $TEST_PID

echo ""
echo "=================================="
echo "TEST COMPLETED"
echo "=================================="
echo ""
echo "Test output:"
tail -50 test_output.log

