# Operator Decision System for Hardening Pipeline

## Overview

The Operator Decision System allows human operators to make informed decisions during the automated hardening pipeline when issues arise that require judgment, such as missing dependencies or configuration conflicts.

This system is designed to work seamlessly with **parallel execution** across multiple hosts, pausing only the affected host while allowing others to continue.

## How It Works

### 1. Issue Detection

During hardening, modules can detect issues that require operator decision:
- Missing dependencies (e.g., `tar` utility for Python bootstrap)
- Configuration conflicts
- Unexpected system states

### 2. Decision Request

When an issue is detected:
1. **Decision file created** in `decisions/` directory
2. **Console notification printed** with clear instructions
3. **Host execution paused** - only that host waits
4. **Other hosts continue** - parallel execution unaffected

### 3. Operator Response

The operator:
1. Sees the notification in the console
2. Opens the decision file (plain text)
3. Reviews the issue and options
4. Edits the `decision:` line with their choice
5. Saves the file

### 4. Automatic Continuation

The system:
1. Detects the decision (polls every 2 seconds)
2. Validates the choice
3. Continues hardening based on the decision
4. Cleans up decision files

## Example Flow

###Console Output

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!  OPERATOR DECISION REQUIRED - Host: 10.0.0.4
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Module: python_bootstrap
Decision File: decisions/10_0_0_4_python_bootstrap.decision

ACTION REQUIRED:
1. Open the decision file in an editor:

   nano decisions/10_0_0_4_python_bootstrap.decision

2. Review the issue and options
3. Edit the 'decision: PENDING' line with your choice
4. Save and exit - hardening will continue automatically

Available Options:
  skip. Skip Python 3.12 installation - Let Ansible auto-discover system Python (missing: tar)
  retry. I've fixed the dependencies - Re-check and continue with Python 3.12 installation

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Decision File (`decisions/10_0_0_4_python_bootstrap.decision`)

```
================================================================================
OPERATOR DECISION REQUIRED
================================================================================

Host:    10.0.0.4
Module:  python_bootstrap
Issue:   Missing required utilities: tar
Time:    2026-01-08T00:45:23.123456

================================================================================
OPTIONS
================================================================================

skip. Skip Python 3.12 installation - Let Ansible auto-discover system Python (missing: tar)
retry. I've fixed the dependencies - Re-check and continue with Python 3.12 installation

================================================================================
INSTRUCTIONS
================================================================================

1. Review the issue and options above
2. Edit the 'decision' line below with your choice (skip, retry)
3. Save the file
4. The hardening process will automatically continue

================================================================================
YOUR DECISION (Edit the value below)
================================================================================

decision: PENDING

```

### Operator Actions

**Option 1: Skip Python Installation**
```bash
# Edit the file
nano decisions/10_0_0_4_python_bootstrap.decision

# Change this line:
decision: PENDING

# To:
decision: skip

# Save and exit (Ctrl+X, Y, Enter)
```

**Option 2: Fix Dependencies and Retry**
```bash
# 1. Fix the dependency issue
ssh root@10.0.0.4 "dnf install -y tar"

# 2. Edit the decision file
nano decisions/10_0_0_4_python_bootstrap.decision

# Change:
decision: PENDING

# To:
decision: retry

# Save and exit
```

## Python Bootstrap Integration

The `python_bootstrap` module uses this system when dependencies are missing:

### Decision Options

1. **skip** - Skip Python 3.12 installation
   - Ansible will use auto-discovery to find system Python
   - Hardening continues with system Python (may be 3.13+)
   - Useful when dependencies can't be easily installed

2. **retry** - Fix dependencies and retry
   - Operator installs missing utilities manually
   - Module re-checks dependencies
   - Proceeds with Python 3.12 installation if successful
   - If dependencies still missing, requests decision again

### Example Scenarios

#### Scenario 1: Fedora Missing tar

```
Issue: Missing required utilities: tar
Operator Decision: retry
Action Taken:
1. ssh root@10.0.0.4 "dnf install -y tar"
2. Edit decision file: decision: retry
3. Module re-checks dependencies
4. Python 3.12 installation proceeds
```

#### Scenario 2: Minimal Alpine Container

```
Issue: Missing required utilities: tar, gzip, curl or wget
Operator Decision: skip
Action Taken:
1. Too many missing dependencies
2. Edit decision file: decision: skip
3. Python 3.12 installation skipped
4. Ansible uses auto-discovery (system Python)
```

## Configuration

### Timeout

Default: **300 seconds (5 minutes)**

Modify in module:
```python
decision = decision_manager.request_decision(
    issue=f"Missing required utilities: {', '.join(missing)}",
    options=options,
    timeout=600  # 10 minutes
)
```

### Poll Interval

Default: **2 seconds**

The system checks for decisions every 2 seconds to minimize latency.

## File Locations

```
decisions/                           # Decision files directory
├── 10_0_0_4_python_bootstrap.decision   # Human-readable
├── 10_0_0_4_python_bootstrap.json       # Programmatic access
└── ...
```

**Cleanup:** Decision files are automatically deleted after use.

## Workflow Integration

### During `uv run fab harden`

```
Pipeline Execution:
  Host 10.0.0.3 (Alpine)  → [Discovery] → [Snapshot] → [User Hardening] → ...
  Host 10.0.0.4 (Fedora)  → [Discovery] → [Snapshot] → [User Hardening] → [Python Bootstrap]
                                                                              ↓
                                                                        [MISSING DEPS]
                                                                              ↓
                                                                    [OPERATOR DECISION]
                                                                              ↓
                                                                        [PAUSED - Waiting]
  Host 10.0.0.5 (Rocky)   → [Discovery] → [Snapshot] → [User Hardening] → [Python Bootstrap] → ...

Operator Actions:
1. Sees notification for 10.0.0.4
2. Decides: skip or retry
3. Edits decision file
4. Host 10.0.0.4 continues automatically
```

### Benefits

✅ **Non-Blocking** - Other hosts continue unaffected
✅ **Clear Notifications** - Impossible to miss
✅ **Simple Interface** - Just edit a text file
✅ **Timeout Protection** - Defaults to safe action if no response
✅ **Audit Trail** - JSON files can be logged for review

## Advanced Usage

### Check Pending Decisions

```python
from utilities.operator_decision import OperatorDecisionManager

pending = OperatorDecisionManager.get_pending_decisions()
print(f"Pending decisions: {len(pending)}")
for decision_file in pending:
    print(f"  - {decision_file}")
```

### Cleanup All Decisions

```python
OperatorDecisionManager.cleanup_all_decisions()
```

### Custom Decision Options

```python
decision_manager = OperatorDecisionManager(conn.host, "custom_module")

options = {
    "option1": "Description of option 1",
    "option2": "Description of option 2",
    "option3": "Description of option 3"
}

decision = decision_manager.request_decision(
    issue="Custom issue description",
    options=options,
    timeout=180
)

if decision == "option1":
    # Handle option 1
    pass
elif decision == "option2":
    # Handle option 2
    pass
```

## Best Practices

### For Operators

1. **Monitor the console** during hardening
2. **Respond promptly** to decision requests
3. **Document decisions** for post-competition review
4. **Test fixes** before choosing "retry"

### For Module Developers

1. **Only request decisions for critical issues**
2. **Provide clear, actionable options**
3. **Include enough context** in the issue description
4. **Set reasonable timeouts** (5-10 minutes)
5. **Default to safe actions** on timeout

## Troubleshooting

### Decision File Not Found

**Symptom:** File disappears before you can edit it
**Cause:** Module timed out and cleaned up
**Solution:** Increase timeout or respond faster

### Invalid Decision Not Accepted

**Symptom:** System keeps waiting after editing file
**Cause:** Typo in decision value
**Solution:** Ensure exact match with option keys (e.g., `skip`, not `Skip`)

### Multiple Hosts Waiting

**Symptom:** Several decision requests at once
**Cause:** Common issue affecting multiple hosts
**Solution:** Handle them one at a time or in parallel terminals

---

**Status:** ✅ Implemented and Ready for Testing
**Version:** 1.0
**Last Updated:** 2026-01-08
