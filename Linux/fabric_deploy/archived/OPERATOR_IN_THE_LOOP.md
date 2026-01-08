# Operator-in-the-Loop: Python Bootstrap Dependency Management

## Overview

The Python Bootstrap module now supports **operator-in-the-loop** decision making for handling missing dependencies. This allows you to make informed choices when hosts are missing required utilities for Python 3.12 installation.

## Why This Matters

When running hardening across multiple hosts in parallel, some hosts may be missing dependencies like `tar`, `curl`, `wget`, etc. Instead of silently failing or continuing with uncertain outcomes, you can now:

1. **See all failures upfront** before the main hardening runs
2. **Make informed decisions** for each failed host
3. **Fix issues manually** and have the system re-verify
4. **Use automatic fallback** (Ansible auto-discovery) when appropriate

## Workflow

### Recommended: Pre-Flight Check Before Hardening

```bash
# Step 1: Run pre-flight dependency check
uv run fab check-python-bootstrap-deps

# Step 2: If prompted, make your choices for failed hosts

# Step 3: Run hardening (will use your saved decisions)
uv run fab harden
```

### Alternative: Hardening Without Pre-Flight

```bash
# Hardening will proceed automatically
# Failed hosts will fall back to Ansible auto-discovery
uv run fab harden
```

## Pre-Flight Check: Step-by-Step

### 1. Run the Check

```bash
cd Linux/fabric_deploy
uv run fab check-python-bootstrap-deps
```

### 2. Review Results

The check runs on all hosts in parallel and shows:

```
DEPENDENCY CHECK RESULTS
============================================================
✓ Ready for Python 3.12: 8 hosts
✗ Missing dependencies: 1 hosts
```

### 3. Operator Prompt (If Failures Exist)

You'll see detailed information about each failure:

```
PYTHON BOOTSTRAP DEPENDENCY FAILURES DETECTED
============================================================

1 host(s) are missing required dependencies for Python 3.12 installation:

1. localhost (10.0.0.4)
   Missing: tar

============================================================
OPTIONS:
============================================================
For each host, you can:
  [F] Fix manually - Pause to let you install dependencies, then retry
  [S] Skip - Continue with Ansible auto-discovery (use system Python)
  [A] Abort - Stop the entire hardening process
```

### 4. Make Your Choice

#### Option F: Fix Manually and Retry

```
Apply same decision to all hosts? [y/N]: n

[1/1] localhost (10.0.0.4)
Missing: tar

Decision for this host [F/S/A]: F
```

**What happens:**
- System pauses and shows you exactly which commands to run
- You install the missing dependencies manually
- Press ENTER to continue
- System re-verifies all dependencies
- If still failing, falls back to auto-discovery

**Example fix commands shown:**
```
WAITING FOR MANUAL DEPENDENCY INSTALLATION
============================================================

Please install the missing dependencies on 1 host(s):

  localhost (10.0.0.4) - Missing: tar
    Install with:
      Fedora/RHEL: ssh root@10.0.0.4 'dnf install -y tar'
      Debian/Ubuntu: ssh root@10.0.0.4 'apt-get install -y tar'
      Alpine: ssh root@10.0.0.4 'apk add tar'

Once dependencies are installed, press ENTER to continue...
```

#### Option S: Skip (Use Auto-Discovery)

```
Decision for this host [F/S/A]: S
```

**What happens:**
- Host is marked to skip Python 3.12 installation
- During hardening, python_bootstrap will be skipped for this host
- Ansible will use auto-discovery to find system Python
- Config generation won't set `ansible_python_interpreter` for this host

#### Option A: Abort

```
Decision for this host [F/S/A]: A
```

**What happens:**
- Pre-flight check stops immediately
- No hardening will proceed
- Decisions are NOT saved
- You can investigate and re-run later

### 5. Batch Mode (Multiple Hosts)

If multiple hosts have failures:

```
Apply same decision to all hosts? [y/N]: y

Decision for ALL hosts:
  [F] Fix manually and retry
  [S] Skip (use auto-discovery)
  [A] Abort hardening

Your choice [F/S/A]: S
```

This applies your choice to all failed hosts at once.

## How Decisions Are Stored

Decisions are saved to:
```
ansible/operator_decisions.json
```

**Example:**
```json
{
  "timestamp": "2026-01-08T01:23:45.678901",
  "decisions": {
    "10.0.0.4": "skip_auto_discovery",
    "10.0.0.5": "retry"
  }
}
```

## Integration with Hardening Pipeline

When you run `uv run fab harden` after pre-flight:

1. **Python bootstrap step** checks for operator decisions
2. **For each host:**
   - If decision is "skip" → Skips installation, saves state as failed (Ansible auto-discovery)
   - If decision is "retry" or no decision → Proceeds with normal installation
   - If decision is "abort" → Skips installation entirely

3. **Config generation** (`ansible/generate_configs.py`) uses the state file:
   - Successful installations → Sets `ansible_python_interpreter: /root/python/bin/python3.12`
   - Failed/skipped installations → Omits `ansible_python_interpreter` (auto-discovery)

## Decision File Lifecycle

### When Decisions Are Cleared

- At the **start** of `check-python-bootstrap-deps` (fresh start)
- When you manually delete `ansible/operator_decisions.json`

### When Decisions Are Used

- During `uv run fab harden` when python_bootstrap module runs
- Decisions persist across multiple hardening runs
- Re-running pre-flight check overwrites previous decisions

### Manually Managing Decisions

```bash
# View current decisions
cat ansible/operator_decisions.json

# Clear decisions (start fresh)
rm ansible/operator_decisions.json

# Edit decisions manually (if needed)
vim ansible/operator_decisions.json
```

## Example Scenarios

### Scenario 1: Fresh Setup, One Host Missing tar

```bash
$ uv run fab check-python-bootstrap-deps

# Output shows Fedora missing tar
# You choose: [F] Fix manually

# System shows:
#   Fedora/RHEL: ssh root@10.0.0.4 'dnf install -y tar'

# You run the command in another terminal:
$ ssh root@10.0.0.4 'dnf install -y tar'

# Press ENTER in the pre-flight check
# System re-verifies and confirms tar is now present

$ uv run fab harden
# Hardening proceeds normally, Python 3.12 installed on all hosts
```

### Scenario 2: Production Rush, No Time to Fix

```bash
$ uv run fab check-python-bootstrap-deps

# Output shows Fedora missing tar
# You choose: [S] Skip (need to harden NOW)

$ uv run fab harden
# Fedora skips Python 3.12, uses system Python
# Other hosts install Python 3.12
# Everything works, Fedora uses Python 3.13 (auto-discovery)
```

### Scenario 3: Multiple Hosts, Same Issue

```bash
$ uv run fab check-python-bootstrap-deps

# Output shows 3 hosts missing tar
# Batch mode: Apply same decision to all hosts? [y/N]: y
# You choose: [S] Skip

$ uv run fab harden
# All 3 hosts skip Python 3.12
# Use system Python via auto-discovery
```

## Troubleshooting

### Pre-flight check hangs

**Cause:** Connection issues to remote hosts
**Solution:** Check `logs/preflight/<host>/<timestamp>.log` for details

### Decisions not being used during hardening

**Cause:** Decision file not found or corrupted
**Solution:**
```bash
# Check if file exists
ls -l ansible/operator_decisions.json

# Re-run pre-flight
uv run fab check-python-bootstrap-deps
```

### Re-verification still shows failures after manual fix

**Cause:** Dependencies not actually installed, or connection cached
**Solution:**
- Verify manually: `ssh root@<host> 'command -v tar'`
- If installed, choose [S] Skip and file a bug report

### Want to change decision after hardening started

**Cause:** Decisions saved but you changed your mind
**Solution:**
- Stop hardening (Ctrl+C)
- Delete `ansible/operator_decisions.json`
- Re-run pre-flight check with new choices

## Benefits Over Automatic Handling

### ✅ With Operator-in-the-Loop

- **Visibility:** See all issues upfront
- **Control:** Choose how to handle each host
- **Verification:** System confirms fixes worked
- **Transparency:** Know exactly what will happen during hardening

### ❌ Without Operator-in-the-Loop

- **Surprise failures:** Discover issues mid-hardening
- **No control:** System decides automatically
- **Wasted time:** Hardening starts, then fails
- **Uncertainty:** Not clear which hosts use which Python

## Technical Details

### Files Created/Modified

1. **`utilities/operator_interaction.py`** - Operator prompt and decision handling
2. **`tasks/preflight.py`** - Pre-flight check Fabric task
3. **`utilities/modules/python_bootstrap.py`** - Reads and respects operator decisions
4. **`fabfile.py`** - Registers `check-python-bootstrap-deps` task

### Decision States

| Decision | Code | Behavior |
|----------|------|----------|
| Fix manually | `retry` | Wait for operator, re-verify, then install |
| Skip | `skip_auto_discovery` | Mark as failed, Ansible uses auto-discovery |
| Abort | `abort` | Stop everything, don't save decisions |

### Parallel Execution Compatibility

The operator-in-the-loop design is **fully compatible** with parallel execution:

1. **Pre-flight runs in parallel** (all hosts checked simultaneously)
2. **Failures collected** before prompting operator
3. **Operator prompted once** with all failures
4. **Decisions saved** before hardening starts
5. **Hardening runs in parallel** with each host reading its own decision

---

**Status:** ✅ Production Ready
**Parallel Safe:** ✅ Yes
**User Experience:** ✅ Interactive and Clear
