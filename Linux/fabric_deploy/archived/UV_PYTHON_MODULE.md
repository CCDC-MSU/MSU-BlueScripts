# Instruction: UV/Python Bootstrap Module

## Executive Summary

Create a new hardening module (`python_bootstrap.py`) that:
1. Verifies uv installer dependencies are present on the remote host
2. Installs `uv` via the official install script
3. Uses `uv` to install Python 3.12 to `/root/python/bin/python3.12`
4. Must run **before** any module that uses Ansible (e.g., `logging_hardening`)

This ensures Ansible has a consistent Python interpreter across all distributions, bypassing distro-specific Python version issues (like Fedora 41's Python 3.13 breaking `libdnf5`).

---

## Module Execution Order

The orchestrator must run modules in this order:

```
n. python_bootstrap      ← NEW (ensures Python 3.12 exists)
n + 1. logging_hardening     ← Uses Ansible, needs Python 3.12
```

Update `deployment.py`.

---

## UV Installer Dependencies

Before attempting to install `uv`, the module MUST verify these utilities exist. If any are missing, fail with a clear error message.

### Required Dependencies

| Category | Utility | Purpose | Check Command |
|----------|---------|---------|---------------|
| **Network** | `curl` OR `wget` | Download installer | `command -v curl \|\| command -v wget` |
| **TLS** | `ca-certificates` | SSL verification | Check varies by distro (see below) |
| **Archive** | `tar` | Extract archives | `command -v tar` |
| **Archive** | `gzip` | Decompress | `command -v gzip` |
| **Shell** | `sh` | Run scripts | Always present |
| **System** | `uname` | Arch detection | `command -v uname` |
| **System** | `mktemp` | Temp files | `command -v mktemp` |
| **System** | `chmod` | Permissions | `command -v chmod` |
| **Text** | `awk` | Text processing | `command -v awk` |
| **Text** | `grep` | Pattern matching | `command -v grep` |
| **Text** | `sed` | Stream editing | `command -v sed` |
| **Text** | `cut` | Field extraction | `command -v cut` |
| **Linux** | `ldd` | libc version check | `command -v ldd` |
| **Linux** | `getent` | User DB lookup | `command -v getent` (or set `$HOME`) |

### CA-Certificates Check by Distro

```bash
# Check if CA certs are available (the actual verification)
# This works across distros - if curl/wget can reach HTTPS, we're good
curl -sSf https://astral.sh >/dev/null 2>&1 || wget -q --spider https://astral.sh 2>/dev/null
```

If this fails, suggest installing ca-certificates:
- **Debian/Ubuntu:** `apt-get install -y ca-certificates`
- **RHEL/Fedora:** `dnf install -y ca-certificates`
- **Alpine:** `apk add ca-certificates`
- **Arch:** `pacman -S ca-certificates`
- **SUSE:** `zypper install -y ca-certificates`

---

## Implementation

### File: `utilities/modules/python_bootstrap.py`

```python
"""
Python Bootstrap Module
Installs uv and Python 3.12 for consistent Ansible execution.

This module MUST run before any module that uses Ansible.
"""

import logging
from typing import List
from .base import HardeningModule, HardeningCommand, HardeningResult, PythonAction

logger = logging.getLogger(__name__)

# Target Python installation
PYTHON_VERSION = "3.12"
PYTHON_INSTALL_DIR = "/root/python"
PYTHON_BIN_DIR = "/root/python/bin"
PYTHON_BIN = f"{PYTHON_BIN_DIR}/python{PYTHON_VERSION}"

# UV installer URL
UV_INSTALL_URL = "https://astral.sh/uv/install.sh"


class PythonBootstrapModule(HardeningModule):
    """Bootstrap Python 3.12 via uv for Ansible compatibility"""
    
    def get_name(self) -> str:
        return "python_bootstrap"
    
    def get_commands(self) -> List[HardeningCommand]:
        commands = []
        
        # Step 1: Verify dependencies
        commands.append(PythonAction(
            function=self._verify_uv_dependencies,
            description="Verify uv installer dependencies are present",
            requires_sudo=False
        ))
        
        # Step 2: Install uv
        commands.append(HardeningCommand(
            command=self._get_install_uv_command(),
            description="Install uv package manager",
            check_command="command -v uv >/dev/null 2>&1 || test -f ~/.local/bin/uv",
            requires_sudo=False  # uv installs to user's home
        ))
        
        # Step 3: Source uv environment
        commands.append(HardeningCommand(
            command='test -f "$HOME/.cargo/env" && . "$HOME/.cargo/env" || true',
            description="Source uv environment",
            requires_sudo=False
        ))
        
        # Step 4: Install Python 3.12
        commands.append(HardeningCommand(
            command=self._get_install_python_command(),
            description=f"Install Python {PYTHON_VERSION} via uv",
            check_command=f"test -f {PYTHON_BIN}",
            requires_sudo=False
        ))
        
        # Step 5: Verify Python installation
        commands.append(HardeningCommand(
            command=f"{PYTHON_BIN} --version",
            description="Verify Python installation",
            requires_sudo=False
        ))
        
        return commands
    
    def _verify_uv_dependencies(self, conn, server_info) -> HardeningResult:
        """
        Verify all required utilities for uv installer are present.
        Returns failure with detailed message if any are missing.
        """
        missing = []
        warnings = []
        
        # Required utilities
        required_utils = [
            'tar', 'gzip', 'uname', 'mktemp', 'chmod',
            'awk', 'grep', 'sed', 'cut'
        ]
        
        # Linux-specific utilities
        linux_utils = ['ldd']
        
        # Check required utilities
        for util in required_utils:
            result = conn.run(f"command -v {util}", warn=True, hide=True)
            if not result.ok:
                missing.append(util)
        
        # Check Linux-specific (only if on Linux)
        if server_info.os_family not in ['freebsd', 'openbsd', 'netbsd']:
            for util in linux_utils:
                result = conn.run(f"command -v {util}", warn=True, hide=True)
                if not result.ok:
                    missing.append(util)
        
        # Check for curl OR wget
        curl_ok = conn.run("command -v curl", warn=True, hide=True).ok
        wget_ok = conn.run("command -v wget", warn=True, hide=True).ok
        if not curl_ok and not wget_ok:
            missing.append("curl or wget")
        
        # Check getent OR $HOME
        getent_ok = conn.run("command -v getent", warn=True, hide=True).ok
        home_set = conn.run('test -n "$HOME"', warn=True, hide=True).ok
        if not getent_ok and not home_set:
            warnings.append("getent missing and $HOME not set - will set HOME=/root")
        
        # Check SSL connectivity (ca-certificates)
        if curl_ok:
            ssl_check = conn.run("curl -sSf https://astral.sh >/dev/null 2>&1", warn=True, hide=True)
        else:
            ssl_check = conn.run("wget -q --spider https://astral.sh 2>/dev/null", warn=True, hide=True)
        
        if not ssl_check.ok:
            # This might mean missing ca-certificates OR no network
            warnings.append("SSL verification failed - may need ca-certificates or network access")
        
        if missing:
            return HardeningResult(
                success=False,
                command="verify_uv_deps",
                description="Verify uv installer dependencies",
                error=f"Missing required utilities: {', '.join(missing)}. Install these before proceeding."
            )
        
        output = "All dependencies present"
        if warnings:
            output += f". Warnings: {'; '.join(warnings)}"
        
        return HardeningResult(
            success=True,
            command="verify_uv_deps",
            description="Verify uv installer dependencies",
            output=output
        )
    
    def _get_install_uv_command(self) -> str:
        """Generate command to install uv"""
        return (
            'if command -v uv >/dev/null 2>&1 || test -f "$HOME/.local/bin/uv"; then '
            '  echo "uv already installed"; '
            'else '
            '  export HOME="${HOME:-/root}"; '
            '  if command -v curl >/dev/null 2>&1; then '
            f'    curl -LsSf {UV_INSTALL_URL} | sh; '
            '  else '
            f'    wget -qO- {UV_INSTALL_URL} | sh; '
            '  fi; '
            'fi'
        )
    
    def _get_install_python_command(self) -> str:
        """Generate command to install Python via uv"""
        return (
            f'export HOME="${{HOME:-/root}}"; '
            f'export UV_PYTHON_INSTALL_DIR={PYTHON_INSTALL_DIR}; '
            f'export UV_PYTHON_BIN_DIR={PYTHON_BIN_DIR}; '
            f'mkdir -p {PYTHON_INSTALL_DIR} {PYTHON_BIN_DIR}; '
            # Find uv binary
            'UV_BIN=""; '
            'if command -v uv >/dev/null 2>&1; then '
            '  UV_BIN=$(command -v uv); '
            'elif test -f "$HOME/.local/bin/uv"; then '
            '  UV_BIN="$HOME/.local/bin/uv"; '
            'elif test -f "$HOME/.cargo/bin/uv"; then '
            '  UV_BIN="$HOME/.cargo/bin/uv"; '
            'fi; '
            'if [ -z "$UV_BIN" ]; then '
            '  echo "ERROR: uv not found"; exit 1; '
            'fi; '
            f'"$UV_BIN" python install {PYTHON_VERSION}'
        )
    
    def is_applicable(self) -> bool:
        """Applicable to all Linux systems"""
        # Skip BSD for now - uv may have different behavior
        return self.os_family not in ['freebsd', 'openbsd', 'netbsd']
```

---

## Integration Points

### 1. Register the Module

In `utilities/modules/__init__.py`:

```python
from .python_bootstrap import PythonBootstrapModule

# Add to exports
__all__ = [
    ...,
    'PythonBootstrapModule',
]
```

### 2. Uncomment generate_configs.py Line 137

In `ansible/generate_configs.py`, change:

```python
# FROM (line 136-139):
'vars': {
    # 'ansible_python_interpreter': '/root/python/bin/python3.12',
}

# TO:
'vars': {
    'ansible_python_interpreter': '/root/python/bin/python3.12',
}
```

This tells Ansible to use our installed Python instead of the system Python.

---

## Dependency Safety Net Script

If you want a standalone script to verify dependencies before running the module, here's a shell script version:

### File: `scripts/all/check_uv_deps.sh`

```bash
#!/bin/sh
# Check if all uv installer dependencies are present
# Exit 0 if all present, exit 1 with list of missing

set -e

MISSING=""
WARNINGS=""

check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        MISSING="$MISSING $1"
    fi
}

# Required utilities
for cmd in tar gzip uname mktemp chmod awk grep sed cut; do
    check_cmd "$cmd"
done

# Linux-specific
if [ "$(uname -s)" = "Linux" ]; then
    check_cmd ldd
fi

# Need curl OR wget
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    MISSING="$MISSING curl-or-wget"
fi

# Check getent or $HOME
if ! command -v getent >/dev/null 2>&1; then
    if [ -z "$HOME" ]; then
        echo "WARNING: getent missing and \$HOME not set"
        export HOME=/root
    fi
fi

# Check SSL connectivity
if command -v curl >/dev/null 2>&1; then
    if ! curl -sSf https://astral.sh >/dev/null 2>&1; then
        WARNINGS="$WARNINGS ssl-check-failed"
    fi
elif command -v wget >/dev/null 2>&1; then
    if ! wget -q --spider https://astral.sh 2>/dev/null; then
        WARNINGS="$WARNINGS ssl-check-failed"
    fi
fi

if [ -n "$MISSING" ]; then
    echo "MISSING DEPENDENCIES:$MISSING"
    echo ""
    echo "Install missing utilities before proceeding."
    echo "Common package names:"
    echo "  Debian/Ubuntu: apt-get install -y coreutils gzip wget ca-certificates gawk"
    echo "  RHEL/Fedora:   dnf install -y coreutils gzip wget ca-certificates gawk"
    echo "  Alpine:        apk add coreutils gzip wget ca-certificates gawk"
    echo "  Arch:          pacman -S coreutils gzip wget ca-certificates gawk"
    exit 1
fi

if [ -n "$WARNINGS" ]; then
    echo "WARNINGS:$WARNINGS"
fi

echo "All uv installer dependencies present!"
exit 0
```

---

## Error Handling Strategy

When dependencies are missing:

1. **Fail fast** - Don't attempt uv installation
2. **Report clearly** - List all missing utilities
3. **Suggest fixes** - Show distro-specific install commands
4. **Don't retry** - This is a prerequisite failure, not a transient error

When Ansible package installation fails (after Python is installed):

1. **Log the error** with full Ansible output
2. **Return failure** - Don't silently continue
3. **Operator intervention required** - Some packages may need manual installation

---

## Testing Matrix

| Host | Expected Behavior |
|------|-------------------|
| All Linux | Dependencies should be present (standard utils) |
| Alpine | May need `coreutils` for some utilities |
| Slackware | May need extra packages |
| Minimal containers | Most likely to have missing deps |
| BSD | Skip module (not applicable) |

### Verification Commands

After running the module, verify:

```bash
# Check uv installed
~/.local/bin/uv --version

# Check Python installed
/root/python/bin/python3.12 --version

# Check Ansible can use it
ansible -m ping localhost -e "ansible_python_interpreter=/root/python/bin/python3.12"
```

---

## Summary of Changes Required

| File | Change |
|------|--------|
| **NEW** `utilities/modules/python_bootstrap.py` | Create the full module |
| `utilities/modules/__init__.py` | Import and export `PythonBootstrapModule` |
| `utilities/deployment.py` | Add `python_bootstrap` to module order (first!) |
| `ansible/generate_configs.py:137` | Uncomment `ansible_python_interpreter` line |
| **NEW** `scripts/all/check_uv_deps.sh` | Optional standalone dependency checker |
