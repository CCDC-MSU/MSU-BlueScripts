# Hardening Modules

This directory contains the Python-based hardening modules used by the Fabric orchestration system. Each module encapsulates a specific security domain and is responsible for generating the appropriate commands to secure that aspect of the system.

## Module Architecture

All modules inherit from `HardeningModule` (in `base.py`) and must implement:
*   `get_name()`: Unique identifier for the module.
*   `get_commands()`: Returns a list of `HardeningCommand` or `PythonAction` objects to be executed.
*   `is_applicable()`: Checks if the module should run on the target OS.

## Available Modules

### `user_hardening.py`
**Purpose**: Manages user accounts, passwords, and sudo access.
**Key Features**:
*   Reads configuration from `users.json`.
*   Changes passwords for all users (caching them for the operator).
*   Ensures required users exist and have correct sudo privileges.
*   Locks unauthorized accounts that have valid shells.
*   "Root Access Persistence": Injects a local SSH key for root to maintain access even after password changes.

### `ssh_hardening.py`
**Purpose**: Secures the SSH daemon configuration.
**Key Features**:
*   **Safe Reload**: Uses a "Dead Man's Switch" (reverts changes after 60s) to prevent locking the operator out.
*   **Honeypot**: Identifies potential unauthorized users ("trapped users") and restricts them to a honeypot command.
*   **Enforcement**: Sets Protocol 2, disables root password login, disables potentially dangerous forwarded ports.
*   **Connectivity Test**: Verifies SSH is still working before finalizing changes.

### `firewall_hardening.py`
**Purpose**: Configures the host firewall to a "default deny" posture.
**Key Features**:
*   **Backend Agnostic**: Automatically detects and uses `firewalld`, `iptables`, `nftables`, `pf` (BSD), or `ipfw`.
*   **Trust Model**: Only allows SSH from specific "Trusted IPs" (hardcoded list of CCDC operator machines).
*   **Safety**: Also utilizes a "Dead Man's Switch" to auto-flush rules if connectivity is lost.

### `package_installer.py`
**Purpose**: Installs essential defense tools and removes bloat.
**Key Features**:
*   **Multi-OS Support**: Handles `apt`, `yum/dnf`, `pacman`, `zypper`, `apk`, `pkg` (BSD), and `brew`.
*   **Tool Mapping**: Maps generic tool names (e.g., "vim", "auditd") to the specific package name for the target distro.
*   **Cleanup**: Removes unused packages and verifies installed package integrity.

### `logging_setup.py`
**Purpose**: Configures comprehensive system logging.
**Key Features**:
*   **Rsyslog/Syslog**: Sets up centralized logging rules for auth, kernel, and daemon logs.
*   **Auditd**: Deploys CCDC-specific audit rules (monitoring file access, execve, socket creation).
*   **Journald**: Configures persistent storage and compression.
*   **Log Rotate**: Ensures security logs are rotated and compressed to prevent disk exhaustion.

### `agent_account.py`
**Purpose**: Creates a dedicated backdoor/maintenance account.
**Key Features**:
*   Creates a `scan-agent` user with sudo privileges.
*   Hardcodes a specific password for this agent.
*   Useful for maintaining access if other accounts are compromised or locked out.

### `bash_scripts.py`
**Purpose**: Bridge for legacy or complex shell scripts.
**Key Features**:
*   Allows the orchestrator to deploy and run raw bash scripts (from `scripts/`) as if they were a module.
*   Handles script upload, execution, and output logging.

## Base Classes (`base.py`)

*   **`HardeningModule`**: Abstract base class defining the contract for all modules.
*   **`CommandAction`**: Represents a shell command to be run on the remote host. Contains `command`, `check_command` (idempotency), and `rollback_command`.
*   **`PythonAction`**: Represents a local Python function to be executed (e.g., for complex logic, file processing, or interacting with the Fabric connection directly).
