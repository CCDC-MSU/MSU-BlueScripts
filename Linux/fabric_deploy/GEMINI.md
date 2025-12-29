# Fabric Hardening System - Project Blueprint

## 1. Project Overview

**Goal**: Automatically discover facts about remote Linux/Unix/BSD systems and apply appropriate hardening measures to secure them against Red Team attacks and malware.

**Context**: Designed for the Collegiate Cyber Defence Competition (CCDC).
- **Timeframe**: 30 minutes setup time, 8 hours of defense.
- **Environment**: "Jump box" (control node) + ~8 remote systems (Linux/BSD).
- **Operator**: One Blue Team member (Operator) manages this system from the jump box.

**Philosophy**: "Run and forget". The system should be robust, idempotent where possible, and provide clear feedback via logs and reports.

## 2. System Architecture

### 2.1 Control Node (Jump Box)
The system runs on a central control node using Python and **Fabric** for SSH-based orchestration.
- **Entrypoint**: `fabfile.py` provides the CLI commands (`discover`, `harden`, `run-script`, etc.).
- **Configuration**:
    - `hosts.txt`: List of target systems (format: `ip:user:pass:friendly_name`).
    - `users.json`: Defines required users (regular/super) and accounts to ignore.
    - `config.yaml`: Global settings (default scripts, connection timeouts).
    - `tools/`: Directory of binary tools to upload to remotes.
- **Logs & Reports**:
    - `logs/{task}/{host}/{timestamp}.log`: Detailed execution logs.
    - `reports/`: Markdown summaries of hardening actions per host.

### 2.2 Remote Nodes
Target systems can be various Linux distributions (Debian, RHEL, SUSE, Arch, Alpine) or BSD variants (FreeBSD, OpenBSD, NetBSD).
- **Agentless**: No pre-installed agent required. Relies on SSH and standard system tools (Python is preferred but not strictly required for shell scripts, though modules run Python logic locally to generate commands).
- **State**: We assume the systems may be compromised or in an unknown state.

## 3. Core Components

### 3.1 System Discovery (`utilities/discovery.py`)
Before taking action, the system profiles the target.
- **Mechanism**: Runs a chain of shell commands (`uname`, `cat /etc/passwd`, `systemctl`, etc.) to gather data.
- **Data Model** (`utilities/models.py`): Populates a `ServerInfo` object containing:
    - **OS**: Distro, version, kernel, architecture.
    - **Users/Groups**: List of users, valid shells, sudo capabilities (`analyze_sudoers`).
    - **Services**: Running systemd/init services.
    - **Network**: Interfaces, listening ports, routes.
    - **Tools**: Presence of critical tools (`iptables`, `auditd`, etc.).

### 3.2 Hardening Modules (`utilities/modules/`)
Python classes that generate platform-specific shell commands to apply security controls.
- **Orchestration** (`utilities/deployment.py`): The `HardeningDeployer` and `HardeningOrchestrator` select applicable modules based on discovered OS family and execute them.
- **Active Verification**: Modules can verify changes (e.g., testing SSH connectivity after config changes) and rollback if needed.

**Key Modules:**
1.  **User Hardening** (`user_hardening.py`):
    - Reads `users.json` for required state.
    - Changes passwords for all users (caches passwords to file).
    - Ensures valid sudoers configuration.
    - Locks unauthorized accounts.
2.  **SSH Hardening** (`ssh_hardening.py`):
    - Backs up `sshd_config`.
    - Pushes a secure configuration (Protocol 2, no root login, whitelist users).
    - **Honeypot**: Identifies "trapped" users (likely non-system accounts not in our allowlist) and jails them with a honeypot command.
    - **Safety**: Tests connection before finalizing; rolls back on failure.
3.  **Firewall Hardening** (`firewall_hardening.py`):
    - detects active firewall (ufw, firewalld, iptables, pf, ipfw).
    - Resets rules to default deny.
    - Allows SSH (from trusted IPs).
    - *Note*: Needs alignment with `lockdown.sh` strategies.
4.  **Package Installer** (`package_installer.py`):
    - Installs essential defense tools (`auditd`, `vim`, `tmux`, `zsh`, `curl`).
    - Updates existing packages (conditionally, as this can be slow).
    - Maps generic tool names to distro-specific package names.
5.  **Logging Setup** (`logging_setup.py`):
    - Configures `rsyslog` / `syslog` / `journald`.
    - Sets up `auditd` with CCDC-specific rules (monitoring `/etc/passwd`, execve, etc.).
    - Configures `logrotate`.
6.  **Bash Scripts** (`bash_scripts.py`):
    - Wrapper to deploy and run raw shell scripts from `scripts/all/`.

### 3.3 Scripts (`scripts/all/`)
Standalone shell scripts for tasks that don't fit the module model or need to be run raw.
- **`lockdown.sh`**: Immediate "Panic Button" script. Limits SSH to trusted IPs and blocks outbound connections (except critical services if `--allow-internet` is used). Includes a "dead man's switch" safety net.
- **`pre-hardening-snapshot.sh`**: comprehensive system state capture (files, process list, netstat) before hardening begins.
- **`check-go-binaries.sh`, `find_media.sh`, `search-pii.sh`**: Hunting and forensics helpers.
- **`systemd-hunting.sh`**: Analysis of systemd units for persistence mechanisms.

## 4. Operational Workflow

The standard operating procedure for the Competition:

1.  **Preparation (T-30 mins)**:
    - Operator populates `hosts.txt` with target IPs and default creds.
    - Operator configures `users.json` with the team's user list.
    - Operator ensures `tools/` contains necessary binaries.

2.  **Initial Discovery**:
    - Run `fab discover-all`.
    - Populate the class `ServerInfo` with the discovered data to be used by the hardening modules.
    - Review `discovery_*.json` and logs to understand the battlefield.

3.  **Snapshot & Lockdown**:
    - Run `fab run-script scripts/all/pre-hardening-snapshot.sh` (Save state).
    - Run the module to install and make sure the firewall is working.
    - Run `fab run-script scripts/all/lockdown.sh` (Stop the bleeding).

4.  **Hardening Execution**:
    - Run `fab harden` (or `fab harden --modules user_hardening,ssh_hardening` for targeted fix).
    - **Deployment Logic**:
        - Connect to host.
        - Run Discovery (refresh state).
        - For each Module:
            - Generate commands.
            - Execute commands (with sudo).
            - Log success/failure.
        - Generate markdown Report.

5.  **Verification**:
    - Operator checks `logs/reports/` for failures.
    - Operator verifies authorized access (SSH).
    - Team members take over refined/hardened hosts.

The setup should be such that the operator only runs fab harden and the rest is handled automatically.

## 5. Development Roadmap & Status

| Feature | Status | Notes |
| :--- | :--- | :--- |
| **Discovery** | 🟢 Stable | Works on Linux/BSD. |
| **User Hardening** | 🟡 Good | Needs careful handling of `users.json` to avoid lockouts. |
| **SSH Hardening** | 🟢 Stable | Safe rollback features implemented. |
| **Firewall (Module)** | 🔴 Needs Update | Logic significantly diverged from robust `lockdown.sh`. Needs syncing. |
| **Lockdown Script** | 🟢 Stable | robust, multi-backend (iptables/nft/pf/ipfw). |
| **Logging** | 🟡 Functional | Logic is comprehensive but complex; needs verification on BSDs. |
| **Reporting** | 🟡 Basic | Generates Markdown; needs more detail (diffs, specific alerts). |
| **Tools Upload** | 🟡 Manual | `fab upload-tools` exists, needs integration into main flow. |

## 6. Key Files Map

- **Entry**: `fabfile.py`
- **Config**: `utilities/models.py` (Data classes), `utilities/utils.py` (Parsers)
- **Logic**: `utilities/deployment.py` (Orchestrator), `utilities/discovery.py` (Scanner)
- **Modules**: `utilities/modules/*.py`
- **Scripts**: `scripts/all/*.sh`
