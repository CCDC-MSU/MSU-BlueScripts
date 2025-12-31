**Concerned with ops? [Look at the workflow guide](docs/workflow_guide.md)**
---
# CCDC Hardening Deployment Framework

**Automated Defense**

This framework is designed for use in the Collegiate Cyber Defense Competition (CCDC). It automates the discovery, lockdown, and hardening of Linux/BSD systems, allowing a single operator to secure an entire fleet of machines in minutes.

## Features

*   **One-Click Hardening**: `fab harden` runs the entire defense pipeline across all hosts in parallel.
*   **Safety First**:
    *   **Dead Man's Switch**: SSH changes automatically revert if you lock yourself out.
    *   **Root Persistence**: Automatically injects a recovery SSH key before rotating passwords.
*   **Aggressive Defense**:
    *   **User Lockdown**: Rotates all passwords, locks unauthorized shells, and sanitizes sudoers.
    *   **Honeypot Traps**: Identifies suspicious idle accounts and traps them in a honeypot environment.
    *   **Firewall Lockdown**: Blocks all inbound traffic except trusted SSH.
*   **Cross-Platform**: Automatically adapts to Debian, RHEL, SUSE, Arch, Alpine, and BSD variants.

## Getting Started

Designed to run from a central "Jump Box".

### 1. Setup
```bash
# Clone the repo
git clone <repo_url> ccdc-scripts
cd ccdc-scripts/Linux/fabric_deploy

# Run the bootstrap script (installs Python/Pip, creates venv)
./bootstrap_onto_jumpbox.sh

# Activate environment
source activate.sh
```

### 2. Configuration
*   **`hosts.txt`**: List your targets.
    ```text
    192.168.1.10:root:password:Web-Server
    192.168.1.11:admin:password:DB-Server
    ```
*   **`users.json`**: Build users.json with the list of correct users. Leave the password fields empty for a password to be auto generated. (same on all hosts by default)
    *   **`do_not_change_users`**: CRITICAL. List Black Team/Scoring accounts here so they aren't touched.
    *   **`__PER_HOST__`**: Use this as a password value to generate a unique random password for that user on each host.

## Usage

### Primary Workflow: `fab harden`

This is the only command you typically need. It runs the full hardening pipeline:

```bash
fab harden
```

**What it does (The Pipeline):**
1.  **Discovery**: Profiles the OS, users, and services.
2.  **Snapshot**: Backs up critical files to `/root/pre-hardening-snapshot/`.
3.  **Root Persistence**: Injects `keys/test-root-key.pub` into root's `authorized_keys`.
4.  **User Hardening**: Rotates passwords, locks invalid users, fixes sudoers.
5.  **Firewall & Lockdown**: Installs firewall, blocks inbound traffic, runs `lockdown.sh`.
6.  **SSH Hardening**: Secures `sshd_config`, enables Dead Man's Switch, sets up Honeypots.
7.  **Script Deployment**: Uploads helper tools (`diff-changes.sh`, etc.) to `/root/tools`.
8.  **Logging**: Configures persistent logging (auditd/rsyslog).

### Viewing Results
*   **Reports**: `reports/<host>/<timestamp>.md` (High-level summary of what changed).
*   **Logs**: `logs/harden/<host>/<timestamp>.log` (Detailed execution logs).
*   **Passwords**: `logs/user-hardening/<host>/passwords_<timestamp>.txt` (New passwords).

---

## Advanced Usage / Troubleshooting

**Manual Module Testing**
To run a specific module (e.g., to fix SSH without running the full pipeline):
```bash
fab test-module --module=ssh_hardening --live
```
*(Available modules: user_hardening, ssh_hardening, firewall_hardening, package_installer, logging_setup)*

**Run Custom Scripts**
Run a local script on all remote hosts:
```bash
fab run-script --file scripts/all/my-custom-fix.sh
```

**Discovery Only**
Just gather facts without changing anything:
```bash
fab discover-all
```

## Architecture

*   **`fabfile.py`**: Entry point.
*   **`utilities/modules/`**: detailed Python logic for each hardening step.
*   **`scripts/all/`**: Bash scripts for raw system interaction (`lockdown.sh`, `archive_cronjobs.sh`).

## Contributing

The easiest way to contribute is to add a posix compatible script to `/scripts/all/`