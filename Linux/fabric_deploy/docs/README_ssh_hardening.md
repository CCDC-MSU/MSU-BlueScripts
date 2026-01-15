# SSH Hardening Module

**Go back to [main README](README.md)**

This module secures remote access, often the most attacked service in CCDC. It includes safety mechanisms ("Dead Man's Switch") and aggressive defense tactics (Honeypot Traps with SSH key detection).

## Overview

The `ssh_hardening` module replaces the default insecurity of `sshd_config` with a known good configuration. It is designed to be "safe by default," meaning it will automatically roll back changes if it detects that you have locked yourself out.

### Key Features

-   **Dead Man's Switch**: Before reloading SSH, it starts a background timer. If the new verify connection fails, the system automatically reverts to the old config after 60 seconds.
-   **Intelligent Honeypot Trapping**: Identifies suspicious users by **prioritizing accounts with SSH keys** (potential red team backdoors). If a Red Teamer logs in as them, they are jailed in a fake shell environment at `/bin/honeypot`, and all their commands are logged to `/root/logs/honeypot.log`. These users are locked (via `user_hardening`) so the only way they can SSH in is with an SSH key.
-   **SSH Key Archival**: Before user hardening runs, all SSH keys are archived to `/root/ssh/keys/<timestamp>/` and removed from users' `authorized_keys` files (via `archive_ssh_keys.sh`). This prevents red team from using pre-existing backdoors.
-   **Root Security**: Disables password login for root (`PermitRootLogin prohibit-password`), enforcing key-based authentication using the recovery key.
-   **Robust Rollback**: Backs up `sshd_config` and validates syntax before every restart.
-   **Smart Reload**: Detects the init system (Systemd/SysV/OpenRC/BSD) to reload SSH without dropping active connections.

## Hardening Parameters

The module applies a new configuration featuring:

*   **`Protocol 2`**: Legacy Protocol 1 is disabled.
*   **`PermitRootLogin prohibit-password`**: Root can only log in with SSH Keys (keys/test-root-key*).
*   **`PubkeyAuthentication yes`**: Enforced.
*   **`PasswordAuthentication yes`**: Kept enabled for regular users (unless you decide to disable it later).
*   **`AllowUsers ...`**: Explicit whitelist of known users + trapped users. All others are denied.
*   **`Match User <trap> ...`**: Forces suspicious users into `/bin/honeypot`.

## Module Workflow

### Phase 1: Preparation (Before SSH Hardening in Pipeline)
1.  **Discovery**: System discovery detects which users have SSH keys in `~/.ssh/authorized_keys`
2.  **Archive Keys**: `archive_ssh_keys.sh` backs up all authorized_keys files to `/root/ssh/keys/<timestamp>/` and **removes them** (except whitelisted users)
3.  **User Hardening**: Adds recovery key for root, sets passwords, locks unauthorized users

### Phase 2: SSH Hardening Module
1.  **Trap Selection**: Intelligently selects **1 user** for honeypot trapping:
    *   **Priority 1**: Unauthorized users WITH SSH keys (detected during discovery) - likely red team backdoors
    *   **Priority 2**: If no keys found, selects longest username (heuristic for non-system accounts)
    *   Selection happens BEFORE key removal, so we know which users had keys
2.  **Deploy Honeypot**: If trapped user selected:
    *   Uploads `/bin/honeypot` (blue-sweet-tooth.sh)
    *   Makes it executable and adds to `/etc/shells`
    *   Creates log directory `/root/logs/` with secure permissions
3.  **Backup**: `cp /etc/ssh/sshd_config /etc/ssh/sshd_config.fabric.backup`
4.  **Generate Config**: Creates secure config prepended to existing config
5.  **Append Trap Config**: Adds `Match User <trapped>` block forcing them into `/bin/honeypot`
6.  **Validate**: Runs `sshd -t` to ensure new config is valid syntax
7.  **Arm Dead Man's Switch**: Starts `nohup sleep 60 && mv backup config && reload...`
8.  **Reload**: Reloads the SSH daemon
9.  **Test Connection**: Attempts to connect via Python (using `test-root-key` for root)
    *   **Success**: Kills the Dead Man's Switch (Disarm) and marks server safe to reboot
    *   **Failure**: Manual rollback is attempted. If that fails, the Switch triggers in 60s

## Usage

### Primary Method (Automated)
This module runs automatically as part of the main hardening pipeline:
```bash
fab harden
```

### Manual / Testing
To run *only* this module (e.g., if you updated `users.json` and need to refresh `AllowUsers`):
```bash
fab test-module --module=ssh_hardening --live
```

## ⚠️ Important Considerations

1.  **Firewall Rules**: Ensure port 22 is allowed (handled by `firewall_hardening` and `lockdown.sh`).
2.  **Root Key**: This module effectively locks out Root Password Login. You **MUST** have the private key (`keys/test-root-key.private`) to log in as root afterwards. The `user_hardening` module automatically sets this up before SSH hardening runs.
3.  **SSH Keys Archived**: All user SSH keys are archived to `/root/ssh/keys/<timestamp>/` and removed from systems. If you want to restore a trapped user's key (to bait red team), you can restore it from the archive.
4.  **Honeypot Logs**: All commands from trapped users are logged to `/root/logs/honeypot.log`. Monitor this file for red team activity.
5.  **Pipeline Order**: The order matters:
    - Discovery → Archive Keys → User Hardening → SSH Hardening
    - This ensures we detect keys BEFORE removing them, and add root recovery key AFTER removing red team keys

## Honeypot Usage

### To Bait Red Team with Their Own Key:
If you want to use the honeypot to catch red team members:

```bash
# 1. Find the archived key
ls /root/ssh/keys/*/

# 2. Identify the trapped user from logs or SSH config
grep "Match User" /etc/ssh/sshd_config

# 3. Restore their key
TRAPPED_USER="<username>"
TIMESTAMP="<timestamp_from_ls>"
cp /root/ssh/keys/$TIMESTAMP/${TRAPPED_USER}__*__authorized_keys /home/$TRAPPED_USER/.ssh/authorized_keys
chown $TRAPPED_USER:$TRAPPED_USER /home/$TRAPPED_USER/.ssh/authorized_keys
chmod 600 /home/$TRAPPED_USER/.ssh/authorized_keys

# 4. Monitor the honeypot log
tail -f /root/logs/honeypot.log
```

When red team tries to use their backdoor key, they'll be trapped in a fake shell and all their commands will be logged.