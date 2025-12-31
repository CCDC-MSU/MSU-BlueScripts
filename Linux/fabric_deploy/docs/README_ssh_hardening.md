# SSH Hardening Module

**Go back to [main README](README.md)**

This module secures remote access, often the most attacked service in CCDC. It includes a safety mechanisms ("Dead Man's Switch") and aggressive defense tactics (Honeypot Traps).

## Overview

The `ssh_hardening` module replaces the default insecurity of `sshd_config` with a known good configuration. It is designed to be "safe by default," meaning it will automatically roll back changes if it detects that you have locked yourself out.

### Key Features

-   **Dead Man's Switch **: Before reloading SSH, it starts a background timer. If the new verify connection fails, the system automatically reverts to the old config after 60 seconds.
-   **Honeypot Trapping **: Identifies the "most suspicious" users (often unused accounts) and traps them. If a Red Teamer logs in as them, they are jailed in a harmless environment, and all their commands are logged. These users are locked so only way they could ssh in is if they have a ssh key.
-   **Root Security**: Disables password login for root (`PermitRootLogin prohibit-password`), enforcing key-based authentication.
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

1.  **Backup**: `cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.<date>`
2.  **Generate Config**: Creates a secure config and appends "Trapped User" blocks.
    *   *Trap Selection Logic*: Finds valid users NOT in `users.json`. Picks the top 2 longest usernames (heuristic that they are not system accounts like `lp` or `mail`) and traps them. (we may add better huristics like checking if they have ssh keys)
3.  **Validate**: Runs `sshd -t` to ensure the new config is valid syntax.
4.  **Arm Switch**: Starts `nohup sleep 60 && mv backup config && reload...`.
5.  **Reload**: Reloads the SSH daemon.
6.  **Test Connection**: Attempts to connect via Python (using `test-root-key` if testing root).
    *   **Success**: Kills the Dead Man's Switch (Disarm).
    *   **Failure**: Manual rollback is attempted. If that fails, the Switch triggers in 60s.

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
2.  **Root Key**: This module effectively locks out Root Password Login. You **MUST** have the private key (`keys/test-root-key.private`) to log in as root afterwards. (by default the user_hardening modules sets a key for the root user)
3.  **Honeypot**: `/bin/honeypot` (or similar) exists or is a symlink to Linux/fabric_deploy/scripts/helpers/blue-sweet-tooth.sh