# User Hardening Module

**Go back to [main README](README.md)**

This is modules manages user access, credentials, and persistence.

## Overview

The User Hardening Module (`user_hardening.py`) ensures that only authorized users exist on the system, that they have secure credentials, and that the Blue Team maintains root through both password and sshkey.

### Key Features

-   **Root Access Persistence** (CRITICAL): Automatically injects a local SSH key (`keys/test-root-key.pub`) into `/root/.ssh/authorized_keys` *before* changing any passwords. This ensures we don't lock ourselves out.
-   **Password Rotation**: Generates and applies complex passwords for all authorized users.
-   **Sudoers Sanitation**: Revokes `sudo` access from unauthorized users and grants it only to valid `super_users`.
-   **Account Locking**: Locks unauthorized accounts (valid shell but not in config) to neutralize Red Team backdoors.
-   **Logging**: Saves all generated passwords to `logs/user-hardening/<host>/passwords_<timestamp>.txt` on the Jump Box.

## Configuration: `users.json`

The module checks `fabric_deploy/users.json` to classify users.

```json
{
  "regular_users": {
    "jon": "password_for_jon_to_use_on_all_hosts",
    "jack": ""  # a complex password will be generated and used across all the hosts (this is to mimic domain joined machines, same password works everywhere)
  },
  "super_users": {
    "dradmin": "StrongStaticPassword!",
    "root":"__PER_HOST__"   # have a differnt password per host for root
  },
  "do_not_change_users": {
    "BTA": "black team service account"
  }
}
```

*   **`__PER_HOST__`**: If used as a password value, the module generates a unique random password for that user on each host.
*   **`do_not_change_users`**: Critical safety list. Users here are **ignored** by password changes and locking logic. **ALWAYS** put Black Team/Scoring Engine accounts here.

## Module Workflow

1.  **Inject Root Key**: Checks if `keys/test-root-key.pub` is in `/root/.ssh/authorized_keys`. If not, adds it. Updates the active connection to use the private key.
2.  **Load Config**: Reads `users.json`.
3.  **Super Users**: Ensures they exist, adds to sudoers, sets password.
4.  **Regular Users**: Ensures they exist, **removes** from sudoers, sets password.
5.  **Lock Unknowns**: Finds any user with a valid shell (`/bin/bash`, `sh`, etc. (dynamically tested through su $user)) not in your lists and runs `usermod -L` / `chsh -s /sbin/nologin`.
6.  **Log Passwords**: Dumps the new credentials to a local file.

## Usage

### Primary Method (Automated)
This module runs automatically as part of the main hardening pipeline:
```bash
fab harden
```

### Manual / Testing
To run *only* this module (e.g., to fix broken users):
```bash
fab test-module --module=user_hardening --live
```

## ⚠️ Important Considerations

1.  **Do Not Lock Out The Scoring Engine**: Use `do_not_change_users` for any account required by the competition (check your packet!).
2.  **Root Access**: The script sets `root` access via SSH key. You should use `ssh -i keys/test-root-key.private root@<host>` if the password fails.