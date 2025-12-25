# User Hardening Module

**Go back to [main README](README.md)**

This is one of the most important modules in the CCDC framework, providing comprehensive user account security management.

## Overview

The User Hardening Module (`user_hardening.py`) is a core component of the CCDC Hardening Deployment Framework. It provides an automated and configurable way to manage user accounts and privileges on target systems.

### Key Features

-   **Authorized User Management**: Uses a central configuration file to define regular, super, and protected accounts and creates missing users.
-   **Comprehensive Sudo Control**: Grants and revokes `sudo` access based on discovered sudoers entries and group membership.
-   **Password Management**: Uses `users.json` passwords for all authorized users (except do-not-change accounts), generates missing ones, supports per-host unique passwords, and logs them locally.
-   **Unauthorized User Security**: Locks any account with a valid shell that is not defined in the configuration (no deletion).
-   **Protected Account Safety**: Skips any account listed in `dontchange_accounts`.
-   **Cross-Platform Support**: Works on both Linux and BSD/Unix systems.

## Configuration: `users.json`

The module reads `fabric_deploy/users.json` and uses it to define three categories of users. Values are treated as passwords; missing values are generated and written back. Use `__PER_HOST__` to request per-host unique passwords without writing back.

```json
{
  "regular_users": {
    "jon": "StrongPassword1!",
    "jack": "__PER_HOST__"
  },
  "super_users": {
    "dradmin": "StrongPassword2!",
    "mr-it": "__PER_HOST__"
  },
  "dontchange_accounts": {
    "black-team-acc": "do not change",
    "scan-agent": "do not change",
    "root": "system account - do not modify"
  }
}
```

*   **`regular_users`**: Standard user accounts that should exist on the system but should **not** have `sudo` privileges.
*   **`super_users`**: Administrative accounts that are granted `sudo` privileges.
*   **`dontchange_accounts`**: A list of accounts that the script should never modify. This is crucial for protecting system accounts, service accounts, and any accounts used by the competition scoring engine.
*   **Per-host unique passwords**: Set the value to `__PER_HOST__` to generate a unique password on each host (these values are not written back to `users.json`).

## Module Workflow

1.  **Load Configuration**: Reads `users.json`, populates missing passwords (writing them back), and identifies regular, super, and do-not-change accounts (per-host sentinel values are preserved).
2.  **Resolve Current Sudo Access**: Builds the current sudo user set from sudoers data and group membership.
3.  **Enforce Super Users**: Ensures each super user exists, sets the configured password, and grants sudo access.
4.  **Enforce Regular Users**: Ensures each regular user exists, sets the configured password, and removes any sudo access.
5.  **Lock Unauthorized Users**: Locks any discovered user with a valid shell that is not in `users.json` (excluding do-not-change accounts).
6.  **Write Password Log**: Writes passwords used to `logs/user-hardening/<host>/passwords_<timestamp>.txt` on the jump box.

## Discovery Context

-   Uses `UserInfo.valid_shell` to determine which discovered users are eligible for password/access enforcement.
-   Uses the `sudoers` block (dump + parsed lists) to resolve current sudo access before enforcing changes.

## Usage

It is highly recommended to always test this module in dry-run mode before applying any changes.
The default hardening pipeline in `utilities/deployment.py` does not include `user_hardening`; run it via `fab test-module` or add it to the orchestrator.

*   **Test in Dry-Run Mode (Safe)**:
    ```bash
    fab test-module --module=user_hardening
    ```

*   **Execute in Live Mode**:
    After you have reviewed the dry-run output and are confident in the changes, run the module in live mode.
    ```bash
    fab test-module --module=user_hardening --live
    ```

## Important Considerations

*   **Review `users.json` Before Deployment**: Ensure that all authorized users, including any service or competition accounts, are correctly listed in the `dontchange_accounts` section.
*   **Passwords in `users.json`**: Values are treated as passwords; missing values are generated and written back. Use `__PER_HOST__` for per-host unique passwords.
*   **Missing Users**: This module creates missing users in `regular_users` or `super_users`, using `/bin/sh` as the default shell.
*   **System Accounts**: Any account with a valid shell that is not listed in `users.json` is locked, including service/system accounts. Add them to `dontchange_accounts` if they must remain active.
*   **Coordinate with Your Team**: Make sure that the user and password configuration meets the requirements of your team.
*   **Securely Document Passwords**: `users.json` contains passwords (some auto-populated) and generated passwords are stored locally under `logs/user-hardening/` on the jump box; treat both as sensitive.
