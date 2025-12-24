# User Hardening Module

**Go back to [main README](README.md)**

This is one of the most important modules in the CCDC framework, providing comprehensive user account security management.

## Overview

The User Hardening Module (`user_hardening.py`) is a core component of the CCDC Hardening Deployment Framework. It provides an automated and configurable way to manage user accounts and privileges on target systems.

### Key Features

-   **Authorized User Management**: Uses a central configuration file to define regular, super, and protected accounts; it does not create missing users.
-   **Comprehensive Sudo Control**: Grants and revokes `sudo` access with a high degree of reliability across Linux and BSD.
-   **Password Management**: Sets secure, predefined passwords for all authorized users.
-   **Unauthorized User Security**: Disables login shells for any accounts not defined in the configuration without deleting them.
-   **Protected Account Safety**: Preserves only the accounts listed in `dontchange_accounts`.
-   **Cross-Platform Support**: Works on both Linux and BSD/Unix systems.

## Configuration: `users.json`

The module reads `fabric_deploy/users.json` and uses it to define three categories of users:

```json
{
  "regular_users": {
    "jon": "SecureJon2024!",
    "jack": "JackSecure2024!"
  },
  "super_users": {
    "dradmin": "DrAdmin2024!Secure",
    "mr-it": "MrIT2024!Password"
  },
  "dontchange_accounts": {
    "black-team-acc": "do not change password",
    "scan-agent": "do not change password",
    "root": "system account - do not modify"
  }
}
```

*   **`regular_users`**: Standard user accounts that should exist on the system but should **not** have `sudo` privileges.
*   **`super_users`**: Administrative accounts that are granted `sudo` privileges.
*   **`dontchange_accounts`**: A list of accounts that the script should never modify. This is crucial for protecting system accounts, service accounts, and any accounts used by the competition scoring engine.

## Module Workflow

1.  **Backup User Files**: Creates timestamped backups of `/etc/passwd` and `/etc/shadow` (or `/etc/master.passwd` on BSD).
2.  **Manage Sudo Access**: Removes `sudo` privileges from all `regular_users` and grants them to all `super_users`.
3.  **Set Passwords**: Sets the passwords for all users in `regular_users` and `super_users` to the values specified in `users.json`.
4.  **Secure Unauthorized Users**: Any account not listed in `users.json` has its login shell set to `/bin/false` or `/usr/sbin/nologin` (no deletion).
5.  **Generate Security Report**: Creates `/root/user_security_report.txt` with the final state.

## Discovery Context

-   Uses the discovered default shell and OS family to select platform-appropriate commands.
-   Discovery summaries include a `sudoers` block (dump + parsed lists) for auditing current sudo access before running this module.

## Usage

It is highly recommended to always test this module in dry-run mode before applying any changes.

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
*   **Missing Users**: This module does not create accounts; missing users in `regular_users` or `super_users` can cause command failures.
*   **System Accounts**: Any account not listed in `users.json` may have its shell disabled, including service/system accounts. Add them to `dontchange_accounts` if they must remain active.
*   **Coordinate with Your Team**: Make sure that the user and password configuration meets the requirements of your team.
*   **Securely Document Passwords**: The passwords in `users.json` are stored in plain text. Make sure to handle this file securely and share the passwords with your team through a secure channel.
