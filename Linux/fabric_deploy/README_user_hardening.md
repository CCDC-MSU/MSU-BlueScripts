# User Hardening Module

**Go back to [main README](../README.md)**

This is one of the most important modules in the CCDC framework, providing comprehensive user account security management.

## Overview

The User Hardening Module (`user_hardening.py`) is a core component of the CCDC Hardening Deployment Framework. It provides an automated and configurable way to manage user accounts and privileges on target systems.

### Key Features

-   **Authorized User Management**: Creates and manages regular and super users based on a central configuration file.
-   **Comprehensive Sudo Control**: Grants and revokes `sudo` access with a high degree of reliability.
-   **Password Management**: Sets secure, predefined passwords for all authorized users.
-   **Unauthorized User Security**: Automatically locks and disables any user accounts not defined in the configuration.
-   **Protected Account Safety**: Preserves critical system, competition, and service accounts.
-   **Cross-Platform Support**: Works on both Linux and BSD/Unix systems.

## Configuration: `users.json`

The module is controlled by the `users.json` file, which defines three categories of users:

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

The module follows a 15-step security process to ensure that user accounts are configured securely and reliably:

1.  **Backup User Files**: Creates timestamped backups of `/etc/passwd`, `/etc/shadow`, and other critical user files.
2.  **Create Users**: Adds any users from `regular_users` and `super_users` that do not already exist.
3.  **Manage Sudo Access**: Removes `sudo` privileges from all regular users and grants them to all super users.
4.  **Set Passwords**: Sets the passwords for all users in `regular_users` and `super_users` to the values specified in `users.json`.
5.  **Secure Unauthorized Users**: Any user account on the system that is not listed in `users.json` will be automatically locked and have its shell disabled.
6.  **Generate Security Report**: Creates a detailed report of all actions taken, saved to `/root/user_security_report.txt` on the target machine.

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
*   **Coordinate with Your Team**: Make sure that the user and password configuration meets the requirements of your team.
*   **Securely Document Passwords**: The passwords in `users.json` are stored in plain text. Make sure to handle this file securely and share the passwords with your team through a secure channel.
