# SSH Hardening Module

**Go back to [main README](README.md)**

This module provides a robust and safe way to harden the SSH configuration on target systems. It includes features for automatic backup, validation, and rollback to prevent accidental lockouts.

## Overview

The `ssh_hardening` module applies a set of security best practices to the `sshd_config` file. It is designed to be run on a wide range of Linux and BSD systems.

### Key Features

-   **Secure Configuration**: Applies a strong set of default security parameters to the SSH daemon.
-   **Automatic Backup**: Creates a timestamped backup of the `sshd_config` file before making any changes.
-   **Configuration Validation**: Validates the new SSH configuration before applying it to prevent syntax errors.
-   **Safe Reload**: Reloads the SSH service when possible and falls back to restart if reload is unavailable.
-   **Connectivity Testing**: After applying the new configuration, the module attempts a new SSH connection using the same credentials to verify access.
-   **Automatic Rollback**: If the connectivity test fails, the module restores the newest backup and restarts SSH.

## Hardening Parameters

The module applies the following security settings to `/etc/ssh/sshd_config`:

*   `PermitRootLogin no`: Disables direct login for the `root` user.
*   `PermitEmptyPasswords no`: Prevents users with empty passwords from logging in.
*   `ChallengeResponseAuthentication no`: Disables challenge-response authentication.
*   `X11Forwarding no`: Disables X11 forwarding to prevent potential security risks.
*   `MaxAuthTries 5`: Limits the number of authentication attempts per connection.
*   `ClientAliveInterval 300`: Sets a timeout interval for idle client connections.
*   `ClientAliveCountMax 2`: Sets the number of client alive messages that can be sent without receiving a response.
*   `Protocol 2`: Forces the use of the more secure SSH protocol version 2.

## Discovery Context

-   Uses the discovered default shell when writing SSH configuration changes.
-   Uses the discovered OS family to choose the SSH reload command.
-   Discovery summaries include a `sudoers` block (dump + parsed lists) for privilege auditing alongside SSH changes.

## Usage

This module is typically run as part of the main hardening pipeline, but it can also be tested individually.

*   **Test in Dry-Run Mode (Safe)**:
    ```bash
    fab test-module --module=ssh_hardening
    ```

*   **Execute in Live Mode**:
    ```bash
    fab test-module --module=ssh_hardening --live
    ```

## Important Considerations

*   **Firewall Rules**: Ensure that your firewall rules allow SSH traffic (usually on port 22). If you change the SSH port, you will need to update your firewall rules accordingly.
*   **Key-Based Authentication**: This module does not enforce key-based authentication by default, but it is highly recommended. You can add `PasswordAuthentication no` to the `ssh_params` in the script to enforce key-based authentication.
*   **`AllowUsers` Directive**: The `TODO` in the script mentions explicitly allowing only authorized users to log in via SSH using the `AllowUsers` directive. This is a very effective security measure that you can add to the module for even tighter security.
