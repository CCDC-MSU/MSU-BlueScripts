# Logging Setup Module

**Go back to [main README](../README.md)**

This module provides a comprehensive logging setup for both Linux and BSD systems, designed to capture a wide range of security-relevant events.

## Overview

The `logging_setup` module configures the native logging services on the target system to create a robust and detailed audit trail. It differentiates between Linux and BSD systems to apply the appropriate configurations.

### Key Features

-   **Centralized Logging Configuration**: Consolidates logging rules for easy management.
-   **Cross-Platform Support**: Automatically detects the OS and applies the correct logging setup for Linux and BSD.
-   **Security-Focused Logging**: Configures logging for critical security events, including authentication, `sudo` usage, and SSH activity.
-   **Log Rotation**: Sets up automatic log rotation to prevent log files from consuming excessive disk space.
-   **Persistent Logging**: On Linux systems with `systemd`, it ensures that logs are preserved across reboots.
-   **Detailed Auditing**: On Linux, it configures `auditd` to monitor a wide range of system events, including file access, privilege escalation, and network activity.

## Linux Logging Configuration

For Linux systems, the module configures the following services:

*   **`rsyslog`**: The standard syslog daemon on most Linux distributions.
    *   A new configuration file is created at `/etc/rsyslog.d/ccdc-security.conf`.
    *   Specific log files are created for different types of events, including `/var/log/auth.log`, `/var/log/secure`, `/var/log/ssh.log`, and `/var/log/sudo.log`.
*   **`systemd-journald`**: The `systemd` logging service.
    *   Configured for persistent storage, log compression, and a 30-day retention policy.
*   **`auditd`**: The Linux Auditing System.
    *   A comprehensive set of audit rules is created at `/etc/audit/rules.d/ccdc.rules`.
    *   These rules monitor changes to critical files, login/logout events, privilege escalation, and more.
*   **`logrotate`**: The standard log rotation utility.
    *   A new configuration file at `/etc/logrotate.d/ccdc-security` is created to manage the new security log files.
*   **Process Accounting**: Enables process accounting (`accton`) to log every command run on the system.
*   **Bash History**: Enhances `bash` history to include timestamps and increases the history size.

## BSD Logging Configuration

For BSD systems, the module configures the native logging tools:

*   **`syslogd`**: The standard BSD syslog daemon.
    *   The main configuration file at `/etc/syslog.conf` is updated with an enhanced ruleset.
*   **`newsyslog`**: The BSD log rotation utility.
    *   The configuration at `/etc/newsyslog.conf` is updated to rotate the new security log files.
*   **Process Accounting**: Enables process accounting to log all commands.
*   **Shell History**: Increases the history size for `csh`.

## Usage

This module is typically run as part of the main hardening pipeline. However, you can also test it individually.

*   **Test in Dry-Run Mode (Safe)**:
    ```bash
    fab test-module --module=logging_setup
    ```

*   **Execute in Live Mode**:
    ```bash
    fab test-module --module=logging_setup --live
    ```
