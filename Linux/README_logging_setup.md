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

## Log Files Explained

Linux

   * `/etc/rsyslog.conf.backup.$(date +%Y%m%d_%H%M%S)`: A backup of the original rsyslog configuration file.
   * `/etc/rsyslog.d/ccdc-security.conf`: configuration file for rsyslog that contains the logging rules.
   * `/var/log/messages`: General, non-critical system messages.
   * `/var/log/secure`: Privileged authentication and security-related messages.
   * `/var/log/maillog`: Logs from the mail server.
   * `/var/log/cron`: Logs related to scheduled tasks (cron jobs).
   * `/var/log/auth.log`: Detailed authentication and authorization events.
   * `/var/log/kern.log`: Messages from the Linux kernel.
   * `/var/log/daemon.log`: Logs from background services (daemons).
   * `/var/log/syslog`: A general-purpose log file for system events.
   * `/var/log/ssh.log`: All connection attempts and activities related to the SSH daemon.
   * `/var/log/sudo.log`: A log of all commands executed with sudo.
   * `/etc/systemd/journald.conf.d/ccdc.conf`: Configuration for the systemd journal, making logs persistent across reboots and enabling compression.
   * `/etc/audit/rules.d/ccdc.rules`: A set of rules for the auditd service to monitor file changes, privilege escalation, and other security-sensitive events.
   * `/etc/logrotate.d/ccdc-security`: Configuration for logrotate to manage and rotate the new security log files.
   * `/var/log/pacct`: Process accounting logs, which record every command executed on the system.
   * `/etc/bash.bashrc`: System-wide configuration for the bash shell, modified to add timestamps to command history.

  BSD

   * `/etc/syslog.conf.backup.$(date +%Y%m%d_%H%M%S)`: A backup of the original BSD syslog.conf file.
   * `/etc/syslog.conf`: The main configuration file for the syslogd daemon on BSD.
   * `/var/log/messages`: General system messages.
   * `/var/log/security`: Security-related events.
   * `/var/log/auth.log`: Authentication and authorization logs.
   * `/var/log/authpriv`: Privileged authentication logs.
   * `/var/log/maillog`: Mail server logs.
   * `/var/log/cron`: Logs from cron jobs.
   * `/var/log/daemon.log`: Logs from background services.
   * `/var/log/kern.log`: Kernel messages.
   * `/var/log/ssh.log`: Logs from the SSH daemon.
   * `/etc/newsyslog.conf`: Configuration for newsyslog (the BSD log rotator), modified to include the new security logs.
   * `/var/account/acct`: Process accounting logs.
   * `/etc/csh.cshrc`: System-wide configuration for the csh shell, modified to increase command history size.

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
