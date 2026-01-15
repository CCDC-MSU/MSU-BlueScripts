# Scripts Overview

This directory contains standalone shell scripts used for system hardening, auditing, and maintenance. Most of these are used by the Fabric deployment system but can also be run manually on target hosts.

## Firewall & Network

### `lockdown.sh`
**Purpose**: The primary "Panic Button" script. Immediately locks down network access.
- **Default Mode**: Blocks all incoming traffic except SSH from trusted IPs defined in the script.
- **Allow Internet Mode** (`--allow-internet`): Blocks incoming traffic but allows outbound connections (DNS, HTTP/S, NTP).
- **Features**: 
    - Supports multiple backends: `iptables`, `nftables`, `pf` (BSD), `ipfw` (BSD), `firewalld`.
    - Includes a "Safety Net" that reverts changes after 60 seconds if not cancelled (to prevent locking yourself out).

### `setup_firewall.sh`
**Purpose**: Prepares the firewall system before hardening begins.
- **Function**: Detects the available firewall tool (firewalld, ufw, nft, iptables, pf, ipfw) and ensures it is enabled and running.
- **Safety**: Sets the default policy to ALLOW ALL (or trusted) to ensure the service is active without accidentally cutting off access before the rules are properly configured.

## Auditing & Forensics

### `pre-hardening-snapshot.sh`
**Purpose**: Creates a comprehensive system state backup before any hardening actions are taken.
- **Captures**: configuration files (`/etc`), user databases, running processes, network connections, open ports, and installed packages.
- **Location**: Saves backups to `/root/pre-hardening-backups/<timestamp>`.

### `systemd-hunting.sh`
**Purpose**: Deep scans systemd unit files for signs of compromise or persistence.
- **Checks**: Root execution of network services, recent modifications, executions from `/tmp`, obfuscated commands (base64, etc.), remote downloads (`curl`/`wget`), and suspicious timers.
- **Output**: Generates a detailed audit log in `/var/log`.

### `user-profiles-compiler.sh`
**Purpose**: Audits user shell profiles for malicious content.
- **Function**: Aggregates system-wide (`/etc/profile`, etc.) and user-specific (`.bashrc`, `.profile`) configuration files into a single readable file per user.
- **Checks**: Scans for vulnerabilities like piped remote commands, dangerous aliases, and credential exposure.

### `environment-variables-scanner.sh`
**Purpose**: Hunts for suspicious environment variables that could indicate compromise.
- **Checks**: Scans running processes, system files, and user homes for variables like `LD_PRELOAD`, `LD_LIBRARY_PATH`, and others often used in malware or privilege escalation.

### `pam_audit.sh`
**Purpose**: security audit of Pluggable Authentication Modules (PAM).
- **Checks**: Scans for dangerous configurations like `pam_exec.so` (arbitrary command execution), `nullok` (empty passwords), and `pam_rootok.so`. Verifies file permissions and stack order.

### `check-go-binaries.sh`
**Purpose**: Forensic helper to identify Go executables.
- **Function**: Searches the filesystem for files larger than 1MB that contain the string "go1.", which can help identify unmanaged or suspicious Go binaries.

### `find_media.sh`
**Purpose**: Locates media files on the system.
- **Function**: Scans `/home` directories for common image, video, and document formats and saves the list to `~/media_files.txt`.

### `search-pii.sh`
**Purpose**: Scans for Personally Identifiable Information (PII).
- **Features**: Uses Regex/PCRE to find patterns resembling Credit Card numbers, SSNs, phone numbers, and addresses in files.

## Maintenance & Hardening

### `fix-file-permissions.sh`
**Purpose**: Audits and fixes filesystem permissions.
- **Targets**: Critical files like `/etc/passwd`, `/etc/shadow`, SSH configurations, and boot config.
- **Action**: Reports on insecure permissions and attempts to fix them to standard secure values (e.g., `600` for `shadow`).

### `archive_cronjobs.sh`
**Purpose**: Quarantines existing cron jobs.
- **Action**: Moves user crontabs and system cron files (`/etc/cron.d`, etc.) to an archive directory (`/root/archive/cronjobs`), effectively disabling them until they can be reviewed and manually restored.

### `archive_ssh_keys.sh`
**Purpose**: Secures SSH access by archiving existing authorized keys.
- **Action**: Moves `authorized_keys`, `shosts`, and `hosts.equiv` files for all users to a backup location (`/root/ssh/keys`). 
- **Exclusions**: respecting a whitelist of users (default: root, admin, deploy) who retain their keys.

### `secure-php.sh`
**Purpose**: Hardens PHP configuration.
- **Action**: Finds `php.ini` files and appends security directives to disable dangerous functions (`exec`, `system`, etc.), turn off `register_globals`, and restrict file operations.
