# Test Environment & Vulnerability Verification Guide

This document describes the test environment setup (`setup_test_env`) and how it helps verify the effectiveness of the hardening steps.

## Purpose
The **Test Environment Setup** injects specific vulnerabilities, artifacts, and misconfigurations into a target system. This allows the Blue Team to:
1.  Verify that hardening scripts correctly detect and remediate issues.
2.  Review logs and reports to ensure visibility of compromised states.
3.  Simulate a "compromised" baseline similar to a CCDC scenario.

## Usage

### 1. Compromise the System (Inject Vulnerabilities)
Run the following command to inject vulnerabilities into the hosts defined in `hosts.txt`:
```bash
fab setup-test-env
```
**Warning**: This will actively weaken the security of the target hosts. **DO NOT RUN ON PRODUCTION SYSTEMS.**

### 2. Verify Compromise
Check the target systems for the presence of artifacts (see table below).

### 3. Harden the System (Apply Fixes)
Run the hardening suite to remediate the vulnerabilities:
```bash
fab harden
```

### 4. Verify Remediation
Check the reports in `logs/reports/` and verify that the vulnerabilities have been removed or mitigated.

---

## Vulnerability to Remediation Mapping

The following table maps each injected vulnerability to the expected action taken by `fab harden`.

| Component | Injected Vulnerability | Expected Hardening Outcome | Verifying Module/Script |
| :--- | :--- | :--- | :--- |
| **User/Auth** | User `hacker` created with weak password (`password123`). | Password changed to CCDC standard. Account potentially locked if not in `users.json`. | `user_hardening` |
| **User/Auth** | User `hacker` granted NOPASSWD sudo access. | Sudoers file overwritten/sanitized. `hacker` user sudo access removed (unless added to `users.json` admins). | `user_hardening` |
| **SSH** | `PermitRootLogin yes`, `PasswordAuthentication yes` in `sshd_config`. `AllowUsers` restriction removed. | `sshd_config` reverted to secure state (Root deny, Password deny/limited, AllowUsers enforced). Service reloaded. | `ssh_hardening` |
| **SSH Keys** | Dummy public key added to a user's `authorized_keys`. | `authorized_keys` file archived and cleared (or key removed). | `archive_ssh_keys.sh` |
| **Firewall** | Firewall rules flushed (IPTables/NFTables) or service stopped. | Firewall enabled (UFW/Firewalld/IPTables), rules reset to default deny, SSH allowed from trusted IPs. | `firewall_hardening` / `lockdown.sh` |
| **Services** | `auditd` package uninstalled. | `auditd` package re-installed. | `package_installer` |
| **Services** | Malicious systemd service `/etc/systemd/system/backdoor.service` created. | Service identified by `systemd-hunting.sh` and logged in report. (Note: currently reports, may not auto-delete). | `systemd-hunting.sh` |
| **Logging** | CCDC rsyslog config removed/renamed. | CCDC rsyslog config restored (`ccdc-security.conf`) and service restarted. | `logging_setup` |
| **Agent** | `scan-agent` user removed. | `scan-agent` user re-created with correct privileges and keys. | `agent_account` |
| **Files** | Suspicious media files (`.mp4`, `.jpg`) created in `/home`. | Files identified and listed in report/log. | `find_media.sh` |
| **Files** | Fake Go binary (`go1.` string) created in `/tmp`. | Binary identified and listed in report/log. | `check-go-binaries.sh` |
| **Files** | Fake PII file (`pii_data.txt`) created in `/home`. | File identified and listed in report/log. | `search-pii.sh` |
| **Files** | `/etc/shadow` permissions set to `644` (World Readable). | Permissions fixed to `640` or `600` (root:shadow). | `fix-file-permissions.sh` |
| **Config** | Malicious environment variables (`LD_PRELOAD`) in `/etc/profile.d/bad_env.sh`. | Identified and logged. (Note: script flags it, manual removal may be required for complex cases). | `environment-variables-scanner.sh` |
| **Config** | `pam_permit.so` added to `/etc/pam.d/common-auth`. | dangerous PAM usage flagged in report. | `pam_audit.sh` |
| **Config** | `php.ini` set to `allow_url_include = On`. | `php.ini` appended with secure settings (`allow_url_include = Off`, etc.). | `secure-php.sh` |
| **Cron** | Suspicious cron job (`/bin/bash ...`) added to `/etc/cron.d/backdoor`. | Cron job archived and removed/moved to quarantine. | `archive_cronjobs.sh` |
| **Shell** | Malicious alias (`alias sudo='sudo -s'`) added to `.bashrc`. | Alias identified and flagged in report (or `.bashrc` sanitized if user profile compiler active). | `user-profiles-compiler.sh` |

## Troubleshooting

- **Fabric Connection Failed**: If `fab setup-test-env` fails to connect, ensure the `hosts.txt` has correct initial credentials. Note that if you run `fab harden` first, it might have changed passwords or SSH keys!
- **Setup Partial Failure**: If some steps fail, run with `-d` (debug) or check the remote logs in `/root/hardening-logs/`.
- **"Safe to Reboot" Checks**: The environment setup might trigger "safe to reboot" flags in the system discovery if it detects critical changes, but primarily this flag is set by the hardening process itself.
