# CCDC Fabric Hardening System: Blue Team Guide
**"Run and Forget" Automated Defense**

## 1. Introduction
This system is designed to **automatically discover, profile, and secure** our remote Linux/Unix/BSD systems. This tool provides a robust baseline configuration without requiring manual intervention on every host.

**Philosophy**:
- **Automated**: One command to harden all Linux/bsd hosts.
- **Idempotent**: Can be run multiple times without breaking things.
- **Safe**: Includes built-in connection tests and "Dead Man's Switches" to prevent locking ourselves out.

---

## 2. The Setup (T-30 Minutes)
The **Operator** on the Jump Box is responsible for these files. All Blue Teamers should verify their credentials here.

### `hosts.txt`
The inventory of our target systems. This inventory will be gathered from the packet provided to us.
```text
# Format: IP:User:Password:FriendlyName
192.168.1.10:root:password123:Web-Server
192.168.1.20:admin:adminpass:Database
```
*Tip: Use the `FriendlyName` (e.g., "Web-Server") to make logs/reports readable.*

### `users.json`
The central authority for user management. This file dicates what users exist on the system, and again the information can be gathered from the packet provided.
- **regular_users**: Standard team accounts (e.g., individual Blue Team members).
- **super_users**: Admin/Sudo accounts (all the admin users (includes root and blue-team-agent)).
- **do_not_change_users**: Black team accounts that we should not touch

---

## 3. The Workflow (Automated)

### The "One-Click" Method
We have consolidated discovery, lockdown, and hardening into a single pipeline.
```bash
fab harden
```
*(Runs in parallel on all hosts defined in `hosts.txt`)*

**What actually happens (The Pipeline):**
1.  **Discovery**: Automatically profiles the system (OS, Users, Services) to decide which commands to run.
2.  **Snapshot**: Backs up critical files and system state to `/root/pre-hardening-snapshot/`.
3.  **User Hardening (Round 1)**: 
    - Changes passwords for all users (except those in `do_not_change_users`) to prevent immediate access by Red Team.
    - Saves new passwords to `logs/user-hardening/<host>/passwords_<date>.txt`.
4.  **Firewall Setup**: 
    - Installing/Enabling the appropriate firewall (ufw/firewalld/iptables).
    - Blocks ALL incoming traffic except SSH from our Trusted IPs.
5.  **Lockdown Script**: 
    - Runs `lockdown.sh` as a secondary enforcement layer.
    - Blocks new outbound connections (stops reverse shells).
6.  **SSH Hardening**: 
    - Configures `sshd_config` (Protocol 2, PubKey only).
    - Sets up "Honeypot Traps" for suspicious users.    (max of 2 per system, check Linux/fabric_deploy/utilities/modules/ssh_hardening.py and /home/antimony/Desktop/cyber/repos/MSU-BlueScripts/Linux/fabric_deploy/scripts/helpers/blue-sweet-tooth.sh for more information)
    - **Dead Man's Switch**: Reverts changes if connection is lost.
7.  **Script Uploads**: Pushes helper scripts to `/root/scripts`.
8.  **Local Fixes**: Runs offline scripts like `fix-file-permissions.sh`.
9.  **Reboot**: Clears memory-resident malware.
10. **User Hardening (Round 2)**: Rotates passwords *again* post-reboot to ensure no malware captured them.
11. **Allow Internet**: Relaxes firewall for updates (`lockdown.sh --allow-internet`).  (everything up to this point should take no more than a couple of minutes)
12. **Install & Update**: Installs various packages, and updates packages.
13. **Logging Setup**: Configures `auditd` and `rsyslog` for deep visibility.
14. **Final Snapshot**: Captures the hardened state.

---

## 4. Operational Maintenance

### Viewing Logs & Reports
*   **Logs**: `logs/harden/<friendly_name>/<timestamp>.log` - Detailed execution logs.
*   **Logs**: `/root/script-logs/{scriptname}-{time}.log` - Contains the stdout from the individual scripts ran. (think find_media.sh or environment-variable-scanner.sh)
*   **Reports**: `reports/<friendly_name>/<timestamp>.md` - High-level summary for the team.
    *   *Check this report for a concise list of what changed on your box!*

### Next steps
*   **Run tools**: Run tools uploaded to `/root/tools/` (an example would be diff-changes.sh) this shows you a diff for the important files against the snapshots taken previously.
*   **Harden services**: Figure out what's running, harden it (don't forget to change passwords)
*   **Open up to traffic**: Now you can allow scoring engines to reach your machines
*   **Watch logs**: Hopefully everything went smoothly and now all you have to do is look at the logs, hunt for threats and complete injects!

### Troubleshooting
1.  **"Hardening pipeline failed on Host Y"**
    *   Unfortunately there is no way to completely automate every single possible configuration of Linux/ BSD environments, so we must be ready in case automated hardening fails.
    *   The system is modular; failure in one step (e.g., logging) often allows others to complete.
    *   Coordinate with the one running the automated hardening tool to see which steps failed, and complete them manually.

---

**Summary**:
1.  **Update Configs** (`hosts.txt`, `users.json`).
2.  **Run** (`fab harden`).
3.  **Verify** (Check `reports/`).
