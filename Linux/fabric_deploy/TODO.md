# **Project TODO & Bug List**

## 0. Start Contributing Now

* a few of the modules have TODO lines in them, those might be the easiest to work on
* need proper readme for modules


## 1. Known Bugs

* NO Known bugs, update if found

---

## 2. Things to Watch Out For

* Clear apt cache after usage.
* Change default passwords for all applications and databases.

---

## 3. Nice Ideas / Quality-of-Life

* Alert users via `wall`, e.g.:

  ```bash
  wall <<< "!WARNING SOMEONE MODIFIED FILE pathtofile!"
  ```
* Provide a list of shortened URLs for common resources.
* Include cheat sheets for critical tools/commands.
* Maintain a list of known/standard users per OS.
* Maintain a list of known/standard services per OS.
* Monitor **outbound** network connections.
* Explore CAPRICA (ACL generator).

---

## 4. Good to Have

* Proper logging to files instead of dumping everything to stdout.

---

## 5. Tools to setup (maybe?)

* **Suricata**
* **Wazuh**

---

## 7. System Checks & Data Gathering

* Check SSH keys for each user.
* List installed packages.
* Gather:

  * Unit files
  * Processes
  * Open ports
  * Users
  
---

## 8. Hardening Enhancements    (it might be hard to implement this)

* Compare against a **known-good list**:

  * Processes
  * Open ports  (need to have a list of running processes first)
  * Connections
    Flag any unknown entries.

* Post-hardening monitoring:

  * Watch for new processes/ports.
  * Alert on any sudo operation.    (this is were the wall command could be used)
* Implement safe-change checks:

---

## 9. BSD-Specific

* Boot directly into production mode.

---

## 10. Hardening System Changes

* Add support for background tasks. (might want to install packages in background)

---

## 11. To Test  (need to go over these modules with a fine comb and make sure they work as intended)

### Agent Account

* Create `scan-agent` account with sudo permissions.
* Run commands from this account after creation.
* Store its password as a global variable.

### Install Useful Packages (i think we can shrink the list of packages being installed right now)

* Create a package-installation module.
* Detect and use the correct package manager.

---

## 12. User Hardening Module

* Reads from `users.json`:

```json
[{
  "regular_users": {
    "jon": "jon'spassword",
    "jack": "jack'spassword"
  },
  "super_users": {
    "dradmin": "dradminspassword",
    "mr-it": "mrit's password"
  },
  "dontchange_accounts": {
    "black-team-acc": "do not change password",
    "scan-agent": "do not change password"
  }
}]
```

Rules:

* Regular users → no sudo access. Remove from all sudo groups.
* Super users → must have sudo access.
* All users → assign new password (unless in `dontchange_accounts`).
* Lock accounts not in `users.json` (excluding system accounts).
* Works on both Linux and BSD/Unix-like systems.

---

## 13. Improvements

### SSH Module

* Backup SSH config.
* Revert if test fails (cron job option).
* Properly test new sessions before restarting SSH.
* Fix: `Failed to restart sshd.service: Interactive authentication required`.

### Firewall Hardening

* Prefer iptables over UFW (more common support).
* Backup current UFW settings before reset.
* Fix: root privileges required for firewall enable.
* Log open ports to file.
* Log installed services.
* Restrict both ingress & egress traffic.

---

## 14. SSH Hardening Module

* Restrict which users can SSH.
* Disable root login.
* Verify SSH config file permissions.
* Disable empty passwords.
* `AllowTcpForwarding no`.
* Disable DNS lookups.
* Disable PAM.
* Check for active SSH connections (reboot kills them).

---

## 15. Cron Job Management

* Detect all existing cron jobs.
* Backup cron configurations (support Linux + BSD/Unix).

contact me for the hosts.txt file.