# helper scripts are meant to be run by individuals on the actual box for active threat hunting / hardening

# trace-process-ancestry.sh
say pid 4444 tries to reach out to a c2 server, now we need to find out how it came to be
this tool uses auditd logs to try and reconstruct the parent chain for a particular pid

## Prerequisits

### Required

- **Linux/Unix system** with kernel 2.6.30 or later
- **auditd installed and running**:
  ```bash
  # Debian/Ubuntu
  sudo apt-get install auditd
  
  # RHEL/CentOS/Fedora
  sudo yum install audit
  
  # Arch Linux
  sudo pacman -S audit
  ```

- **Root privileges or CAP_AUDIT_READ capability** to read audit logs

- **Audit rules configured** to log process execution:
  ```bash
  # Add these rules to /etc/audit/rules.d/execve.rules
  -a exit,always -F arch=b64 -S execve -k process_exec
  -a exit,always -F arch=b32 -S execve -k process_exec
  
  # Reload audit rules
  sudo augenrules --load
  sudo systemctl restart auditd
  ```

### Optional

- POSIX-compliant shell (sh, bash, dash, etc.)
- Terminal with color support (for colored output)


## Usage

- **Make executable**
chmod +x trace-process-ancestry.sh

- **Trace a specific PID**
sudo ./trace-process-ancestry.sh 4444

- **Trace with custom max depth**
sudo ./trace-process-ancestry.sh 4444 100

## Example Output
```
=== Process Ancestry Trace ===

Target PID: 4444
Tracing ancestry to PID 1 (max depth: 50)...

├─ PID 4444 (target)
│  PPID: 3333
│  Time: 12/26/2024 10:30:15
│  Exec: /tmp/malicious_binary
│  Args: ./malicious_binary --connect c2.example.com
│
  ├─ PID 3333
  │  PPID: 2222
  │  Time: 12/26/2024 10:25:00
  │  Exec: /usr/bin/python3
  │  Args: python3 /var/www/app.py
  │
    ├─ PID 2222
    │  PPID: 1111
    │  Time: 12/26/2024 09:00:00
    │  Exec: /usr/sbin/apache2
    │  Args: /usr/sbin/apache2 -k start
    │
      ├─ PID 1111
      │  PPID: 1
      │  Time: 12/26/2024 08:50:00
      │  Exec: /lib/systemd/systemd
      │  Args: /usr/lib/systemd/systemd --system
      │
        ├─ PID 1 (init)
        │  PPID: 0
        │  Exec: /sbin/init

Reached init (PID 1) - trace complete!
```