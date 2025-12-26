# trace-process-ancestry.sh

Say PID 4444 tries to reach out to a C2 server, now we need to find out how it came to be. This tool uses auditd logs to reconstruct the parent chain for a particular PID, tracing all the way back to PID 1 (init).

## Why This Matters

When investigating security incidents, knowing a process's ancestry is critical:
- **Identify compromised services**: Trace malicious processes back to the vulnerable service that spawned them
- **Detect lateral movement**: See the full attack chain even if intermediate processes have terminated
- **Post-mortem analysis**: Works even after the malicious process has exited

## Prerequisites

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

### Basic Usage

```bash
# Trace a specific PID
sudo ./trace-process-ancestry.sh 4444
```

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

**Analysis**: This output reveals that Apache2 (PID 2222) spawned a Python application (PID 3333), which then executed the malicious binary (PID 4444). The compromised service is the Python web application.

## How It Works

1. **Queries auditd logs**: Uses `ausearch` to find EXECVE syscall records for the target PID
2. **Extracts parent information**: Retrieves PPID, executable path, command line, and timestamp
3. **Recursive tracing**: Follows the parent chain recursively until reaching PID 1
4. **Fallback mechanism**: If a process isn't in audit logs (still running), falls back to `/proc` filesystem
5. **Safety features**: Prevents infinite loops and detects cycles

### Why auditd?

- **Kernel-level logging**: Captures process execution at syscall level, before evasion can occur
- **Immutable records**: Logs persist even after process termination
- **Original parent info**: Records the true parent PID even if the process later orphans
- **Hard to bypass**: Requires kernel-level privileges to evade

## Use Cases

### Incident Response

```bash
# A process is making suspicious network connections
sudo netstat -tnp | grep ESTABLISHED
# tcp  0  0  192.168.1.10:45678  evil.c2.com:443  ESTABLISHED  4444/unknown

# Trace its ancestry
sudo ./trace-process-ancestry.sh 4444
```

### Security Monitoring

```bash
# Find all processes spawned from a specific service
sudo ausearch -i -k process_exec | grep "ppid=1234"

# Then trace each suspicious child
sudo ./trace-process-ancestry.sh <suspicious_pid>
```

### Forensic Analysis

```bash
# After detecting compromise, trace all related processes
for pid in 4444 4445 4446; do
    echo "=== Tracing PID $pid ===" 
    sudo ./trace-process-ancestry.sh $pid > trace_$pid.log
done
```

## Troubleshooting

### "Cannot access audit logs"

**Problem**: Script cannot read audit logs

**Solution**: 
```bash
# Run with root privileges
sudo ./trace-process-ancestry.sh 4444

# OR grant CAP_AUDIT_READ capability
sudo setcap cap_audit_read+ep /usr/local/bin/trace-process-ancestry.sh
```

### "PID not found in audit logs"

**Problem**: Target process started before auditing was enabled or audit logs rotated

**Solutions**:
- Ensure audit rules are configured (see Prerequisites)
- Check audit log retention: `sudo cat /etc/audit/auditd.conf | grep num_logs`
- Increase log retention if needed
- If process is still running, the script will fall back to `/proc`

### "Maximum depth reached"

**Problem**: Ancestry chain exceeds max depth limit (default 50)

**Solution**:
```bash
# Increase max depth
sudo ./trace-process-ancestry.sh 4444 200
```

### Missing timestamps or command lines

**Problem**: Audit logs don't contain full information

**Solution**:
```bash
# Ensure detailed logging is enabled in /etc/audit/auditd.conf
log_format = ENRICHED

# Add more detailed audit rules
-a exit,always -F arch=b64 -S execve -k process_exec
```

## Limitations

- **Log rotation**: Very old processes may not be in current audit logs
- **Pre-audit processes**: Cannot trace processes that started before auditing was enabled
- **Performance**: On systems with millions of log entries, searches may be slow
- **Storage**: Comprehensive process logging requires significant disk space
- **Audit tampering**: If attacker gains root and disables auditing, some records may be lost

## Best Practices

1. **Enable audit immutability**: Prevent attackers from disabling auditing
   ```bash
   # Add to /etc/audit/rules.d/99-finalize.rules
   -e 2
   ```

2. **Monitor audit logs**: Alert on audit service stops or log deletions
   ```bash
   -w /var/log/audit/ -p wa -k audit_log_tampering
   ```

3. **Regular log rotation**: Configure appropriate retention
   ```bash
   # In /etc/audit/auditd.conf
   num_logs = 100
   max_log_file = 100
   ```

4. **Centralized logging**: Ship audit logs to a SIEM or log aggregator

5. **Test your setup**: Regularly verify that audit logging is working
   ```bash
   # Generate a test event
   ls /tmp
   
   # Verify it was logged
   sudo ausearch -m EXECVE -ts recent | grep ls
   ```

## Integration Examples

### Alert Script

```bash
#!/bin/sh
# alert-on-suspicious.sh
# Monitor for processes connecting to known C2 servers

C2_IP="203.0.113.100"

# Find processes connected to C2
netstat -tn | grep "$C2_IP" | awk '{print $7}' | cut -d'/' -f1 | while read pid; do
    if [ -n "$pid" ] && [ "$pid" != "-" ]; then
        echo "ALERT: PID $pid connected to C2 server $C2_IP"
        ./trace-process-ancestry.sh "$pid" > "/var/log/security/incident_${pid}_$(date +%s).log"
    fi
done
```

### Automated Reporting

```bash
#!/bin/sh
# daily-security-scan.sh
# Daily scan for suspicious process patterns

REPORT="/var/log/security/daily_report_$(date +%Y%m%d).txt"

echo "Daily Security Scan - $(date)" > "$REPORT"
echo "=================================" >> "$REPORT"

# Find processes executing from /tmp
ausearch -ts today -k process_exec -i | grep 'exe="/tmp' | \
    awk '{print $4}' | cut -d'=' -f2 | sort -u | while read pid; do
    echo "\nSuspicious: Process from /tmp detected (PID: $pid)" >> "$REPORT"
    ./trace-process-ancestry.sh "$pid" >> "$REPORT" 2>&1
done
```

## Contributing

Contributions are welcome! Please:
- Test on multiple distributions
- Maintain POSIX compliance
- Add comments for complex logic
- Update documentation

## License

This script is provided as-is for security monitoring and incident response purposes.

## See Also

- [Linux Audit Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)
- [ausearch man page](https://linux.die.net/man/8/ausearch)
- [Process monitoring best practices](https://github.com/Neo23x0/auditd)

## Credits

Created for security professionals to aid in incident response and threat hunting.